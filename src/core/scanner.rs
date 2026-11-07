//! 扫描调度器：解析目标 → 并发主机探活 → 端口扫描 → 汇总输出。
//!
//! 运行模型（rustscan 思路）：
//! - 主机探活阶段：`buffer_unordered(concurrency)` 全速流水推进，
//!   慢主机不阻塞其他主机的探测；
//! - 端口扫描阶段：(主机, 端口) 对惰性分块，块内并发度 = portscan_concurrency；
//! - 全程响应取消令牌，事件通过 crossbeam 通道推给 UI/CLI。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::Instant;

use anyhow::Context as _;
use crossbeam_channel::Sender;
use futures::{StreamExt, future::join_all};
use tokio_util::sync::CancellationToken;

use crate::core::config::{ProbeMethod, ScanConfig};
use crate::core::events::{HostResult, ScanEvent};
use crate::core::probe::{arp, format_ms, icmp, portscan, sysping, tcp, with_retries};

/// 独立探活的探针集合（每主机并发执行全部启用项）
enum LivenessProbe {
    Arp,
    Icmp,
    SysPing,
    Tcp(tcp::TcpProbe),
}

impl LivenessProbe {
    fn name(&self) -> &'static str {
        match self {
            LivenessProbe::Arp => "ARP",
            LivenessProbe::Icmp => "ICMP",
            LivenessProbe::SysPing => "PING",
            LivenessProbe::Tcp(_) => "TCP",
        }
    }
}

/// 扫描入口。事件全部推入 `tx`，正常结束发送 `Finished`，异常时发送 `Error`。
pub async fn run_scan(cfg: ScanConfig, cancel: CancellationToken, tx: Sender<ScanEvent>) {
    let t0 = Instant::now();
    if let Err(e) = run_inner(&cfg, &cancel, &tx, t0).await {
        let _ = tx.send(ScanEvent::Error(format!("{e:#}")));
    }
}

async fn run_inner(
    cfg: &ScanConfig,
    cancel: &CancellationToken,
    tx: &Sender<ScanEvent>,
    t0: Instant,
) -> anyhow::Result<()> {
    let send = |ev: ScanEvent| {
        let _ = tx.send(ev);
    };

    if cfg.methods.is_empty() {
        anyhow::bail!("未选择任何探活方式");
    }

    send(ScanEvent::Log("解析目标中…".into()));
    let (hosts, warnings) = crate::core::target::expand_targets(&cfg.targets, cfg.max_hosts)
        .await
        .context("目标解析失败")?;
    for w in &warnings {
        send(ScanEvent::Log(format!("[警告] {w}")));
    }
    let total = hosts.len();
    send(ScanEvent::Log(format!(
        "共 {total} 个目标主机，方式: {}",
        cfg.methods
            .iter()
            .map(|m| m.name())
            .collect::<Vec<_>>()
            .join("/")
    )));
    send(ScanEvent::Started { total });

    // ---------- 阶段一：主机探活 ----------
    let liveness: Vec<LivenessProbe> = cfg
        .methods
        .iter()
        .filter_map(|m| match m {
            ProbeMethod::Arp => Some(LivenessProbe::Arp),
            ProbeMethod::Icmp => Some(LivenessProbe::Icmp),
            ProbeMethod::SystemPing => Some(LivenessProbe::SysPing),
            ProbeMethod::Tcp => Some(LivenessProbe::Tcp(tcp::TcpProbe {
                ports: cfg.tcp_ports.clone(),
            })),
            ProbeMethod::PortScan => None,
        })
        .collect();

    let mut results: BTreeMap<Ipv4Addr, HostResult> = BTreeMap::new();

    if !liveness.is_empty() {
        let done = AtomicUsize::new(0);
        let mut stream = futures::stream::iter(hosts.iter().copied())
            .map(|ip| {
                let probes = &liveness;
                async move {
                    if cancel.is_cancelled() {
                        return None;
                    }
                    Some((
                        ip,
                        probe_host(ip, probes, cfg.timeout, cfg.retries, cancel).await,
                    ))
                }
            })
            .buffer_unordered(cfg.concurrency.max(1));

        while let Some(item) = stream.next().await {
            if cancel.is_cancelled() {
                break;
            }
            let Some((ip, r)) = item else { continue };
            let done_n = done.fetch_add(1, SeqCst) + 1;
            send(ScanEvent::Host(Box::new(r.clone())));
            send(ScanEvent::Progress {
                done: done_n,
                total,
            });
            results.insert(ip, r);
        }
    }

    // ---------- 阶段二：端口扫描 ----------
    if cfg.methods.contains(&ProbeMethod::PortScan) && !cancel.is_cancelled() {
        // 端口仅用于补充探活，跳过已确认存活的目标。
        let scan_targets: Vec<Ipv4Addr> = hosts
            .iter()
            .copied()
            .filter(|ip| !results.get(ip).is_some_and(|r| r.alive))
            .collect();

        if scan_targets.is_empty() {
            send(ScanEvent::Log("没有需要端口扫描的主机".into()));
        } else {
            let total_pairs = scan_targets.len() * cfg.scan_ports.len();
            send(ScanEvent::Log(format!(
                "端口扫描: {} 台主机 × {} 端口 = {} 对",
                scan_targets.len(),
                cfg.scan_ports.len(),
                total_pairs
            )));
            send(ScanEvent::PortScanProgress {
                done: 0,
                total: total_pairs,
            });

            let done = AtomicUsize::new(0);
            let tx2 = tx.clone();
            let scan_concurrency = cfg.portscan_concurrency;
            let scan_ports = cfg.scan_ports.clone();
            let scan_timeout = cfg.timeout;
            let cancel2 = cancel.clone();
            let host_results = portscan::scan_hosts(
                &scan_targets,
                &scan_ports,
                scan_timeout,
                scan_concurrency,
                &cancel2,
                move |n| {
                    let d = done.fetch_add(n, SeqCst) + n;
                    let _ = tx2.send(ScanEvent::PortScanProgress {
                        done: d,
                        total: total_pairs,
                    });
                },
            )
            .await;

            for (ip, pr) in host_results {
                let alive_by_scan = pr.is_alive_signal();
                {
                    let entry = results.entry(ip).or_insert_with(|| HostResult {
                        ip,
                        alive: false,
                        confirmed_by: Vec::new(),
                        latency: None,
                        open_ports: Vec::new(),
                        detail: String::new(),
                    });
                    entry.open_ports = pr.open.clone();
                    if alive_by_scan {
                        if !entry.alive {
                            entry.alive = true;
                            entry.confirmed_by.push("PORT".into());
                        }
                        let mut detail = String::new();
                        if !pr.open.is_empty() {
                            detail.push_str(&format!(
                                "开放端口 {}",
                                pr.open
                                    .iter()
                                    .map(|p| p.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ));
                        }
                        if pr.refused > 0 {
                            if !detail.is_empty() {
                                detail.push('，');
                            }
                            detail.push_str(&format!("{} 端口 RST", pr.refused));
                        }
                        entry.detail = detail;
                    }
                }
                if let Some(r) = results.get(&ip) {
                    send(ScanEvent::Host(Box::new(r.clone())));
                }
            }
        }
    }

    let alive = results.values().filter(|r| r.alive).count();
    send(ScanEvent::Finished {
        elapsed: t0.elapsed(),
        total,
        alive,
    });
    Ok(())
}

/// 对单台主机并发执行全部启用的探活方式，任一确认即存活。
async fn probe_host(
    ip: Ipv4Addr,
    probes: &[LivenessProbe],
    timeout: std::time::Duration,
    retries: u32,
    cancel: &CancellationToken,
) -> HostResult {
    let mut outs: Vec<(&str, crate::core::probe::ProbeOutcome)> = Vec::new();
    for phase in 0..3 {
        if outs.iter().any(|(_, o)| o.alive) {
            break;
        }
        outs.extend(
            join_all(
                probes
                    .iter()
                    .filter(|p| match p {
                        LivenessProbe::Arp => phase == 0,
                        LivenessProbe::Tcp(_) => phase == 2,
                        _ => phase == 1,
                    })
                    .map(|p| async move {
                        let outcome = match p {
                            LivenessProbe::Arp => {
                                with_retries(cancel, retries, || arp::probe(ip, timeout)).await
                            }
                            LivenessProbe::Icmp => {
                                with_retries(cancel, retries, || icmp::probe(ip, timeout)).await
                            }
                            LivenessProbe::SysPing => {
                                with_retries(cancel, retries, || sysping::probe(ip, timeout)).await
                            }
                            LivenessProbe::Tcp(t) => {
                                with_retries(cancel, retries, || t.probe(ip, timeout)).await
                            }
                        };
                        (p.name(), outcome)
                    }),
            )
            .await,
        );
    }

    let alive = outs.iter().any(|(_, o)| o.alive);
    let confirmed_by = outs
        .iter()
        .filter(|(_, o)| o.alive)
        .map(|(name, _)| name.to_string())
        .collect();
    let latency = outs
        .iter()
        .filter(|(_, o)| o.alive)
        .filter_map(|(_, o)| o.latency)
        .min();
    let detail = outs
        .iter()
        .map(|(name, o)| {
            let lat = o
                .latency
                .map(|d| format!(" {}", format_ms(d)))
                .unwrap_or_default();
            format!("{name}:{}{lat}", o.note)
        })
        .collect::<Vec<_>>()
        .join("；");

    HostResult {
        ip,
        alive,
        confirmed_by,
        latency,
        open_ports: Vec::new(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn ping_alive_skips_tcp_and_port_scan() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let cfg = ScanConfig {
            targets: vec!["127.0.0.1".into()],
            methods: vec![
                ProbeMethod::SystemPing,
                ProbeMethod::Tcp,
                ProbeMethod::PortScan,
            ],
            ..Default::default()
        };
        run_scan(cfg, CancellationToken::new(), tx).await;
        let events: Vec<_> = rx.try_iter().collect();
        assert!(
            events.iter().any(
                |e| matches!(e, ScanEvent::Host(r) if r.alive && r.confirmed_by == vec!["PING"])
            )
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ScanEvent::PortScanProgress { .. }))
        );
    }
}
