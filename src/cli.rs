//! 命令行模式：无头运行扫描器，便于脚本化与调试。

use std::time::Instant;

use clap::Parser;

use crate::core::config::{DEFAULT_SCAN_PORTS, DEFAULT_TCP_PORTS_TEXT, ProbeMethod, ScanConfig};
use crate::core::events::{HostResult, ScanEvent};
use crate::core::probe::format_ms;
use crate::core::runtime::spawn_scan;
use crate::core::target::parse_ports;

#[derive(Parser, Debug)]
#[command(
    name = "sonar",
    version,
    about = "IP 探活扫描器（ICMP / 系统 ping / TCP / 端口扫描）",
    after_help = "不带参数启动图形界面；带目标参数则进入命令行模式。\n示例: sonar 192.168.1.0/24 -m icmp,tcp --alive-only"
)]
pub struct Cli {
    /// 目标：IP / CIDR / 范围 / 域名（逗号分隔，可多个）
    #[arg(value_name = "TARGETS")]
    pub targets: Vec<String>,

    /// 探活方式，逗号分隔: icmp,ping,tcp,port
    #[arg(short = 'm', long, default_value = "icmp,tcp")]
    pub methods: String,

    /// TCP 探活端口列表
    #[arg(long, default_value = DEFAULT_TCP_PORTS_TEXT)]
    pub tcp_ports: String,

    /// 端口扫描目标端口
    #[arg(long, default_value = DEFAULT_SCAN_PORTS)]
    pub scan_ports: String,

    /// 单次探测超时（毫秒）
    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,

    /// 失败重试次数
    #[arg(long, default_value_t = 1)]
    pub retries: u32,

    /// 主机探活并发数
    #[arg(long, default_value_t = 256)]
    pub concurrency: usize,

    /// 端口扫描并发数（(主机,端口) 对）
    #[arg(long, default_value_t = 4000)]
    pub scan_concurrency: usize,

    /// 只输出存活主机
    #[arg(long)]
    pub alive_only: bool,

    /// 以 JSON 行格式输出结果
    #[arg(long)]
    pub json: bool,
}

impl Cli {
    fn into_config(self) -> anyhow::Result<ScanConfig> {
        if self.targets.is_empty() {
            anyhow::bail!("缺少扫描目标，例如: sonar 192.168.1.0/24");
        }
        let methods: Vec<ProbeMethod> = self
            .methods
            .split([',', ';'])
            .filter_map(|s| ProbeMethod::from_str(s.trim()))
            .collect();
        if methods.is_empty() {
            anyhow::bail!(
                "无效的探活方式: {}（可用: icmp,ping,tcp,port）",
                self.methods
            );
        }
        let tcp_ports = parse_ports(&self.tcp_ports)?;
        let scan_ports = parse_ports(&self.scan_ports)?;
        Ok(ScanConfig {
            targets: self.targets,
            methods,
            tcp_ports,
            scan_ports,
            timeout: std::time::Duration::from_millis(self.timeout_ms.max(50)),
            retries: self.retries,
            concurrency: self.concurrency.max(1),
            portscan_concurrency: self.scan_concurrency.max(1),
            max_hosts: 1 << 20,
        })
    }
}

pub fn run_from_args() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let alive_only = cli.alive_only;
    let json = cli.json;
    let cfg = cli.into_config()?;
    let t0 = Instant::now();

    let handle = spawn_scan(cfg);
    let mut last_progress: Option<(usize, usize)> = None;

    for ev in handle.events.iter() {
        match ev {
            ScanEvent::Started { total } => {
                if !json {
                    println!("开始扫描，共 {total} 个目标");
                }
            }
            ScanEvent::Log(msg) => {
                if !json {
                    println!("[*] {msg}");
                }
            }
            ScanEvent::Host(r) => {
                if !alive_only || r.alive {
                    print_host(&r, json);
                }
            }
            ScanEvent::Progress { done, total } => {
                if !json {
                    eprint!("\r探活进度 {done}/{total}");
                    last_progress = Some((done, total));
                }
            }
            ScanEvent::PortScanProgress { done, total } => {
                if !json {
                    eprint!("\r端口扫描进度 {done}/{total}");
                }
            }
            ScanEvent::Finished {
                elapsed,
                total,
                alive,
            } => {
                if !json {
                    eprintln!();
                    println!(
                        "扫描完成: {total} 目标 / 存活 {alive}，用时 {:.2}s",
                        elapsed.as_secs_f64()
                    );
                }
                break;
            }
            ScanEvent::Error(e) => {
                if !json {
                    eprintln!();
                }
                eprintln!("[!] 错误: {e}");
                break;
            }
        }
    }
    let _ = last_progress;
    let _ = t0;
    Ok(())
}

fn print_host(r: &HostResult, json: bool) {
    if json {
        println!("{}", crate::core::events::to_json_line(r));
        return;
    }
    if r.alive {
        let lat = r
            .latency
            .map(|d| format!(" {:>8}", format_ms(d)))
            .unwrap_or_default();
        let by = r.confirmed_by.join(",");
        let ports = if r.open_ports.is_empty() {
            String::new()
        } else {
            format!(
                "  开启: {}",
                r.open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        println!("✓ {:<16}{lat}  [{by}]{ports}", r.ip.to_string());
    } else {
        println!("✗ {}", r.ip);
    }
}
