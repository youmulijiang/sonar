//! 端口扫描探活（rustscan 风格）。
//!
//! 将 (主机, 端口) 对做惰性分块，块内全并发连接，块间顺序推进，
//! 内存占用与并发数成正比而与目标规模无关。收到 RST 的端口同样
//! 证明主机存活（只是端口未开放）。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use futures::future::join_all;
use tokio_util::sync::CancellationToken;

use super::tcp::try_connect;

#[derive(Debug, Default, Clone)]
pub struct PortScanResult {
    pub open: Vec<u16>,
    pub refused: usize,
}

impl PortScanResult {
    /// 是否有存活信号（开放端口或 RST）
    pub fn is_alive_signal(&self) -> bool {
        !self.open.is_empty() || self.refused > 0
    }
}

/// (主机, 端口) 交叉积的惰性分块迭代器
struct PairChunks<'a> {
    hosts: &'a [Ipv4Addr],
    ports: &'a [u16],
    host_idx: usize,
    port_offset: usize,
    chunk: usize,
}

impl<'a> PairChunks<'a> {
    fn new(hosts: &'a [Ipv4Addr], ports: &'a [u16], chunk: usize) -> Self {
        PairChunks {
            hosts,
            ports,
            host_idx: 0,
            port_offset: 0,
            chunk: chunk.max(1),
        }
    }
}

impl Iterator for PairChunks<'_> {
    type Item = Vec<(Ipv4Addr, u16)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.host_idx >= self.hosts.len() || self.ports.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(self.chunk);
        while out.len() < self.chunk && self.host_idx < self.hosts.len() {
            let host = self.hosts[self.host_idx];
            let take = (self.ports.len() - self.port_offset).min(self.chunk - out.len());
            out.extend(
                self.ports[self.port_offset..self.port_offset + take]
                    .iter()
                    .map(|&p| (host, p)),
            );
            self.port_offset += take;
            if self.port_offset >= self.ports.len() {
                self.host_idx += 1;
                self.port_offset = 0;
            }
        }
        (!out.is_empty()).then_some(out)
    }
}

/// 对所有主机执行端口扫描，返回每台主机的扫描结果。
/// `progress` 以 (主机,端口) 对数量回调进度增量。
pub async fn scan_hosts(
    hosts: &[Ipv4Addr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
    progress: impl Fn(usize) + Send + Sync,
) -> HashMap<Ipv4Addr, PortScanResult> {
    let mut results: HashMap<Ipv4Addr, PortScanResult> = hosts
        .iter()
        .map(|&h| (h, PortScanResult::default()))
        .collect();

    for chunk in PairChunks::new(hosts, ports, concurrency) {
        if cancel.is_cancelled() {
            break;
        }
        let chunk_len = chunk.len();
        let outcomes = join_all(
            chunk
                .iter()
                .map(|&(ip, port)| try_connect(ip, port, timeout)),
        )
        .await;
        for ((ip, port), state) in chunk.into_iter().zip(outcomes) {
            let entry = results.entry(ip).or_default();
            match state {
                super::tcp::PortState::Open(_) => entry.open.push(port),
                super::tcp::PortState::Refused(_) => entry.refused += 1,
                super::tcp::PortState::Filtered => {}
            }
        }
        progress(chunk_len);
    }

    for r in results.values_mut() {
        r.open.sort_unstable();
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair_chunks() {
        let hosts = vec![
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
        ];
        let ports = vec![1u16, 2, 3, 4, 5];

        let chunks: Vec<Vec<(Ipv4Addr, u16)>> = PairChunks::new(&hosts, &ports, 7).collect();
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 15);
        // 每个 chunk 不超过 chunk 大小
        assert!(chunks.iter().all(|c| c.len() <= 7));
        // (主机,端口) 对无重复
        let mut seen = std::collections::HashSet::new();
        for c in &chunks {
            for p in c {
                assert!(seen.insert(*p));
            }
        }
        assert_eq!(seen.len(), 15);

        // 空端口列表
        assert!(PairChunks::new(&hosts, &[], 4).next().is_none());
    }
}
