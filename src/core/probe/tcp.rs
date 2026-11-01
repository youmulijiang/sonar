//! TCP 连接探活探针。
//!
//! 对候选端口并发发起 TCP 连接：
//! - 连接成功 → 存活（端口开放）
//! - 收到 RST（ConnectionRefused）→ 存活（主机有响应但端口未开放）
//! - 全部超时/不可达 → 判定不存活

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use futures::future::join_all;

use super::ProbeOutcome;

pub struct TcpProbe {
    pub ports: Vec<u16>,
}

impl TcpProbe {
    pub async fn probe(&self, ip: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
        let results = join_all(
            self.ports
                .iter()
                .map(|&port| try_connect(ip, port, timeout)),
        )
        .await;

        let mut alive = false;
        let mut best: Option<Duration> = None;
        let mut open = Vec::new();
        let mut refused = 0usize;

        for (port, state) in self.ports.iter().zip(results) {
            match state {
                PortState::Open(elapsed) => {
                    alive = true;
                    open.push(*port);
                    best = Some(best.map_or(elapsed, |b: Duration| b.min(elapsed)));
                }
                PortState::Refused(elapsed) => {
                    alive = true;
                    refused += 1;
                    best = Some(best.map_or(elapsed, |b: Duration| b.min(elapsed)));
                }
                PortState::Filtered => {}
            }
        }

        if alive {
            let mut note = String::new();
            if !open.is_empty() {
                note.push_str(&format!(
                    "开放 {}",
                    open.iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            if refused > 0 {
                if !note.is_empty() {
                    note.push('，');
                }
                note.push_str(&format!("{refused} 端口 RST"));
            }
            ProbeOutcome::alive(best, note)
        } else {
            ProbeOutcome::dead("全部端口无响应")
        }
    }
}

#[derive(Debug)]
pub enum PortState {
    /// 连接成功（端口开放）
    Open(Duration),
    /// 收到 RST（主机存活）
    Refused(Duration),
    /// 超时 / 不可达
    Filtered,
}

pub async fn try_connect(ip: Ipv4Addr, port: u16, timeout: Duration) -> PortState {
    let addr = std::net::SocketAddr::from((ip, port));
    let started = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortState::Open(started.elapsed()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            PortState::Refused(started.elapsed())
        }
        Ok(Err(_)) | Err(_) => PortState::Filtered,
    }
}
