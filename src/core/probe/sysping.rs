//! 系统 ping 探活探针：调用操作系统自带的 ping 命令。
//!
//! 兼容性最好（不依赖原始套接字权限），但每主机创建一个进程，
//! 大规模扫描时吞吐受进程创建速度限制，建议并发数适度。

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::Command;

use super::ProbeOutcome;

pub async fn probe(ip: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
    let mut cmd = build_command(ip, timeout);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let started = Instant::now();
    let wait = timeout + Duration::from_millis(500);
    let result = tokio::time::timeout(wait, cmd.output()).await;
    match result {
        Ok(Ok(out))
            if out.status.success()
                && (!cfg!(windows)
                    || out
                        .stdout
                        .windows(4)
                        .any(|w| w.eq_ignore_ascii_case(b"ttl="))) =>
        {
            ProbeOutcome::alive(Some(started.elapsed()), "系统 ping 应答")
        }
        Ok(Ok(_)) => ProbeOutcome::dead("不可达"),
        Ok(Err(e)) => ProbeOutcome::dead(format!("ping 命令执行失败: {e}")),
        Err(_) => ProbeOutcome::dead("超时"),
    }
}

fn build_command(ip: Ipv4Addr, timeout: Duration) -> Command {
    let mut cmd = Command::new("ping");
    if cfg!(windows) {
        cmd.arg("-n").arg("1");
        cmd.arg("-w").arg(timeout.as_millis().to_string());
    } else if cfg!(target_os = "macos") {
        cmd.arg("-c").arg("1");
        // macOS 的 -W 单位为毫秒
        cmd.arg("-W").arg(timeout.as_millis().to_string());
    } else {
        cmd.arg("-c").arg("1");
        // iputils 的 -W 单位为秒（支持小数）
        cmd.arg("-W")
            .arg(format!("{:.1}", timeout.as_secs_f64().max(0.1)));
        cmd.arg("-i").arg("0.2");
    }
    cmd.arg(ip.to_string());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn repeated_loopback_ping() {
        for _ in 0..10 {
            assert!(
                probe(Ipv4Addr::LOCALHOST, Duration::from_secs(2))
                    .await
                    .alive
            );
        }
    }
}
