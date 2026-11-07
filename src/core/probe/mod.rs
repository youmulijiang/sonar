pub mod arp;
pub mod icmp;
pub mod portscan;
pub mod sysping;
pub mod tcp;

use std::future::Future;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// 单次探测结论
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub alive: bool,
    pub latency: Option<Duration>,
    pub note: String,
}

impl ProbeOutcome {
    pub fn alive(latency: Option<Duration>, note: impl Into<String>) -> Self {
        ProbeOutcome {
            alive: true,
            latency,
            note: note.into(),
        }
    }

    pub fn dead(note: impl Into<String>) -> Self {
        ProbeOutcome {
            alive: false,
            latency: None,
            note: note.into(),
        }
    }
}

/// 带重试的探测执行：存活立即返回；未存活则按 `retries` 次数重试（间隔 120ms）。
/// 取消令牌触发时提前终止并按未存活处理。
pub async fn with_retries<F, Fut>(
    cancel: &CancellationToken,
    retries: u32,
    mut f: F,
) -> ProbeOutcome
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ProbeOutcome>,
{
    let mut last = ProbeOutcome::dead("未执行");
    for attempt in 0..=retries {
        if cancel.is_cancelled() {
            return ProbeOutcome::dead("已取消");
        }
        last = f().await;
        if last.alive || attempt == retries {
            break;
        }
        if tokio::time::timeout(Duration::from_millis(120), cancel.cancelled())
            .await
            .is_err()
        {
            // 120ms 内未取消，继续重试
        }
    }
    last
}

pub fn format_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms >= 100.0 {
        format!("{ms:.0}ms")
    } else {
        format!("{ms:.1}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_with_retries() {
        let cancel = CancellationToken::new();
        let mut calls = 0u32;
        let out = with_retries(&cancel, 3, || {
            calls += 1;
            async { ProbeOutcome::dead("no") }
        })
        .await;
        assert!(!out.alive);
        assert_eq!(calls, 4);

        let cancel = CancellationToken::new();
        let out = with_retries(&cancel, 3, || async { ProbeOutcome::alive(None, "ok") }).await;
        assert!(out.alive);
    }
}
