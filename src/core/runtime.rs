//! 扫描任务的宿主：独立的 OS 线程 + 独立的 Tokio 运行时。
//!
//! GPUI 有自己的渲染执行器，不能与 Tokio 混跑在同一控制流里；
//! 这里把扫描放在独立线程，通过 crossbeam 通道把事件流回 UI/CLI，
//! 取消通过 CancellationToken 单向传递。两边完全解耦，互不阻塞。

use crossbeam_channel::{Receiver, unbounded};
use tokio_util::sync::CancellationToken;

use crate::core::config::ScanConfig;
use crate::core::events::ScanEvent;
use crate::core::scanner::run_scan;

/// 一次扫描任务的句柄
pub struct ScanHandle {
    pub cancel: CancellationToken,
    pub events: Receiver<ScanEvent>,
}

/// 在独立线程上启动扫描，立即返回句柄
pub fn spawn_scan(cfg: ScanConfig) -> ScanHandle {
    let (tx, rx) = unbounded();
    let cancel = CancellationToken::new();
    let cancel_in = cancel.clone();

    std::thread::Builder::new()
        .name("sonar-scanner".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("创建 Tokio 运行时失败");
            rt.block_on(run_scan(cfg, cancel_in, tx));
        })
        .expect("启动扫描线程失败");

    ScanHandle { cancel, events: rx }
}
