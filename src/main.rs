//! Sonar —— IP 探活扫描器
//!
//! 带参数进入命令行模式，无参数（或 --gui）进入图形界面。

mod cli;
mod core;
mod ui;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let gui = args.is_empty() || args.iter().any(|a| a == "--gui");

    if gui {
        ui::run();
    } else if let Err(e) = cli::run_from_args() {
        eprintln!("错误: {e:#}");
        std::process::exit(1);
    }
}
