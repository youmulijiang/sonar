//! Sonar 主界面。
//!
//! 布局：顶部「开始 / 停止 / 导入菜单 / 设置菜单」；其下左侧为目标多行文本框
//! （每行一个目标，带 清空/去重/导入），右侧为扫描配置区（两个选项卡：
//! 「探活配置」—— ICMP / 系统 Ping / TCP 互斥单选 + 并发/超时/重试 + TCP 候选端口；
//! 「扫描配置」—— 端口扫描开关（默认关闭）+ 端口（默认 Top20）+ 扫描并发）；
//! 配置区下方为进度条（探活进度 + 速度，端口扫描激活时追加端口进度）。
//!
//! 扫描任务在独立线程的 Tokio 运行时上执行（见 core::runtime），
//! UI 通过 crossbeam 通道以 80ms 轮询批量取事件刷新界面，两侧互不阻塞。

mod results_table;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use gpui_kit::assets::IconName;
use gpui_kit::base::v_flex;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState, NumberInput, Textarea, TextareaState};
use gpui_kit::component::label::Label;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::progress::Progress;
use gpui_kit::component::switch::Switch;
use gpui_kit::component::table::{DataTable, TableState};
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, Selectable as _, Sizable as _, TitleBar,
    WindowExt as _,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    App, AppContext as _, Bounds, ClickEvent, Context, Entity, FontWeight, IntoElement,
    ParentElement as _, Render, Styled as _, Task, Window, WindowBounds, WindowOptions, div, px,
    size,
};
use tokio_util::sync::CancellationToken;

use crate::core::config::{DEFAULT_LIVENESS_PORTS, DEFAULT_SCAN_PORTS, ProbeMethod, ScanConfig};
use crate::core::events::{CSV_HEADER, HostResult, ScanEvent};
use crate::core::runtime::spawn_scan;
use crate::core::target::{parse_ports, targets_from_text};
use results_table::{ResultsDelegate, build_rows};

pub fn run() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx: &mut App| {
            gpui_kit::init(cx);
            let bounds = Bounds::centered(None, size(px(1280.), px(860.)), cx);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    ..TitleBar::window_options()
                },
                cx,
                |window, cx| cx.new(|cx| SonarApp::new(window, cx)),
            )
            .expect("打开主窗口失败");
            cx.activate(true);
        });
}

/// 探活方式（互斥单选）
const LIVENESS_NAMES: [&str; 4] = ["ICMP", "系统 Ping", "TCP", "ARP"];

pub struct SonarApp {
    // ---- 目标 ----
    /// 目标多行文本（每行一个目标）
    targets_area: Entity<TextareaState>,

    // ---- 探活配置（选项卡 1） ----
    /// 探活方式：0=ICMP 1=系统 Ping 2=TCP（互斥）
    liveness: usize,
    concurrency_input: Entity<InputState>,
    timeout_input: Entity<InputState>,
    retries_input: Entity<InputState>,

    // ---- 端口扫描（默认关闭，仅对已确认存活的主机扫描） ----
    port_scan_enabled: bool,
    scan_ports_input: Entity<InputState>,
    scan_conc_input: Entity<InputState>,

    // ---- 视图选项 ----
    alive_only: bool,

    // ---- 运行状态 ----
    scanning: bool,
    cancel: Option<CancellationToken>,
    rx: Option<crossbeam_channel::Receiver<ScanEvent>>,
    started_at: Option<Instant>,
    elapsed: Duration,
    progress_done: usize,
    progress_total: usize,
    ps_done: usize,
    ps_total: usize,
    alive_count: usize,
    total_count: usize,

    // ---- 结果 ----
    results: BTreeMap<Ipv4Addr, HostResult>,
    table: Entity<TableState<ResultsDelegate>>,

    _poll_task: Task<()>,
}

impl SonarApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let targets_area = cx.new(|cx| {
            TextareaState::new(window, cx).placeholder(
                "每行一个目标，支持 IP / IP段 / CIDR / 域名\n例如：192.168.1.0/24、10.0.0.1-100",
            )
        });
        let concurrency_input = cx.new(|cx| InputState::new(window, cx).default_value("256"));
        let timeout_input = cx.new(|cx| InputState::new(window, cx).default_value("1500"));
        let retries_input = cx.new(|cx| InputState::new(window, cx).default_value("1"));
        let scan_ports_input =
            cx.new(|cx| InputState::new(window, cx).default_value(DEFAULT_SCAN_PORTS));
        let scan_conc_input = cx.new(|cx| InputState::new(window, cx).default_value("4000"));

        let table = cx.new(|cx| TableState::new(ResultsDelegate::new(), window, cx));

        // 事件轮询：批量取事件 → 更新状态 → notify
        let poll_task = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
                let alive = this
                    .update(cx, |s, cx| {
                        let mut events = Vec::new();
                        if let Some(rx) = &s.rx {
                            for _ in 0..4096 {
                                match rx.try_recv() {
                                    Ok(ev) => events.push(ev),
                                    Err(_) => break,
                                }
                            }
                        }
                        let event_count = events.len();
                        let mut had_host_events = false;
                        for ev in events {
                            if matches!(ev, ScanEvent::Host(_)) {
                                had_host_events = true;
                            }
                            s.handle_event(ev, cx);
                        }
                        // 一批结果统一重建表格行（BTreeMap 有序，避免逐条插入的 O(n²) 开销）
                        if had_host_events {
                            let rows = build_rows(&s.results, s.alive_only);
                            s.table.update(cx, |ts, cx| {
                                ts.delegate_mut().replace_rows(rows);
                                cx.notify();
                            });
                        }
                        if s.scanning
                            && let Some(t0) = s.started_at
                        {
                            s.elapsed = t0.elapsed();
                        }
                        // 本批有任何事件、或仍在扫描中，都需要刷新
                        if event_count > 0 || s.scanning || s.rx.is_some() {
                            cx.notify();
                        }
                    })
                    .is_ok();
                if !alive {
                    break;
                }
            }
        });

        SonarApp {
            targets_area,
            liveness: 0,
            concurrency_input,
            timeout_input,
            retries_input,
            port_scan_enabled: false,
            scan_ports_input,
            scan_conc_input,
            alive_only: false,
            scanning: false,
            cancel: None,
            rx: None,
            started_at: None,
            elapsed: Duration::ZERO,
            progress_done: 0,
            progress_total: 0,
            ps_done: 0,
            ps_total: 0,
            alive_count: 0,
            total_count: 0,
            results: BTreeMap::new(),
            table,
            _poll_task: poll_task,
        }
    }

    fn handle_event(&mut self, ev: ScanEvent, _cx: &mut Context<Self>) {
        match ev {
            ScanEvent::Log(_) => {}
            ScanEvent::Started { total } => {
                self.total_count = total;
            }
            ScanEvent::Host(r) => {
                let was_alive = self.results.get(&r.ip).map(|x| x.alive).unwrap_or(false);
                if r.alive && !was_alive {
                    self.alive_count += 1;
                }
                self.results.insert(r.ip, *r);
            }
            ScanEvent::Progress { done, total } => {
                self.progress_done = done;
                self.progress_total = total;
            }
            ScanEvent::PortScanProgress { done, total } => {
                self.ps_done = done;
                self.ps_total = total;
            }
            ScanEvent::Finished {
                elapsed,
                total,
                alive,
            } => {
                self.scanning = false;
                self.rx = None;
                self.cancel = None;
                self.elapsed = elapsed;
                self.total_count = total;
                self.alive_count = alive;
            }
            ScanEvent::Error(_e) => {
                self.scanning = false;
                self.rx = None;
                self.cancel = None;
            }
        }
    }

    fn num_field(&self, input: &Entity<InputState>, cx: &App, default: u64) -> u64 {
        input
            .read(cx)
            .value()
            .trim()
            .parse::<u64>()
            .unwrap_or(default)
    }

    // ---------- 扫描控制 ----------

    fn start_scan(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.scanning {
            return;
        }

        let targets = targets_from_text(&self.targets_area.read(cx).value());
        if targets.is_empty() {
            window.push_notification(Notification::warning("没有有效的扫描目标（每行一个）"), cx);
            return;
        }

        // 探活方式互斥单选；TCP 探活即 TCP Ping（连接常用候选端口判活）
        let liveness = match self.liveness {
            0 => ProbeMethod::Icmp,
            1 => ProbeMethod::SystemPing,
            3 => ProbeMethod::Arp,
            _ => ProbeMethod::Tcp,
        };
        let mut methods = vec![liveness];
        let mut scan_ports = Vec::new();
        if self.port_scan_enabled {
            scan_ports = match parse_ports(&self.scan_ports_input.read(cx).value()) {
                Ok(p) => p,
                Err(e) => {
                    window.push_notification(Notification::error(format!("扫描端口无效: {e}")), cx);
                    return;
                }
            };
            methods.push(ProbeMethod::PortScan);
        }

        let cfg = ScanConfig {
            targets,
            methods,
            tcp_ports: DEFAULT_LIVENESS_PORTS.to_vec(),
            scan_ports,
            timeout: Duration::from_millis(self.num_field(&self.timeout_input, cx, 1500).max(50)),
            retries: self.num_field(&self.retries_input, cx, 1).min(5) as u32,
            concurrency: self
                .num_field(&self.concurrency_input, cx, 256)
                .clamp(1, 2048) as usize,
            portscan_concurrency: self
                .num_field(&self.scan_conc_input, cx, 4000)
                .clamp(1, 16384) as usize,
            ..ScanConfig::default()
        };

        // 复位状态
        self.results.clear();
        self.alive_count = 0;
        self.total_count = 0;
        self.progress_done = 0;
        self.progress_total = 0;
        self.ps_done = 0;
        self.ps_total = 0;
        self.elapsed = Duration::ZERO;
        self.table.update(cx, |ts, cx| {
            ts.delegate_mut().clear();
            cx.notify();
        });

        let handle = spawn_scan(cfg);
        self.cancel = Some(handle.cancel.clone());
        self.rx = Some(handle.events);
        self.scanning = true;
        self.started_at = Some(Instant::now());
        cx.notify();
    }

    fn stop_scan(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
            cx.notify();
        }
    }

    // ---------- 目标编辑 ----------

    fn clear_targets(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.targets_area.update(cx, |st, cx| {
            st.set_value("", window, cx);
        });
        cx.notify();
    }

    fn dedup_targets(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let lines = targets_from_text(&self.targets_area.read(cx).value());
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for l in lines {
            if seen.insert(l.clone()) {
                out.push(l);
            }
        }
        let joined = out.join("\n");
        self.targets_area.update(cx, |st, cx| {
            st.set_value(joined, window, cx);
        });

        cx.notify();
    }

    fn import_file(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let dialog = rfd::AsyncFileDialog::new()
                .set_title("导入目标文件")
                .add_filter("文本文件", &["txt", "list", "csv", "log"]);
            let Some(handle) = dialog.pick_file().await else {
                return;
            };
            let path = handle.path().to_path_buf();
            let read = cx
                .background_spawn(async move { std::fs::read_to_string(&path) })
                .await;
            let _ = this.update_in(cx, |s, window, cx| {
                match read {
                    Ok(content) => {
                        let targets = targets_from_text(&content);
                        if !targets.is_empty() {
                            let joined = targets.join("\n");
                            s.targets_area.update(cx, |st, cx| {
                                st.set_value(joined, window, cx);
                            });
                        }
                    }
                    Err(_) => {
                        window.push_notification(Notification::error("读取文件失败"), cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    // ---------- 配置 ----------

    fn reset_config(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let defaults: Vec<(Entity<InputState>, String)> = vec![
            (self.concurrency_input.clone(), "256".into()),
            (self.timeout_input.clone(), "1500".into()),
            (self.retries_input.clone(), "1".into()),
            (self.scan_ports_input.clone(), DEFAULT_SCAN_PORTS.into()),
            (self.scan_conc_input.clone(), "4000".into()),
        ];
        for (input, value) in defaults {
            input.update(cx, |st, cx| st.set_value(value, window, cx));
        }
        self.liveness = 0;
        self.port_scan_enabled = false;
        cx.notify();
    }

    // ---------- 菜单动作 ----------

    fn toggle_alive_only(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let rows = build_rows(&self.results, self.alive_only);
        self.table.update(cx, |ts, cx| {
            ts.delegate_mut().replace_rows(rows);
            cx.notify();
        });
    }

    fn clear_results(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.scanning {
            window.push_notification(Notification::warning("扫描进行中，无法清空结果"), cx);
            return;
        }
        self.results.clear();
        self.alive_count = 0;
        self.total_count = 0;
        self.progress_done = 0;
        self.progress_total = 0;
        self.ps_done = 0;
        self.ps_total = 0;
        self.elapsed = Duration::ZERO;
        self.table.update(cx, |ts, cx| {
            ts.delegate_mut().clear();
            cx.notify();
        });
        cx.notify();
    }

    fn export_results(&mut self, csv: bool, _window: &mut Window, cx: &mut Context<Self>) {
        if self.results.is_empty() {
            cx.spawn(async move |this, cx| {
                let _ = this.update_in(cx, |_s, window, cx| {
                    window.push_notification(Notification::warning("没有可导出的结果"), cx);
                    cx.notify();
                });
            })
            .detach();
            return;
        }

        let default_name = if csv {
            "sonar-results.csv"
        } else {
            "sonar-results.json"
        };
        cx.spawn(async move |this, cx| {
            let dialog = rfd::AsyncFileDialog::new()
                .set_title("导出结果")
                .set_file_name(default_name)
                .add_filter(
                    if csv { "CSV 文件" } else { "JSON 文件" },
                    if csv { &["csv"] } else { &["json"] },
                );
            let Some(handle) = dialog.save_file().await else {
                return;
            };
            let path = handle.path().to_path_buf();

            let data = this.update(cx, |s, _cx| {
                if csv {
                    let mut out = String::from(CSV_HEADER);
                    out.push('\n');
                    for r in s.results.values() {
                        out.push_str(&crate::core::events::to_csv_line(r));
                        out.push('\n');
                    }
                    out
                } else {
                    let mut out = String::new();
                    for r in s.results.values() {
                        out.push_str(&crate::core::events::to_json_line(r));
                        out.push('\n');
                    }
                    out
                }
            });

            let written = cx
                .background_spawn(async move { std::fs::write(&path, data.unwrap_or_default()) })
                .await;
            let _ = this.update_in(cx, |_s, _window, _cx| {
                let _ = written;
            });
        })
        .detach();
    }
}

/// 目标面板头部的操作按钮
fn target_tool_button(id: &'static str, icon: IconName, label: &'static str) -> Button {
    Button::new(id).ghost().xsmall().icon(icon).label(label)
}

impl Render for SonarApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let progress_ratio = if self.progress_total > 0 {
            (self.progress_done as f32 / self.progress_total as f32).min(1.0)
        } else {
            0.0
        };
        let port_ratio = if self.ps_total > 0 {
            (self.ps_done as f32 / self.ps_total as f32).min(1.0)
        } else {
            0.0
        };
        let secs = self.elapsed.as_secs_f64();
        let speed = if secs > 0.3 {
            (self.progress_done as f64 / secs) as usize
        } else {
            0
        };
        let view = cx.entity();

        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            // ---- 标题栏 ----
            .child(
                TitleBar::new().child(
                    gpui_kit::base::h_flex()
                        .gap_2()
                        .items_center()
                        .child(Icon::new(IconName::Radar).text_color(cx.theme().primary))
                        .child(
                            div()
                                .text_sm()
                                .font_weight(FontWeight::MEDIUM)
                                .child("Sonar · IP 探活扫描器"),
                        ),
                ),
            )
            // ---- 顶部操作栏 ----
            .child(
                gpui_kit::base::h_flex()
                    .gap_2()
                    .px_3()
                    .py_2()
                    .w_full()
                    .child(
                        Button::new("start")
                            .primary()
                            .icon(IconName::Play)
                            .label("开始")
                            .disabled(self.scanning)
                            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                                this.start_scan(window, cx);
                            })),
                    )
                    .child(
                        Button::new("stop")
                            .outline()
                            .icon(IconName::CircleStop)
                            .label("停止")
                            .disabled(!self.scanning)
                            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                                this.stop_scan(window, cx);
                            })),
                    )
                    .child(div().flex_1())
                    .child({
                        let view = view.clone();
                        Button::new("import-menu")
                            .ghost()
                            .icon(IconName::FileUp)
                            .label("导入 / 导出")
                            .dropdown_menu(move |menu, window, _cx| {
                                let view = view.clone();
                                menu.item(
                                    PopupMenuItem::new("导入目标文件…")
                                        .icon(IconName::FileUp)
                                        .on_click(window.listener_for(
                                            &view,
                                            |this, _, window, cx| {
                                                this.import_file(window, cx);
                                            },
                                        )),
                                )
                                .separator()
                                .item(
                                    PopupMenuItem::new("导出结果 (CSV)")
                                        .icon(IconName::FileDown)
                                        .on_click(window.listener_for(
                                            &view,
                                            |this, _, window, cx| {
                                                this.export_results(true, window, cx);
                                            },
                                        )),
                                )
                                .item(
                                    PopupMenuItem::new("导出结果 (JSON)")
                                        .icon(IconName::Download)
                                        .on_click(window.listener_for(
                                            &view,
                                            |this, _, window, cx| {
                                                this.export_results(false, window, cx);
                                            },
                                        )),
                                )
                            })
                    })
                    .child({
                        let view = view.clone();
                        Button::new("app-menu")
                            .ghost()
                            .icon(IconName::Settings)
                            .tooltip("选项")
                            .dropdown_menu(move |menu, window, cx| {
                                let view = view.clone();
                                menu.item(
                                    PopupMenuItem::new("只显示存活")
                                        .checked(view.read(cx).alive_only)
                                        .on_click(window.listener_for(
                                            &view,
                                            |this, _, window, cx| {
                                                this.alive_only = !this.alive_only;
                                                this.toggle_alive_only(window, cx);
                                            },
                                        )),
                                )
                                .item(
                                    PopupMenuItem::new("清空结果")
                                        .icon(IconName::Trash)
                                        .on_click(window.listener_for(
                                            &view,
                                            |this, _, window, cx| {
                                                this.clear_results(window, cx);
                                            },
                                        )),
                                )
                                .separator()
                                .item(
                                    PopupMenuItem::new("恢复默认配置")
                                        .icon(IconName::RefreshCw)
                                        .on_click(window.listener_for(
                                            &view,
                                            |this, _, window, cx| {
                                                this.reset_config(window, cx);
                                            },
                                        )),
                                )
                            })
                    }),
            )
            // ---- 主配置区：左目标 / 右配置 ----
            .child(
                gpui_kit::base::h_flex()
                    .gap_3()
                    .px_3()
                    .w_full()
                    .flex_1()
                    .min_h_0()
                    // 左：目标多行文本框
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .gap_1()
                            .child(
                                gpui_kit::base::h_flex()
                                    .gap_2()
                                    .items_center()
                                    .child(Label::new("目标"))
                                    .child(div().flex_1())
                                    .child(target_tool_button(
                                        "t-clear",
                                        IconName::Trash,
                                        "清空",
                                    ).on_click(cx.listener(
                                        |this, _: &ClickEvent, window, cx| {
                                            this.clear_targets(window, cx);
                                        },
                                    )))
                                    .child(target_tool_button(
                                        "t-dedup",
                                        IconName::List,
                                        "去重",
                                    ).on_click(cx.listener(
                                        |this, _: &ClickEvent, window, cx| {
                                            this.dedup_targets(window, cx);
                                        },
                                    )))
                                    .child(target_tool_button(
                                        "t-import",
                                        IconName::FileUp,
                                        "导入",
                                    ).on_click(cx.listener(
                                        |this, _: &ClickEvent, window, cx| {
                                            this.import_file(window, cx);
                                        },
                                    ))),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .border_1()
                                    .border_color(cx.theme().border)
                                    .rounded_sm()
                                    .overflow_hidden()
                                    .child(Textarea::new(&self.targets_area).h_full().bordered(false)),
                            ),
                    )
                    // 右：扫描配置区（选项卡 + 进度）
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .border_1()
                            .border_color(cx.theme().border)
                            .rounded_sm()
                            .overflow_hidden()
                            .child(
                                    v_flex()
                                        .flex_1()
                                        .p_3()
                                        .gap_3()
                                        // 探活方式：互斥单选
                                        .child(
                                            gpui_kit::base::h_flex()
                                                .gap_2()
                                                .flex_wrap()
                                                .child(Label::new("方式"))
                                                .child(
                                                    Button::new("probe-icmp")
                                                        .outline()
                                                        .icon(IconName::Activity)
                                                        .label(LIVENESS_NAMES[0])
                                                        .selected(self.liveness == 0)
                                                        .on_click(cx.listener(
                                                            |this, _: &ClickEvent, _, cx| {
                                                                this.liveness = 0;
                                                                cx.notify();
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("probe-ping")
                                                        .outline()
                                                        .icon(IconName::MessageSquare)
                                                        .label(LIVENESS_NAMES[1])
                                                        .selected(self.liveness == 1)
                                                        .on_click(cx.listener(
                                                            |this, _: &ClickEvent, _, cx| {
                                                                this.liveness = 1;
                                                                cx.notify();
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("probe-tcp")
                                                        .outline()
                                                        .icon(IconName::Network)
                                                        .label(LIVENESS_NAMES[2])
                                                        .selected(self.liveness == 2)
                                                        .on_click(cx.listener(
                                                            |this, _: &ClickEvent, _, cx| {
                                                                this.liveness = 2;
                                                                cx.notify();
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("probe-arp")
                                                        .outline()
                                                        .icon(IconName::Network)
                                                        .label(LIVENESS_NAMES[3])
                                                        .selected(self.liveness == 3)
                                                        .on_click(cx.listener(
                                                            |this, _: &ClickEvent, _, cx| {
                                                                this.liveness = 3;
                                                                cx.notify();
                                                            },
                                                        )),
                                                ),
                                        )
                                        // 参数
                                        .child(
                                            gpui_kit::base::h_flex()
                                                .gap_3()
                                                .flex_wrap()
                                                .items_center()
                                                .child(Label::new("并发"))
                                                .child(
                                                    div().w(px(120.)).child(NumberInput::new(
                                                        &self.concurrency_input,
                                                    )),
                                                )
                                                .child(Label::new("超时 (ms)"))
                                                .child(
                                                    div().w(px(120.)).child(NumberInput::new(
                                                        &self.timeout_input,
                                                    )),
                                                )
                                                .child(Label::new("重试"))
                                                .child(
                                                    div().w(px(96.)).child(NumberInput::new(
                                                        &self.retries_input,
                                                    )),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(match self.liveness {
                                                    0 => "ICMP：原生 Echo 探测，Windows 下无需管理员权限",
                                                    3 => "ARP：仅探测本地链路 IPv4（Windows），跨网段跳过",
                                                    1 => "系统 Ping：调用操作系统 ping 命令，兼容性最好",
                                                    _ => "TCP Ping：对常用端口发起 TCP 连接，连接成功或收到 RST 均判定存活",
                                                })
                                        )
                                        // 端口扫描（默认关闭，仅对已确认存活的主机扫描）
                                        .child(
                                            v_flex()
                                                .gap_2()
                                                .pt_2()
                                                .border_t_1()
                                                .border_color(cx.theme().border)
                                                .child(
                                                    gpui_kit::base::h_flex()
                                                        .gap_2()
                                                        .items_center()
                                                        .child(
                                                            Switch::new("port-scan-switch")
                                                                .checked(self.port_scan_enabled)
                                                                .on_change(cx.listener(
                                                                    |this, checked: &bool, _, cx| {
                                                                        this.port_scan_enabled = *checked;
                                                                        cx.notify();
                                                                    },
                                                                )),
                                                        )
                                                        .child(Label::new("端口扫描"))
                                                        .child(
                                                            div()
                                                                .text_xs()
                                                                .text_color(cx.theme().muted_foreground)
                                                                .child("默认关闭；开启后对已确认存活的主机扫描端口"),
                                                        ),
                                                )
                                                .child(
                                                    gpui_kit::base::h_flex()
                                                        .gap_3()
                                                        .items_center()
                                                        .child(Label::new("扫描端口"))
                                                        .child(
                                                            div()
                                                                .flex_1()
                                                                .child(Input::new(&self.scan_ports_input)),
                                                        )
                                                        .child(Label::new("扫描并发"))
                                                        .child(
                                                            div().w(px(130.)).child(NumberInput::new(
                                                                &self.scan_conc_input,
                                                            )),
                                                        ),
                                                ),
                                        ),
                                )
                            // 进度区
                            .child(
                                v_flex()
                                    .gap_1()
                                    .px_3()
                                    .py_2()
                                    .border_t_1()
                                    .border_color(cx.theme().border)
                                    .child(
                                        gpui_kit::base::h_flex()
                                            .gap_3()
                                            .items_center()
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .child(format!(
                                                        "探活进度 {} / {}",
                                                        self.progress_done, self.progress_total
                                                    )),
                                            )
                                            .child(
                                                div().flex_1().child(
                                                    Progress::new("scan-progress")
                                                        .value(progress_ratio),
                                                ),
                                            )
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child(format!("速度 {speed} 个/秒")),
                                            ),
                                    )
                                    .when(self.ps_total > 0, |this| {
                                        this.child(
                                            gpui_kit::base::h_flex()
                                                .gap_3()
                                                .items_center()
                                                .child(
                                                    div().text_sm().child(format!(
                                                        "端口进度 {} / {}",
                                                        self.ps_done, self.ps_total
                                                    )),
                                                )
                                                .child(div().flex_1().child(
                                                    Progress::new("scan-ports").value(port_ratio),
                                                )),
                                        )
                                    }),
                            ),
                    ),
            )
            // ---- 结果表（占约 2/3 高度） ----
            .child(
                div()
                    .flex_grow(2.0)
                    .min_h_0()
                    .px_3()
                    .py_1()
                    .child(DataTable::new(&self.table).stripe(true).bordered(true)),
            )
            // ---- 状态栏 ----
            .child(
                gpui_kit::base::h_flex()
                    .gap_4()
                    .items_center()
                    .px_3()
                    .py_1()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(
                        div().text_sm().child(format!(
                            "目标 {} · 存活 {}",
                            self.total_count, self.alive_count
                        )),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("用时 {:.1}s", self.elapsed.as_secs_f64())),
                    ),
            )
    }
}
