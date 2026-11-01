//! 扫描结果表格（DataTable delegate）。
//!
//! 首列为勾选框，支持标记任意多行；行右键菜单提供复制操作：
//! 复制本行 IP、复制勾选行 IP / 内容、复制全部 IP / 内容（内容为 TSV，可直接粘贴到 Excel）。

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use gpui_kit::assets::IconName;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::component::WindowExt as _;
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::menu::{PopupMenu, PopupMenuItem};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::table::{Column, TableDelegate, TableState};
use gpui_kit::{
    App, ClipboardItem, Context, Entity, IntoElement, ParentElement as _, SharedString,
    Styled as _, Window, div, px,
};

use crate::core::events::HostResult;

/// 表格中的一行
#[derive(Debug, Clone)]
pub struct HostRow {
    pub ip: Ipv4Addr,
    pub alive: bool,
    pub latency: Option<Duration>,
    pub confirmed_by: String,
    pub open_ports: String,
    pub detail: String,
}

impl From<&HostResult> for HostRow {
    fn from(r: &HostResult) -> Self {
        HostRow {
            ip: r.ip,
            alive: r.alive,
            latency: r.latency,
            confirmed_by: r.confirmed_by.join(","),
            open_ports: r
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(","),
            detail: r.detail.clone(),
        }
    }
}

impl HostRow {
    /// 行的 TSV 文本（ip / alive / latency_ms / confirmed_by / open_ports / detail）
    fn to_tsv(&self) -> String {
        let latency = self
            .latency
            .map(|d| format!("{:.1}", d.as_secs_f64() * 1000.0))
            .unwrap_or_default();
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.ip, self.alive, latency, self.confirmed_by, self.open_ports, self.detail
        )
    }

    fn ip_text(&self) -> String {
        self.ip.to_string()
    }
}

pub struct ResultsDelegate {
    rows: Vec<HostRow>,
    /// 勾选的行（按 IP 记录）
    checked: HashSet<Ipv4Addr>,
}

impl ResultsDelegate {
    pub fn new() -> Self {
        ResultsDelegate {
            rows: Vec::new(),
            checked: HashSet::new(),
        }
    }

    pub fn clear(&mut self) {
        self.rows.clear();
        self.checked.clear();
    }

    pub fn replace_rows(&mut self, rows: Vec<HostRow>) {
        self.rows = rows;
        // 保留仍然可见行的勾选
        let visible: HashSet<Ipv4Addr> = self.rows.iter().map(|r| r.ip).collect();
        self.checked.retain(|ip| visible.contains(ip));
    }

    fn toggle_checked(&mut self, ip: Ipv4Addr) {
        if !self.checked.remove(&ip) {
            self.checked.insert(ip);
        }
    }

    fn checked_ips(&self) -> Vec<&HostRow> {
        self.rows
            .iter()
            .filter(|r| self.checked.contains(&r.ip))
            .collect()
    }
}

impl Default for ResultsDelegate {
    fn default() -> Self {
        Self::new()
    }
}

pub const COL_CHECK: usize = 0;
pub const COL_IP: usize = 1;
pub const COL_STATUS: usize = 2;
pub const COL_LATENCY: usize = 3;
pub const COL_METHODS: usize = 4;
pub const COL_PORTS: usize = 5;
const COLS: usize = 7;

impl TableDelegate for ResultsDelegate {
    fn columns_count(&self, _: &App) -> usize {
        COLS
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> Column {
        match col_ix {
            COL_CHECK => Column::new("check", "").width(px(44.)).fixed_left(),
            COL_IP => Column::new("ip", "IP 地址").width(px(126.)).fixed_left(),
            COL_STATUS => Column::new("status", "状态").width(px(64.)),
            COL_LATENCY => Column::new("latency", "时延").width(px(80.)),
            COL_METHODS => Column::new("methods", "确认方式").width(px(120.)),
            COL_PORTS => Column::new("ports", "开放端口").width(px(240.)),
            _ => Column::new("detail", "备注").width(px(340.)),
        }
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(row) = self.rows.get(row_ix) else {
            return div().into_any_element();
        };
        let success = cx.theme().success;
        let danger = cx.theme().danger;
        let muted = cx.theme().muted_foreground;

        match col_ix {
            COL_CHECK => {
                let checked = self.checked.contains(&row.ip);
                let ip = row.ip;
                Checkbox::new(SharedString::from(format!("chk-{row_ix}")))
                    .checked(checked)
                    .on_click(cx.listener(
                        move |this: &mut TableState<Self>, _: &bool, _window, cx| {
                            this.delegate_mut().toggle_checked(ip);
                            cx.notify();
                        },
                    ))
                    .into_any_element()
            }
            COL_IP => div()
                .child(SharedString::from(row.ip.to_string()))
                .into_any_element(),
            COL_STATUS => {
                let (text, color) = if row.alive {
                    ("存活", success)
                } else {
                    ("未响应", muted)
                };
                div().text_color(color).child(text).into_any_element()
            }
            COL_LATENCY => div()
                .text_color(if row.alive { success } else { muted })
                .child(
                    row.latency
                        .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                        .unwrap_or_else(|| "—".into()),
                )
                .into_any_element(),
            COL_METHODS => div()
                .text_color(if row.alive {
                    cx.theme().foreground
                } else {
                    muted
                })
                .child(SharedString::from(row.confirmed_by.clone()))
                .into_any_element(),
            COL_PORTS => div()
                .text_color(if row.open_ports.is_empty() {
                    muted
                } else {
                    danger
                })
                .child(SharedString::from(row.open_ports.clone()))
                .into_any_element(),
            _ => div()
                .text_color(muted)
                .child(SharedString::from(row.detail.clone()))
                .into_any_element(),
        }
    }

    /// 行右键菜单：复制 IP / 内容
    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: PopupMenu,
        window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> PopupMenu {
        let Some(row) = self.rows.get(row_ix) else {
            return menu;
        };
        let row_ip = row.ip;
        let checked_rows = self.checked_ips();
        let has_checked = !checked_rows.is_empty();
        let checked_ips: String = checked_rows
            .iter()
            .map(|r| r.ip_text())
            .collect::<Vec<_>>()
            .join("\n");
        let checked_tsv: String = checked_rows
            .iter()
            .map(|r| r.to_tsv())
            .collect::<Vec<_>>()
            .join("\n");
        let all_ips: String = self
            .rows
            .iter()
            .map(|r| r.ip_text())
            .collect::<Vec<_>>()
            .join("\n");
        let all_tsv: String = self
            .rows
            .iter()
            .map(|r| r.to_tsv())
            .collect::<Vec<_>>()
            .join("\n");

        let entity: Entity<TableState<ResultsDelegate>> = cx.entity();

        // 构造一个复制菜单项：点击后写入剪贴板并提示
        let copy_item = |label: &'static str,
                         icon: IconName,
                         text: String,
                         disabled: bool,
                         window: &mut Window,
                         entity: &Entity<TableState<ResultsDelegate>>|
         -> PopupMenuItem {
            PopupMenuItem::new(label)
                .icon(icon)
                .disabled(disabled)
                .on_click(window.listener_for(entity, move |_, _, window, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                    window.push_notification(Notification::success("已复制到剪贴板"), cx);
                }))
        };

        menu.item(
            PopupMenuItem::new(format!("复制 IP（{row_ip}）"))
                .icon(IconName::Copy)
                .on_click(window.listener_for(&entity, move |_, _, window, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(row_ip.to_string()));
                    window.push_notification(Notification::success("已复制到剪贴板"), cx);
                })),
        )
        .separator()
        .item(copy_item(
            "复制勾选行 IP",
            IconName::Copy,
            checked_ips,
            !has_checked,
            window,
            &entity,
        ))
        .item(copy_item(
            "复制勾选行完整内容 (TSV)",
            IconName::Clipboard,
            checked_tsv,
            !has_checked,
            window,
            &entity,
        ))
        .separator()
        .item(copy_item(
            "复制全部 IP",
            IconName::Copy,
            all_ips,
            self.rows.is_empty(),
            window,
            &entity,
        ))
        .item(copy_item(
            "复制全部内容 (TSV)",
            IconName::Clipboard,
            all_tsv,
            self.rows.is_empty(),
            window,
            &entity,
        ))
    }
}

/// 从结果集合构建表格行（应用存活过滤）
pub fn build_rows(
    results: &std::collections::BTreeMap<Ipv4Addr, HostResult>,
    alive_only: bool,
) -> Vec<HostRow> {
    results
        .values()
        .filter(|r| !alive_only || r.alive)
        .map(HostRow::from)
        .collect()
}
