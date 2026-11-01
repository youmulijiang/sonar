use std::time::Duration;

use std::net::Ipv4Addr;

/// 单个主机的探活结论
#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub alive: bool,
    /// 确认存活的探测方式名（ICMP / PING / TCP / PORT）
    pub confirmed_by: Vec<String>,
    /// 最快确认时延
    pub latency: Option<Duration>,
    /// 端口扫描发现的开放端口（升序）
    pub open_ports: Vec<u16>,
    /// 补充说明
    pub detail: String,
}

/// 导出用：单主机 JSON 行
#[derive(serde::Serialize)]
struct JsonHost {
    ip: String,
    alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<f64>,
    confirmed_by: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    open_ports: Vec<u16>,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
}

/// 单条结果的 JSON 行（供 CLI --json 与 GUI 导出复用）
pub fn to_json_line(r: &HostResult) -> String {
    let h = JsonHost {
        ip: r.ip.to_string(),
        alive: r.alive,
        latency_ms: r.latency.map(|d| d.as_secs_f64() * 1000.0),
        confirmed_by: r.confirmed_by.clone(),
        open_ports: r.open_ports.clone(),
        detail: r.detail.clone(),
    };
    serde_json::to_string(&h).unwrap_or_default()
}

/// 单条结果的 CSV 行（不含表头）
pub fn to_csv_line(r: &HostResult) -> String {
    let lat = r
        .latency
        .map(|d| format!("{:.1}", d.as_secs_f64() * 1000.0))
        .unwrap_or_default();
    let detail = r.detail.replace('"', "\"\"");
    format!(
        "{},{},{},{},{},\"{}\"",
        r.ip,
        r.alive,
        lat,
        r.confirmed_by.join("|"),
        r.open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("|"),
        detail
    )
}

/// CSV 表头（与 to_csv_line 对应）
pub const CSV_HEADER: &str = "ip,alive,latency_ms,confirmed_by,open_ports,detail";

/// 扫描事件流：扫描线程 → UI/CLI 的唯一输出通道
#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        total: usize,
    },
    Log(String),
    Host(Box<HostResult>),
    /// 主机探活阶段进度
    Progress {
        done: usize,
        total: usize,
    },
    /// 端口扫描阶段进度（按 (主机,端口) 对计数）
    PortScanProgress {
        done: usize,
        total: usize,
    },
    Finished {
        elapsed: Duration,
        total: usize,
        alive: usize,
    },
    Error(String),
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_to_json_and_csv_line() {
        let r = HostResult {
            ip: Ipv4Addr::new(192, 168, 1, 7),
            alive: true,
            confirmed_by: vec!["ICMP".into(), "TCP".into()],
            latency: Some(Duration::from_millis(12)),
            open_ports: vec![80, 443],
            detail: "开放端口 80,443".into(),
        };
        let json = to_json_line(&r);
        assert!(json.contains("\"ip\":\"192.168.1.7\""));
        assert!(json.contains("\"open_ports\":[80,443]"));

        let csv = to_csv_line(&r);
        assert_eq!(
            csv,
            "192.168.1.7,true,12.0,ICMP|TCP,80|443,\"开放端口 80,443\""
        );

        let dead = HostResult {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            alive: false,
            confirmed_by: vec![],
            latency: None,
            open_ports: vec![],
            detail: String::new(),
        };
        let json = to_json_line(&dead);
        assert!(json.contains("\"alive\":false"));
        assert!(!json.contains("open_ports")); // 空字段省略
    }
}
