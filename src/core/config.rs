use std::time::Duration;

/// 探活方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeMethod {
    /// 原生 ICMP Echo（Windows 走 IcmpSendEcho，无需管理员；Unix 需 root/cap_net_raw）
    Icmp,
    /// 调用操作系统自带 ping 命令（兼容性最好，速度受进程创建限制）
    SystemPing,
    /// TCP 连接探活（连接成功或收到 RST 均视为存活）
    Tcp,
    /// 端口扫描探活（rustscan 风格批量并发连接）
    PortScan,
}

impl ProbeMethod {
    pub fn name(self) -> &'static str {
        match self {
            ProbeMethod::Icmp => "ICMP",
            ProbeMethod::SystemPing => "PING",
            ProbeMethod::Tcp => "TCP",
            ProbeMethod::PortScan => "PORT",
        }
    }

    pub fn from_str(s: &str) -> Option<ProbeMethod> {
        match s.to_ascii_lowercase().as_str() {
            "icmp" => Some(ProbeMethod::Icmp),
            "ping" | "sysping" => Some(ProbeMethod::SystemPing),
            "tcp" => Some(ProbeMethod::Tcp),
            "port" | "portscan" | "scan" => Some(ProbeMethod::PortScan),
            _ => None,
        }
    }
}

/// TCP 探活默认端口（常见服务，命中任意即判定存活）
pub const DEFAULT_LIVENESS_PORTS: &[u16] = &[
    22, 80, 135, 139, 443, 445, 3306, 3389, 5900, 8080, 8000, 8443, 21, 23, 25, 53, 444, 902, 1433,
    5432, 6379, 9100,
];

/// TCP 探活默认端口（文本形式，供 UI / CLI 默认值使用）
pub const DEFAULT_TCP_PORTS_TEXT: &str = "22,80,135,139,443,445,3306,3389,5900,8080";

/// 端口扫描默认端口：服务器最常开放的 Top 20
pub const DEFAULT_SCAN_PORTS: &str =
    "21,22,23,25,53,80,110,135,139,143,443,445,993,1433,3306,3389,5432,5900,6379,8080";

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// 目标列表（IP / CIDR / 范围 / 域名）
    pub targets: Vec<String>,
    /// 启用的探活方式
    pub methods: Vec<ProbeMethod>,
    /// TCP 探活使用的端口
    pub tcp_ports: Vec<u16>,
    /// 端口扫描的目标端口
    pub scan_ports: Vec<u16>,
    /// 单次探测超时
    pub timeout: Duration,
    /// 失败后重试次数（总尝试 = retries + 1）
    pub retries: u32,
    /// 主机级探活并发数
    pub concurrency: usize,
    /// 端口扫描 (主机, 端口) 对并发数
    pub portscan_concurrency: usize,
    /// 单次扫描最大主机数上限
    pub max_hosts: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            targets: Vec::new(),
            methods: vec![ProbeMethod::Icmp, ProbeMethod::Tcp],
            tcp_ports: DEFAULT_LIVENESS_PORTS.to_vec(),
            scan_ports: crate::core::target::parse_ports(DEFAULT_SCAN_PORTS)
                .expect("内置默认端口串必须可解析"),
            timeout: Duration::from_millis(1500),
            retries: 1,
            concurrency: 256,
            portscan_concurrency: 4000,
            max_hosts: 1 << 20,
        }
    }
}
