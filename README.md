<div align="center">

# 🔭 Sonar

**基于 Rust + GPUI + Tokio 的高性能 IP 探活扫描器**

ICMP · 系统 Ping · TCP Ping · 端口扫描 —— 多探针、高并发、参考 RustScan 的并发模型

[![CI](https://github.com/youmulijiang/sonar/actions/workflows/ci.yml/badge.svg)](https://github.com/youmulijiang/sonar/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#平台支持)

</div>

---

## ✨ 特性

| 探活方式 | 说明 | 权限要求 |
| --- | --- | --- |
| **ICMP** | 原生 ICMP Echo。Windows 走 iphlpapi 的 `IcmpSendEcho`（免管理员）；Unix 走 raw socket | Windows 普通用户 / Unix 需 root 或 `cap_net_raw` |
| **系统 Ping** | 调用操作系统自带 `ping` 命令 | 无 |
| **TCP Ping** | 对常用服务端口发起 TCP 连接，连接成功**或收到 RST** 均判定存活 | 无 |
| **端口扫描** | RustScan 风格 (主机, 端口) 全并发扫描，开启后仅扫描**尚未确认存活的目标**——禁 ping 等其他方式未确认的主机也能由开放端口 / RST 判定存活（默认关闭，可一键开启） | 无 |

- 🎯 **多探针高并发**：探活方式三选一 + 可选端口扫描；`buffer_unordered` 全速流水推进，慢主机不阻塞整体
- 🧾 **目标灵活**：多行文本框每行一个目标，支持 IP / IP 段 / CIDR / 域名（`192.168.1.0/24`、`10.0.0.1-100`、`db.example.com`），可从文本文件导入（支持 `#` 注释）
- 🗂 **GPU 加速界面**：GPUI 渲染，结果表格虚拟滚动（十万行级），首列勾选 + 右键菜单复制 IP / 内容（TSV 可直接粘贴 Excel）
- 📊 **实时进度**：探活进度、速度（个/秒）、端口扫描进度
- 🔒 **稳定可靠**：失败重试、RST 视为存活信号、全程可取消、目标规模上限保护
- 📤 **导入导出**：CSV / JSON 行式导出，CLI `--json` 供脚本消费

## 🚀 快速开始

```bash
# 克隆并构建（需要 Rust stable，MSVC 工具链）
git clone https://github.com/youmulijiang/sonar.git
cd sonar
cargo build --release

# 启动图形界面
./target/release/sonar.exe
```

### CLI 模式

带参数运行即进入无头命令行模式：

```bash
# 探活一个 C 段（ICMP + TCP Ping）
sonar 192.168.1.0/24 -m icmp,tcp --alive-only

# 开启端口扫描（默认 Top 20 常用端口）
sonar 192.168.1.0/24 -m icmp,port --scan-ports 1-65535

# JSON 行输出供脚本消费
sonar 10.0.0.1-100 -m tcp --json
```

<details>
<summary><b>全部 CLI 参数</b></summary>

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-m, --methods` | `icmp,tcp` | 探活方式 `icmp,ping,tcp,port` |
| `--tcp-ports` | 常用端口 | TCP 探活候选端口 |
| `--scan-ports` | Top 20 | 端口扫描范围，支持 `1-65535` |
| `--timeout-ms` | `1500` | 单次探测超时 |
| `--retries` | `1` | 失败重试次数 |
| `--concurrency` | `256` | 主机探活并发数 |
| `--scan-concurrency` | `4000` | 端口扫描 (主机, 端口) 对并发数 |
| `--alive-only` | 关 | 只输出存活主机 |
| `--json` | 关 | JSON 行格式输出 |

</details>

## 🖥 界面

```
[▶ 开始] [停止]                      [导入 / 导出 ▾] [⚙ 选项]
┌─ 目标 ─────────────── [清空][去重][导入] ┐ ┌─ 扫描配置 ─────────────┐
│ 每行一个目标，支持 IP / IP段 /           │ │ 方式 ◉ICMP ○系统Ping ○TCP │
│ CIDR / 域名                             │ │ 并发/超时/重试            │
│                                         │ │ ── 端口扫描（默认关闭）──  │
└─────────────────────────────────────────┘ │ 扫描端口(Top20) 扫描并发  │
┌─ 结果表格（约占 2/3 高度，右键复制）─────┐ │ 探活进度 ▓▓▓░░ 速度 N个/秒 │
│ ☑ 192.168.1.1  存活  3ms  ICMP  [22,80] │ └────────────────────────┘
└─────────────────────────────────────────┘
```

- **目标区**：多行输入，每行一个目标；清空 / 去重 / 文件导入
- **扫描配置**：探活方式互斥单选 + 参数；端口扫描分区默认关闭
- **结果表格**：勾选行后右键复制勾选 IP / 完整内容（TSV），也可复制全部

## 🏗 架构

```
src/
├── main.rs              # 入口：无参 → GUI；带参 → CLI
├── cli.rs               # 命令行模式（clap）
├── ui/                  # GPUI 界面（gpui-kit 组件库）
│   ├── mod.rs           # 主窗口：目标区 / 扫描配置 / 进度 / 表格
│   └── results_table.rs # 结果表格 delegate：勾选、右键复制、虚拟滚动
└── core/                # 与 UI 完全解耦的扫描核心
    ├── target.rs        # 目标解析：IP / CIDR / 范围 / 域名
    ├── config.rs        # 扫描配置与探活方式定义
    ├── probe/
    │   ├── icmp.rs      # ICMP：Windows IcmpSendEcho FFI / Unix raw socket
    │   ├── sysping.rs   # 系统 ping 命令探针
    │   ├── tcp.rs       # TCP Ping 探针（Open / RST / Filtered 三态）
    │   └── portscan.rs  # 惰性分块的全并发端口扫描
    ├── scanner.rs       # 调度器：探活阶段 + 端口扫描阶段 + 事件流
    └── runtime.rs       # 独立线程 + 独立 Tokio 运行时宿主
```

**并发模型**（参考 RustScan）：主机探活 `buffer_unordered(N)` 全速流水；端口扫描把
(主机, 端口) 对惰性分块，块内全并发，内存占用只与并发数相关而与目标规模无关。
扫描跑在独立线程的 Tokio 运行时上，通过 crossbeam 通道推送事件，GPUI 以 80ms
批量轮询刷新，界面始终流畅。

## 🧪 开发

```bash
cargo check           # 类型检查
cargo clippy          # Lint（CI 以 -D warnings 把关）
cargo test            # 单元测试
cargo build --release # 发布构建
```

CI（GitHub Actions，windows-latest）覆盖：`cargo fmt --check` → `clippy -D warnings`
→ `cargo test` → `cargo build --release`。

## ⚠️ 注意事项

- **Windows**：ICMP 走 `IcmpSendEcho`，普通用户即可；目标禁 ping 时请用 TCP Ping
  或端口扫描方式兜底。
- **Unix**：ICMP 需要 root 或 `setcap cap_net_raw`，否则提示改用 ping/tcp。
- **VPN / 安全软件 / TUN 代理**可能干扰 TCP 探测：或吞掉 RST（关闭端口表现为超时），
  或劫持全部出站连接（任何端口都"连接成功"，端口扫描将产生大量假阳性存活）。
  端口扫描结果请结合 ICMP 判断，必要时在代理软件中将目标网段加入直连规则。
- **Debug 构建**下，gpui 上游（gpui-pre 0.3.10）存在一个无障碍焦点断言
  （`set_focus called more than once in a single frame`），在特定交互下会 panic；
  该断言仅启用 `debug_assertions` 时生效，**release 构建不受影响**。

## 📄 License

[MIT](LICENSE) © 2026

### ARP 探活

图形界面可选择 ARP，命令行使用 `-m arp` 或 `-m arp,icmp,tcp,port`。只执行选择的方式；组合时依次执行 ARP、ICMP/Ping、TCP、端口补充探活，确认存活后跳过后续方式。

ARP 当前支持 Windows，使用系统 SendARP，仅探测直连 IPv4 目标，跨路由目标会跳过。系统可能使用邻居缓存，代理 ARP 也可能代答，因此 MAC 解析成功不等于目标应用服务可用。系统调用超时后可能仍在后台完成，并发限制为 32。
