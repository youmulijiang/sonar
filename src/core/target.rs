use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, anyhow, bail};

/// 展开目标描述串（逗号 / 空白分隔），支持：
/// - 单个 IP：`192.168.1.1`
/// - CIDR：`192.168.1.0/24`（前缀 ≤30 时跳过网络地址与广播地址）
/// - 末段范围：`192.168.1.1-254`
/// - 完整范围：`192.168.1.1-192.168.1.254`
/// - 域名：`example.com`（解析其 A 记录）
///
/// 返回排序去重后的 IPv4 列表与解析警告（单个目标失败不影响其余目标）。
/// 超过 `max_hosts` 报错。
pub async fn expand_targets(
    specs: &[String],
    max_hosts: usize,
) -> anyhow::Result<(Vec<Ipv4Addr>, Vec<String>)> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for token in tokenize(specs) {
        if let Err(e) = parse_token(&token, max_hosts, &mut out).await {
            warnings.push(format!("{token}: {e}"));
        }
    }

    if out.is_empty() {
        let mut msg = String::from("没有可用的扫描目标");
        if !warnings.is_empty() {
            msg.push('；');
            msg.push_str(&warnings.join("；"));
        }
        bail!("{msg}");
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > max_hosts {
        bail!(
            "目标主机数 {} 超过上限 {}，请缩小范围",
            out.len(),
            max_hosts
        );
    }
    Ok((out, warnings))
}

fn tokenize(specs: &[String]) -> Vec<String> {
    specs
        .iter()
        .flat_map(|s| s.split(|c: char| c == ',' || c == ';' || c.is_whitespace()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

async fn parse_token(token: &str, max_hosts: usize, out: &mut Vec<Ipv4Addr>) -> anyhow::Result<()> {
    // 范围形式 a-b
    if let Some((left, right)) = token.split_once('-')
        && !left.is_empty()
        && !right.is_empty()
    {
        return parse_range(left.trim(), right.trim(), max_hosts, out);
    }

    // CIDR
    if token.contains('/') {
        let net: ipnet::Ipv4Net = token
            .parse()
            .with_context(|| format!("无效的 CIDR: {token}"))?;
        let start = u32::from(net.network());
        let end = u32::from(net.broadcast());
        let count = (end - start) as u64 + 1;
        if count > max_hosts as u64 {
            bail!("网段包含 {count} 个地址，超过上限 {max_hosts}");
        }
        // 前缀 ≤30 跳过网络地址与广播地址；/31 /32 保留全部地址
        if net.prefix_len() >= 31 {
            for v in start..=end {
                out.push(Ipv4Addr::from(v));
            }
        } else {
            for ip in net.hosts() {
                out.push(ip);
            }
        }
        return Ok(());
    }

    // 单个 IP
    if let Ok(ip) = token.parse::<Ipv4Addr>() {
        out.push(ip);
        return Ok(());
    }

    // 域名解析 A 记录
    let addrs = tokio::net::lookup_host((token, 0u16))
        .await
        .with_context(|| format!("域名解析失败: {token}"))?;
    let mut got = false;
    for a in addrs {
        if let IpAddr::V4(v4) = a.ip() {
            out.push(v4);
            got = true;
        }
    }
    if !got {
        bail!("域名未解析到 IPv4 地址: {token}");
    }
    Ok(())
}

fn parse_range(
    left: &str,
    right: &str,
    max_hosts: usize,
    out: &mut Vec<Ipv4Addr>,
) -> anyhow::Result<()> {
    let start: Ipv4Addr = left
        .parse()
        .map_err(|_| anyhow!("无效的起始地址: {left}"))?;

    // 两种形式：a.b.c.d-e（末段范围） 或 a.b.c.d-a.b.c.d
    let end: Ipv4Addr = match right.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => {
            let last: u8 = right
                .parse()
                .map_err(|_| anyhow!("无效的范围端点: {right}"))?;
            let o = start.octets();
            Ipv4Addr::new(o[0], o[1], o[2], last)
        }
    };

    let s = u32::from(start);
    let e = u32::from(end);
    if s > e {
        bail!("范围起始 {start} 大于结束 {end}");
    }
    let count = (e - s) as u64 + 1;
    if count > max_hosts as u64 {
        bail!("范围包含 {count} 个地址，超过上限 {max_hosts}");
    }
    for v in s..=e {
        out.push(Ipv4Addr::from(v));
    }
    Ok(())
}

/// 从文本内容提取目标 token（每行一个，忽略空行与 `#` 注释行）。
/// 不做格式校验，交由 `expand_targets` 处理。
pub fn targets_from_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// 解析端口描述串：`22,80,443`、`1-1024`、`1-65535` 混合形式
pub fn parse_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.trim().parse().map_err(|_| anyhow!("无效端口: {a}"))?;
            let end: u16 = b.trim().parse().map_err(|_| anyhow!("无效端口: {b}"))?;
            if start == 0 || start > end {
                bail!("无效的端口范围: {part}");
            }
            ports.extend(start..=end);
        } else {
            let p: u16 = part.parse().map_err(|_| anyhow!("无效端口: {part}"))?;
            if p == 0 {
                bail!("端口号必须大于 0");
            }
            ports.push(p);
        }
    }
    if ports.is_empty() {
        bail!("端口列表为空");
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("10-12").unwrap(), vec![10, 11, 12]);
        assert_eq!(parse_ports("80, 1000-1002, 443").unwrap().len(), 5);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("10-5").is_err());
    }

    #[tokio::test]
    async fn test_expand_ips() {
        let (out, warn) = expand_targets(&["127.0.0.1".into()], 1000).await.unwrap();
        assert_eq!(out, vec![Ipv4Addr::LOCALHOST]);
        assert!(warn.is_empty());

        let (out, _) = expand_targets(&["127.0.0.2-4".into()], 1000).await.unwrap();
        assert_eq!(out.len(), 3);

        let (out, _) = expand_targets(&["127.0.0.5-127.0.0.7".into()], 1000)
            .await
            .unwrap();
        assert_eq!(out.len(), 3);

        // 单个目标失败不影响其余目标，且产生警告
        let (out, warn) = expand_targets(&["无效目标!!, 127.0.0.1".into()], 1000)
            .await
            .unwrap();
        assert_eq!(out, vec![Ipv4Addr::LOCALHOST]);
        assert_eq!(warn.len(), 1);

        let (out, _) = expand_targets(&["127.0.0.0/30".into()], 1000)
            .await
            .unwrap();
        assert_eq!(out.len(), 2); // 排除网络地址与广播地址

        let (out, _) = expand_targets(&["127.0.0.0/31".into()], 1000)
            .await
            .unwrap();
        assert_eq!(out.len(), 2); // 点对点网段包含全部地址
    }
}

#[cfg(test)]
mod text_tests {
    use super::targets_from_text;

    #[test]
    fn test_targets_from_text() {
        let text = "192.168.1.1\n\n# 注释行\n  10.0.0.0/24  \nexample.com\n";
        let out = targets_from_text(text);
        assert_eq!(out, vec!["192.168.1.1", "10.0.0.0/24", "example.com"]);
        assert!(targets_from_text("").is_empty());
        assert!(targets_from_text("# only comment").is_empty());
    }
}
