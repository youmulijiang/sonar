use super::ProbeOutcome;
use std::net::Ipv4Addr;
use std::time::Duration;

pub async fn probe(ip: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return ProbeOutcome::dead("ARP requires a unicast address on the local link");
    }
    #[cfg(windows)]
    {
        // Keep the permit inside the blocking call: timing out must not allow
        // unbounded native calls to accumulate during retries.
        static LIMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
        let permit = match LIMIT.acquire().await {
            Ok(p) => p,
            Err(_) => return ProbeOutcome::dead("ARP unavailable"),
        };
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            use windows_sys::Win32::NetworkManagement::IpHelper::{
                GetBestRoute, MIB_IPFORWARDROW, SendARP,
            };
            let address = u32::from_ne_bytes(ip.octets());
            let mut route: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
            let code = unsafe { GetBestRoute(address, 0, &mut route) };
            if code != 0 || unsafe { route.Anonymous1.dwForwardType } != 3 {
                return ProbeOutcome::dead(
                    "ARP skipped: target is not on a directly connected route",
                );
            }
            let started = std::time::Instant::now();
            let mut mac = [0u8; 8];
            let mut len = mac.len() as u32;
            let code = unsafe { SendARP(address, 0, mac.as_mut_ptr().cast(), &mut len) };
            if code == 0 && len == 6 && mac[..6].iter().any(|&b| b != 0) {
                let mac = mac[..6]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                ProbeOutcome::alive(Some(started.elapsed()), format!("ARP MAC {mac}"))
            } else {
                ProbeOutcome::dead(format!("ARP no reply (code {code})"))
            }
        });
        match tokio::time::timeout(timeout, task).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => ProbeOutcome::dead(format!("ARP failed: {e}")),
            Err(_) => ProbeOutcome::dead("ARP timeout"),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = timeout;
        ProbeOutcome::dead("ARP is currently supported on Windows only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_non_link_targets() {
        for ip in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(!probe(ip, Duration::from_secs(1)).await.alive);
        }
    }
}
