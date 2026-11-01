//! ICMP Echo 探活探针。
//!
//! - Windows：调用 iphlpapi 的 `IcmpSendEcho`，普通用户即可使用，不依赖防火墙放行本机
//!   出站原始套接字，是 Windows 上最稳定的 ICMP 实现方式。
//! - Unix/macOS：raw socket 发送 Echo（需要 root 或 cap_net_raw），失败时给出明确提示。

use std::net::Ipv4Addr;
use std::time::Duration;

use super::ProbeOutcome;

pub async fn probe(ip: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
    #[cfg(windows)]
    {
        windows::probe(ip, timeout).await
    }
    #[cfg(unix)]
    {
        unix::probe(ip, timeout).await
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (ip, timeout);
        ProbeOutcome::dead("当前平台不支持 ICMP 探测")
    }
}

const PAYLOAD_LEN: usize = 32;

fn payload() -> [u8; PAYLOAD_LEN] {
    // 类似 ping 默认载荷的可辨识填充
    let mut data = [0u8; PAYLOAD_LEN];
    for (i, b) in data.iter_mut().enumerate() {
        *b = b'a' + (i % 23) as u8;
    }
    data
}

#[cfg(windows)]
mod windows {
    use super::*;

    // ---- iphlpapi FFI ----
    type Handle = *mut core::ffi::c_void;
    const INVALID_HANDLE: Handle = -1isize as Handle;

    const IP_SUCCESS: u32 = 0;
    const IP_REQ_TIMED_OUT: u32 = 11010;

    #[repr(C)]
    struct IcmpOptions {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }

    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut core::ffi::c_void,
        options: IcmpOptions,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> Handle;
        fn IcmpCloseHandle(handle: Handle) -> u32;
        fn IcmpSendEcho(
            icmp_handle: Handle,
            destination_address: u32,
            request_data: *const core::ffi::c_void,
            request_size: u16,
            request_options: *const core::ffi::c_void,
            reply_buffer: *mut core::ffi::c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    pub async fn probe(ip: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
        let timeout_ms = timeout.as_millis().clamp(1, 60_000) as u32;
        let res = tokio::task::spawn_blocking(move || send_echo(ip, timeout_ms))
            .await
            .expect("ICMP blocking 任务不应 panic");
        match res {
            Ok(Some(rtt)) => {
                ProbeOutcome::alive(Some(Duration::from_millis(rtt as u64)), "Echo 应答")
            }
            Ok(None) => ProbeOutcome::dead("超时"),
            Err(e) => ProbeOutcome::dead(e),
        }
    }

    /// 返回 Ok(Some(rtt_ms)) 表示收到应答；Ok(None) 表示超时；Err 为错误说明。
    fn send_echo(ip: Ipv4Addr, timeout_ms: u32) -> Result<Option<u32>, String> {
        unsafe {
            let handle = IcmpCreateFile();
            if handle == INVALID_HANDLE || handle.is_null() {
                return Err("IcmpCreateFile 失败".into());
            }
            let result = send_echo_with(handle, ip, timeout_ms);
            IcmpCloseHandle(handle);
            result
        }
    }

    fn send_echo_with(
        handle: Handle,
        ip: Ipv4Addr,
        timeout_ms: u32,
    ) -> Result<Option<u32>, String> {
        let data = payload();
        let reply_len = std::mem::size_of::<IcmpEchoReply>() + PAYLOAD_LEN + 8;
        let mut reply_buf = vec![0u8; reply_len];

        let replies = unsafe {
            IcmpSendEcho(
                handle,
                u32::from_ne_bytes(ip.octets()), // IPAddr 为网络字节序内存布局
                data.as_ptr() as *const core::ffi::c_void,
                PAYLOAD_LEN as u16,
                std::ptr::null(),
                reply_buf.as_mut_ptr() as *mut core::ffi::c_void,
                reply_len as u32,
                timeout_ms,
            )
        };
        if replies == 0 {
            return Ok(None); // 常规场景即超时
        }
        let reply = unsafe { &*(reply_buf.as_ptr() as *const IcmpEchoReply) };
        match reply.status {
            IP_SUCCESS => Ok(Some(reply.round_trip_time)),
            IP_REQ_TIMED_OUT => Ok(None),
            code => Err(format!("ICMP 错误码 {code}")),
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::net::SocketAddrV4;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::Instant;

    use socket2::{Domain, Protocol, Socket, Type};

    use super::*;

    static SEQ: AtomicU16 = AtomicU16::new(1);

    pub async fn probe(ip: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let ident = (std::process::id() & 0xFFFF) as u16;
        let res = tokio::task::spawn_blocking(move || raw_echo(ip, ident, seq, timeout))
            .await
            .expect("ICMP blocking 任务不应 panic");
        match res {
            Ok(Some(latency)) => ProbeOutcome::alive(Some(latency), "Echo 应答"),
            Ok(None) => ProbeOutcome::dead("超时"),
            Err(e) => {
                let hint = matches!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrInUse
                )
                .then(|| "（raw socket 需要 root 权限或 cap_net_raw，可改用 ping/tcp 方式）")
                .unwrap_or("");
                ProbeOutcome::dead(format!("ICMP 不可用: {e}{hint}"))
            }
        }
    }

    fn raw_echo(
        ip: Ipv4Addr,
        ident: u16,
        seq: u16,
        timeout: Duration,
    ) -> std::io::Result<Option<Duration>> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_nonblocking(false)?;

        let packet = build_echo(ident, seq);
        let dst = SocketAddrV4::new(ip, 0);
        socket.send_to(&packet, &socket2::SockAddr::from(dst))?;

        let started = Instant::now();
        let mut buf = [0u8; 1500];
        while started.elapsed() < timeout {
            // 收包deadline 对齐超时
            let remain = timeout.saturating_sub(started.elapsed());
            if remain.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(remain))?;
            let (n, _) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            if parse_reply(&buf[..n], ident, seq).is_some() {
                return Ok(Some(started.elapsed()));
            }
            // 其他进程/历史报文，继续收
        }
        Ok(None)
    }

    fn build_echo(ident: u16, seq: u16) -> [u8; 8 + PAYLOAD_LEN] {
        let mut pkt = [0u8; 8 + PAYLOAD_LEN];
        pkt[0] = 8; // Echo Request
        pkt[1] = 0;
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // 校验和占位
        pkt[4..6].copy_from_slice(&ident.to_be_bytes());
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        pkt[8..].copy_from_slice(&payload());
        let sum = checksum(&pkt);
        pkt[2..4].copy_from_slice(&sum.to_be_bytes());
        pkt
    }

    /// 从原始 IP 报文中解析匹配的 Echo Reply。
    fn parse_reply(buf: &[u8], ident: u16, seq: u16) -> Option<()> {
        if buf.len() < 21 {
            return None;
        }
        let ihl = (buf[0] & 0x0F) as usize * 4;
        if buf.len() < ihl + 8 {
            return None;
        }
        let icmp = &buf[ihl..];
        if icmp[0] != 0 {
            return None; // 只接受 Echo Reply
        }
        let rx_ident = u16::from_be_bytes([icmp[4], icmp[5]]);
        let rx_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
        if rx_ident != ident || rx_seq != seq {
            return None;
        }
        Some(())
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in data.chunks(2) {
            let w = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum += w;
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}
