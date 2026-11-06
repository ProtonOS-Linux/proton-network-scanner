//! "Is this address alive?" — ICMP echo (ping) without administrator rights,
//! with a TCP fallback.
//!
//! * **Linux** uses an *unprivileged ICMP socket* (`SOCK_DGRAM` +
//!   `IPPROTO_ICMP`). The kernel allows this for groups listed in
//!   `net.ipv4.ping_group_range`, which Debian/systemd set to all users by
//!   default, so no root and no `setcap` are needed. The kernel fills in the
//!   ICMP identifier and checksum and only delivers replies meant for our
//!   socket.
//! * **Windows** uses `IcmpSendEcho` from `iphlpapi.dll`, the same API the
//!   built-in `ping.exe` uses; it needs no admin rights either.
//! * If ICMP is not available (or a host blocks ping), [`tcp_probe`] tries a
//!   few common TCP ports: both "connection accepted" *and* "connection
//!   refused" prove the host is up.
//!
//! No external `ping` processes are started, which keeps CPU and memory use
//! low even with many threads.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

/// Ports tried by [`tcp_probe`]: web, SSH, Windows file sharing / RPC /
/// Remote Desktop, and the Apple device sync port that iPhones keep open.
const PROBE_PORTS: [u16; 7] = [80, 443, 22, 445, 135, 3389, 62078];

/// Send one ICMP echo request and wait for the reply.
///
/// Returns `Some(round_trip_time)` when the host answered, `None` on timeout
/// or "unreachable". Errors creating the socket are returned as `Err` so the
/// caller can switch to [`tcp_probe`] for the rest of the scan.
#[cfg(not(windows))]
pub fn icmp_ping(ip: Ipv4Addr, timeout: Duration, seq: u16) -> std::io::Result<Option<Duration>> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::UdpSocket;

    // Unprivileged "ping socket". Fails with EACCES if the user's group is not
    // in net.ipv4.ping_group_range.
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    // Converting to UdpSocket only gives us safe send/recv on the same fd;
    // it is still an ICMP socket.
    let sock: UdpSocket = sock.into();
    // `connect` makes the kernel drop replies from any other address.
    sock.connect(SocketAddrV4::new(ip, 0))?;

    // ICMP echo request: type 8, code 0, checksum and identifier left at 0
    // (the kernel fills both in for ping sockets), our sequence number, and a
    // small recognisable payload.
    let mut packet = [0u8; 24];
    packet[0] = 8;
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..].copy_from_slice(b"ProtonIPScanner!");

    let start = Instant::now();
    if sock.send(&packet).is_err() {
        // e.g. "network unreachable": the host is simply not reachable.
        return Ok(None);
    }

    // Wait for a matching echo reply; ignore anything else until the deadline.
    let mut buf = [0u8; 128];
    loop {
        let left = match timeout.checked_sub(start.elapsed()) {
            Some(d) if !d.is_zero() => d,
            _ => return Ok(None),
        };
        sock.set_read_timeout(Some(left))?;
        match sock.recv(&mut buf) {
            // Reply layout (no IP header on ping sockets): type, code,
            // checksum(2), id(2), seq(2), payload…  Type 0 = echo reply.
            Ok(n) if n >= 8 && buf[0] == 0 && buf[6..8] == seq.to_be_bytes() => {
                return Ok(Some(start.elapsed()));
            }
            Ok(_) => continue,         // something else (stale reply): keep waiting
            Err(_) => return Ok(None), // timeout or ICMP "host unreachable"
        }
    }
}

/// Windows version: `IcmpSendEcho` (blocking, with its own timeout).
#[cfg(windows)]
pub fn icmp_ping(ip: Ipv4Addr, timeout: Duration, _seq: u16) -> std::io::Result<Option<Duration>> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };

    /// Data carried in our ICMP echo requests (lets us recognise our replies).
    const PAYLOAD: &[u8; 16] = b"ProtonIPScanner!";
    // The reply buffer must hold one ICMP_ECHO_REPLY, the echoed payload and
    // 8 extra bytes for a possible ICMP error message (documented by Microsoft).
    let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 16];

    // SAFETY: IcmpCreateFile takes no arguments and returns a handle that we
    // check before use and always close below.
    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX).max(1);
    // IPAddr is the address in network byte order, i.e. the octets in memory order.
    let dest = u32::from_ne_bytes(ip.octets());
    let start = Instant::now();
    // SAFETY: `handle` is valid; the request pointer/length describe PAYLOAD;
    // the reply pointer/length describe `reply`, which outlives the call.
    let count = unsafe {
        IcmpSendEcho(
            handle,
            dest,
            PAYLOAD.as_ptr().cast(),
            PAYLOAD.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            reply.len() as u32,
            timeout_ms,
        )
    };
    let elapsed = start.elapsed();
    // SAFETY: handle came from IcmpCreateFile and is closed exactly once.
    unsafe { IcmpCloseHandle(handle) };

    if count == 0 {
        return Ok(None);
    }
    // SAFETY: when count > 0 the buffer starts with an ICMP_ECHO_REPLY. The
    // Vec<u8> may not be aligned for that struct, so read it unaligned.
    let r: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(reply.as_ptr().cast()) };
    // Status 0 = IP_SUCCESS, and the reply must come from the host we asked.
    if r.Status == 0 && r.Address == dest {
        // Windows reports whole milliseconds (0 for "<1 ms"); use our own
        // measurement when it is more precise.
        let rtt = Duration::from_millis(u64::from(r.RoundTripTime));
        Ok(Some(if rtt.is_zero() { elapsed } else { rtt }))
    } else {
        Ok(None)
    }
}

/// Check once whether ICMP ping works for this user on this machine.
///
/// Pinging 127.0.0.1 exercises exactly the same code path as a real scan.
pub fn icmp_available() -> bool {
    matches!(icmp_ping(Ipv4Addr::LOCALHOST, Duration::from_millis(500), 1), Ok(Some(_)))
}

/// Fallback liveness test: try a few TCP ports.
///
/// "Connected" or "connection refused" both mean something answered at that
/// address, so the host is up. Each attempt waits at most `timeout / 3`
/// (minimum 150 ms) so a dead host costs well under a second.
pub fn tcp_probe(ip: Ipv4Addr, timeout: Duration) -> Option<Duration> {
    let per_port = (timeout / 3).max(Duration::from_millis(150));
    for port in PROBE_PORTS {
        let start = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(ip, port)), per_port) {
            Ok(_) => return Some(start.elapsed()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Some(start.elapsed()),
            Err(_) => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_probe_localhost_answers_or_refuses() {
        // Something on 127.0.0.1 always answers (accept or RST).
        assert!(tcp_probe(Ipv4Addr::LOCALHOST, Duration::from_millis(500)).is_some());
    }

    #[test]
    #[ignore = "needs a real network without a transparent proxy"]
    fn tcp_probe_dead_address_times_out() {
        // TEST-NET-1 (RFC 5737) is never routed.
        let t = Instant::now();
        let r = tcp_probe(Ipv4Addr::new(192, 0, 2, 1), Duration::from_millis(300));
        assert!(r.is_none());
        assert!(t.elapsed() < Duration::from_secs(3));
    }
}
