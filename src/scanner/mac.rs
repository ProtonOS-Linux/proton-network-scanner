//! MAC (hardware) addresses of devices on the local network, read from the
//! operating system's ARP table.
//!
//! ARP only works inside the local network segment, so callers should only ask
//! about addresses in one of this computer's own subnets. Sending a ping (or a
//! TCP probe) to an address makes the OS resolve it with ARP first, which is
//! why this lookup runs right after the ping — and why it also finds devices
//! whose firewall silently drops ping.

use std::fmt;
use std::net::Ipv4Addr;

/// A 6-byte Ethernet/Wi-Fi hardware address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Bit 1 of the first byte set = "locally administered". Phones and
    /// laptops use such random addresses for Wi-Fi privacy, so no vendor can
    /// be looked up.
    pub fn is_randomized(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// All-zero or broadcast addresses are not real devices.
    pub fn is_valid(&self) -> bool {
        self.0 != [0; 6] && self.0 != [0xff; 6]
    }

    /// Parse `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`.
    pub fn parse(s: &str) -> Option<Mac> {
        let mut out = [0u8; 6];
        let mut parts = s.trim().split([':', '-']);
        for byte in &mut out {
            *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
        }
        parts.next().is_none().then_some(Mac(out))
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

/// Look up the MAC address of `ip` in the ARP table.
///
/// Linux: reads `/proc/net/arp` (world-readable, no root needed). Only
/// complete entries (flag 0x2) count; "incomplete" entries mean ARP got no
/// answer, i.e. nobody is at that address.
#[cfg(not(windows))]
pub fn lookup(ip: Ipv4Addr) -> Option<Mac> {
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_proc_net_arp(&table, ip)
}

/// Parse the text of `/proc/net/arp` (split out so it can be unit-tested).
///
/// Format: `IP address  HW type  Flags  HW address  Mask  Device`
#[cfg_attr(windows, allow(dead_code))]
fn parse_proc_net_arp(table: &str, ip: Ipv4Addr) -> Option<Mac> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 || cols[0].parse::<Ipv4Addr>().ok()? != ip {
            return None;
        }
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
        let mac = Mac::parse(cols[3])?;
        (flags & 0x2 != 0 && mac.is_valid()).then_some(mac)
    })
}

/// Windows: `SendARP` asks the OS to resolve the address (using its cache
/// when it can) and returns the hardware address. No admin rights needed.
#[cfg(windows)]
pub fn lookup(ip: Ipv4Addr) -> Option<Mac> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

    // Room for 8 bytes as the API documents; we use the first 6.
    let mut buf = [0u8; 8];
    let mut len: u32 = buf.len() as u32;
    // SAFETY: `buf`/`len` describe a valid writable buffer for the call;
    // SendARP writes at most `len` bytes and updates `len`.
    let rc = unsafe { SendARP(u32::from_ne_bytes(ip.octets()), 0, buf.as_mut_ptr().cast(), &mut len) };
    if rc != 0 || len < 6 {
        return None;
    }
    let mac = Mac([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]]);
    mac.is_valid().then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:2b:b0:11:22:33     *        wlan0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.77     0x1         0x2         da:a1:19:00:00:01     *        wlan0
";

    #[test]
    fn parses_complete_entries_only() {
        let gw = parse_proc_net_arp(SAMPLE, Ipv4Addr::new(192, 168, 1, 1)).unwrap();
        assert_eq!(gw.to_string(), "A4:2B:B0:11:22:33");
        assert!(parse_proc_net_arp(SAMPLE, Ipv4Addr::new(192, 168, 1, 50)).is_none());
        assert!(parse_proc_net_arp(SAMPLE, Ipv4Addr::new(192, 168, 1, 9)).is_none());
        assert!(parse_proc_net_arp(SAMPLE, Ipv4Addr::new(192, 168, 1, 77)).unwrap().is_randomized());
    }

    #[test]
    fn mac_parse() {
        assert!(Mac::parse("aa-bb-cc-dd-ee-ff").is_some());
        assert!(Mac::parse("aa:bb:cc:dd:ee").is_none());
        assert!(Mac::parse("aa:bb:cc:dd:ee:ff:00").is_none());
        assert!(Mac::parse("zz:bb:cc:dd:ee:ff").is_none());
    }
}
