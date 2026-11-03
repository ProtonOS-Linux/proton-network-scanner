//! Parsing of what the user types in the "IP range" box, and of port lists.
//!
//! Accepted IP forms (several can be combined, separated by commas or spaces):
//!
//! | Example                       | Meaning                                  |
//! |-------------------------------|------------------------------------------|
//! | `192.168.1.10`                | one address                              |
//! | `192.168.1.0/24`              | a CIDR block (network/broadcast skipped) |
//! | `192.168.1.1-254`             | last octet range                         |
//! | `192.168.1.1-192.168.2.254`   | full address range                       |
//!
//! Security: the result is capped at [`MAX_HOSTS`] addresses so a typo such as
//! `10.0.0.0/8` cannot make the app allocate millions of entries or flood a
//! network. All parsing is done with the standard library; nothing typed by the
//! user ever reaches a shell.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Largest number of addresses one scan may contain (a /16 network).
pub const MAX_HOSTS: usize = 65_536;

/// Parse an IP range expression into a sorted, de-duplicated list of addresses.
///
/// Returns a plain-language error message suitable for showing in the UI.
pub fn parse_ip_ranges(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut set = BTreeSet::new();

    for part in input.split([',', ' ', ';', '\n', '\t']).filter(|p| !p.is_empty()) {
        if let Some((net, prefix)) = part.split_once('/') {
            add_cidr(&mut set, net, prefix)?;
        } else if let Some((start, end)) = part.split_once('-') {
            add_dash_range(&mut set, start, end)?;
        } else {
            set.insert(parse_ip(part)?);
        }
        if set.len() > MAX_HOSTS {
            return Err(too_many());
        }
    }

    if set.is_empty() {
        return Err("Type an IP range to scan, for example 192.168.1.1-254.".into());
    }
    Ok(set.into_iter().collect())
}

/// Parse a port list such as `22,80,443,8000-8100` into sorted unique ports.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut set = BTreeSet::new();
    for part in input.split([',', ' ', ';', '\n', '\t']).filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (parse_port(a)?, parse_port(b)?),
            None => {
                let p = parse_port(part)?;
                (p, p)
            }
        };
        if a > b {
            return Err(format!("Port range \"{part}\" is backwards."));
        }
        set.extend(a..=b);
    }
    if set.is_empty() {
        return Err("Type at least one port, for example 22,80,443.".into());
    }
    Ok(set.into_iter().collect())
}

/// Build the usual "whole network" range text for an interface address,
/// e.g. `192.168.1.37/24` → `192.168.1.1-192.168.1.254`.
///
/// Networks larger than a /16 are narrowed to the /24 around the address so
/// the default never exceeds what a home or office scan needs.
pub fn network_range_text(addr: Ipv4Addr, prefix_len: u8) -> String {
    let prefix = if prefix_len < 16 { 24 } else { prefix_len.min(32) };
    let (first, last) = usable_hosts(u32::from(addr), prefix);
    if first == last {
        Ipv4Addr::from(first).to_string()
    } else {
        format!("{}-{}", Ipv4Addr::from(first), Ipv4Addr::from(last))
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn parse_ip(s: &str) -> Result<Ipv4Addr, String> {
    s.trim().parse::<Ipv4Addr>().map_err(|_| format!("\"{}\" is not a valid IPv4 address.", short(s)))
}

fn parse_port(s: &str) -> Result<u16, String> {
    match s.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(format!("\"{}\" is not a port number (1-65535).", short(s))),
    }
}

/// First and last usable host for `addr/prefix` (network and broadcast
/// addresses are skipped for blocks larger than /31).
fn usable_hosts(addr: u32, prefix: u8) -> (u32, u32) {
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    let network = addr & mask;
    let broadcast = network | !mask;
    if prefix >= 31 { (network, broadcast) } else { (network + 1, broadcast - 1) }
}

fn add_cidr(set: &mut BTreeSet<Ipv4Addr>, net: &str, prefix: &str) -> Result<(), String> {
    let base = parse_ip(net)?;
    let prefix: u8 = match prefix.trim().parse() {
        Ok(p) if p <= 32 => p,
        _ => return Err(format!("\"/{}\" is not a valid network size (0-32).", short(prefix))),
    };
    let (first, last) = usable_hosts(u32::from(base), prefix);
    add_span(set, first, last)
}

fn add_dash_range(set: &mut BTreeSet<Ipv4Addr>, start: &str, end: &str) -> Result<(), String> {
    let start_ip = parse_ip(start)?;
    // "192.168.1.1-254" → the end is only the last octet.
    let end_ip = if let Ok(octet) = end.trim().parse::<u8>() {
        let o = start_ip.octets();
        Ipv4Addr::new(o[0], o[1], o[2], octet)
    } else {
        parse_ip(end)?
    };
    let (a, b) = (u32::from(start_ip), u32::from(end_ip));
    if a > b {
        return Err(format!("The range {start_ip} - {end_ip} is backwards."));
    }
    add_span(set, a, b)
}

/// Insert every address in `first..=last`, refusing spans above the cap
/// *before* allocating anything.
fn add_span(set: &mut BTreeSet<Ipv4Addr>, first: u32, last: u32) -> Result<(), String> {
    if (last - first) as usize >= MAX_HOSTS {
        return Err(too_many());
    }
    set.extend((first..=last).map(Ipv4Addr::from));
    Ok(())
}

fn too_many() -> String {
    format!("That range is too big. Proton IP Scanner scans up to {MAX_HOSTS} addresses (a /16) at once.")
}

/// Keep error messages short even if the user pasted something huge.
fn short(s: &str) -> String {
    s.trim().chars().take(40).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_lists() {
        let v = parse_ip_ranges("10.0.0.1, 10.0.0.3 10.0.0.1").unwrap();
        assert_eq!(v, vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 3)]);
    }

    #[test]
    fn cidr_skips_network_and_broadcast() {
        let v = parse_ip_ranges("192.168.1.0/24").unwrap();
        assert_eq!(v.len(), 254);
        assert_eq!(v[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(v[253], Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(parse_ip_ranges("10.0.0.5/32").unwrap().len(), 1);
    }

    #[test]
    fn dash_ranges() {
        assert_eq!(parse_ip_ranges("192.168.1.1-254").unwrap().len(), 254);
        assert_eq!(parse_ip_ranges("10.0.0.250-10.0.1.5").unwrap().len(), 12);
        assert!(parse_ip_ranges("10.0.0.9-3").is_err());
    }

    #[test]
    fn caps_and_errors() {
        assert!(parse_ip_ranges("10.0.0.0/8").is_err());
        assert!(parse_ip_ranges("0.0.0.0-255.255.255.255").is_err());
        assert_eq!(parse_ip_ranges("10.1.0.0/16").unwrap().len(), 65_534);
        assert!(parse_ip_ranges("").is_err());
        assert!(parse_ip_ranges("300.1.1.1").is_err());
        assert!(parse_ip_ranges("1.2.3.4/33").is_err());
        assert!(parse_ip_ranges("; rm -rf /").is_err());
    }

    #[test]
    fn ports() {
        assert_eq!(parse_ports("80, 22,443 22").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-1024").unwrap().len(), 1024);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("65536").is_err());
        assert!(parse_ports("90-80").is_err());
    }

    #[test]
    fn network_text() {
        assert_eq!(network_range_text(Ipv4Addr::new(192, 168, 1, 37), 24), "192.168.1.1-192.168.1.254");
        assert_eq!(network_range_text(Ipv4Addr::new(10, 2, 3, 4), 8), "10.2.3.1-10.2.3.254");
    }
}
