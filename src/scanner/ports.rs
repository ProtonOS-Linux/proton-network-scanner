//! TCP port scanning ("which services does this device offer?").
//!
//! A *connect scan*: we open a normal TCP connection to each port and close it
//! straight away. It needs no special rights and behaves like any app
//! connecting to a server. Optionally we read the first line a service sends
//! on its own (SSH, FTP, SMTP… announce themselves) to show its version.
//!
//! Security: we never *send* anything to the service, the banner read is
//! limited to 256 bytes and a short timeout, and the text is cleaned before it
//! is shown or exported.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// Preset port lists offered in the UI.
pub const PRESET_COMMON: &str = "21,22,23,25,53,80,110,135,139,143,443,445,548,554,631,993,995,1433,1883,3306,3389,5000,5432,5900,8000,8080,8443,9100";
/// Ports the vulnerability scanner checks by default: common services plus
/// databases, remote access, IoT/smart-home and container management ports.
pub const PRESET_VULN: &str = "21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,548,554,587,631,993,995,1433,1521,1723,1883,2049,2375,3000,3306,3389,4443,5000,5001,5432,5900,5901,6379,7547,8000,8008,8080,8081,8088,8443,8888,9000,9100,9200,9443,11211,27017,32400";
/// Comprehensive vulnerability set: every well-known port (1-1024) plus
/// ~400 registered ports where management interfaces, databases, remote
/// access, IoT, industrial and container services usually live.
pub const PRESET_COMPREHENSIVE: &str = "1-1024,1080,1194,1433-1434,1521,1723,1883,1900,2000,2049,2082-2083,2181,2222,2375-2376,2483-2484,3000-3001,3128,3260,3268-3269,3306,3389,3478,3690,4000,4369,4443-4444,4505-4506,4567,4848,5000-5001,5060-5061,5222,5353,5357,5432,5500,5555,5601,5631,5672,5800,5900-5910,5938,5984-5986,6000-6005,6379,6443,6514,6646,6660-6669,6881,7000-7002,7070-7071,7443,7474,7547,7777,8000-8100,8118,8123,8181,8200,8222,8291,8333,8443,8448,8500,8530-8531,8649,8686,8728-8729,8834,8880,8883,8888-8889,9000-9003,9042,9050,9060,9080-9081,9090-9091,9100-9102,9200,9300,9418,9443,9600,9999-10001,10050-10051,10250,10443,11211,15672,16992-16993,17000,18080,20000,25565,27017-27019,28017,32400,32764,37777,44818,47808,49152-49160,50000,50070,54321,55443,62078";
/// Every TCP port.
pub const PRESET_FULL: &str = "1-65535";
pub const PRESET_WEB: &str = "80,81,443,591,3000,5000,8000,8008,8080,8081,8443,8888,9000,9443";
pub const PRESET_WELL_KNOWN: &str = "1-1024";

/// One open port found on a device.
#[derive(Clone, Debug)]
pub struct OpenPort {
    pub port: u16,
    /// Usual service on that port (`"HTTP"`, `"SSH"`…), if well known.
    pub service: &'static str,
    /// First line the service sent by itself, cleaned, if any.
    pub banner: Option<String>,
}

/// Try to connect to `ip:port`. Returns `Some` only if the port is open.
pub fn probe(ip: Ipv4Addr, port: u16, timeout: Duration, grab_banner: bool) -> Option<OpenPort> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let banner = if grab_banner { read_banner(&mut stream) } else { None };
    // The stream is dropped (closed) here.
    Some(OpenPort { port, service: service_name(port), banner })
}

/// Read what a service says on its own within a short time.
fn read_banner(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_millis(700))).ok()?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    clean_banner(&buf[..n])
}

/// Keep the first line, printable ASCII only, at most 80 characters.
fn clean_banner(bytes: &[u8]) -> Option<String> {
    let first_line = bytes.split(|&b| b == b'\n' || b == b'\r').find(|l| !l.is_empty())?;
    let text: String =
        first_line.iter().filter(|b| b.is_ascii_graphic() || **b == b' ').take(80).map(|&b| b as char).collect();
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Well-known service names (IANA registrations plus common real-world use).
pub fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP (mail)",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 | 81 | 591 | 8008 => "HTTP (web)",
        88 => "Kerberos",
        110 | 995 => "POP3 (mail)",
        111 => "RPC portmapper",
        123 => "NTP (time)",
        135 => "Windows RPC",
        137..=139 => "NetBIOS / SMB",
        143 | 993 => "IMAP (mail)",
        161 | 162 => "SNMP",
        389 | 636 => "LDAP",
        443 | 8443 | 9443 => "HTTPS (secure web)",
        445 => "SMB (file sharing)",
        515 | 631 => "Printing (LPD/IPP)",
        548 => "AFP (Apple file sharing)",
        554 => "RTSP (camera stream)",
        873 => "rsync",
        1080 => "SOCKS proxy",
        1433 => "Microsoft SQL Server",
        1521 => "Oracle DB",
        1723 => "PPTP VPN",
        1883 | 8883 => "MQTT (smart home)",
        1900 => "UPnP",
        2049 => "NFS (file sharing)",
        3000 => "Web app (dev)",
        3306 => "MySQL / MariaDB",
        3389 => "Remote Desktop (RDP)",
        5000 | 5001 => "Web admin (NAS)",
        5060 | 5061 => "SIP (VoIP)",
        5353 => "mDNS",
        5432 => "PostgreSQL",
        5900..=5903 => "VNC (remote screen)",
        6379 => "Redis",
        8000 | 8080 | 8081 | 8888 => "HTTP (alt web)",
        9000 => "Web admin",
        9100 => "Printer (raw)",
        27017 => "MongoDB",
        32400 => "Plex",
        62078 => "Apple device sync",
        _ => "",
    }
}

/// Does this port normally serve a web page (so "Open in browser" makes sense)?
pub fn web_scheme(port: u16) -> Option<&'static str> {
    match port {
        443 | 8443 | 9443 | 5001 => Some("https"),
        80 | 81 | 591 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 | 32400 => Some("http"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn finds_open_port_and_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"SSH-2.0-OpenSSH_9.9\x1b[31m\r\nmore").unwrap();
        });
        let open = probe(Ipv4Addr::LOCALHOST, port, Duration::from_secs(1), true).unwrap();
        assert_eq!(open.banner.as_deref(), Some("SSH-2.0-OpenSSH_9.9[31m"));
        t.join().unwrap();
    }

    #[test]
    fn closed_port_is_none() {
        // Bind then drop to get a port that is almost certainly closed.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(probe(Ipv4Addr::LOCALHOST, port, Duration::from_millis(300), false).is_none());
    }

    #[test]
    fn presets_parse() {
        for p in [PRESET_COMMON, PRESET_WEB, PRESET_WELL_KNOWN, PRESET_VULN, PRESET_COMPREHENSIVE, PRESET_FULL] {
            assert!(super::super::range::parse_ports(p).is_ok());
        }
    }
}
