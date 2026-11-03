//! Service detection: what software (and which version) is listening on an
//! open port, plus the safe configuration checks from [`super::checks`].
//!
//! How each port is identified:
//!
//! | Port(s) | Method |
//! |---|---|
//! | web ports (80, 8080, 443, 8443 …) | HTTP(S) `GET /` → `Server` / `X-Powered-By` headers, page content |
//! | 22 / anything starting `SSH-` | SSH greeting (`SSH-2.0-OpenSSH_9.6p1 …`) |
//! | 21, 25, 587, 110, 143 … | greeting line (`220 (vsFTPd 3.0.5)`, `220 … Exim 4.96`) |
//! | 3306 | MySQL/MariaDB handshake packet (version string) |
//! | 6379 | Redis `INFO server` (also tells if a password is required) |
//! | 5900–5903 | VNC version + offered security types |
//! | 11211 | memcached `version` |
//! | 1883 | MQTT CONNECT without credentials (if "safe login checks" is on) |
//! | 2375 | Docker Engine API `GET /version` |
//! | 9200 | Elasticsearch `GET /` |
//! | other | read the greeting; if silent, one neutral probe tells Redis / memcached / HTTP / HTTPS apart |
//!
//! The detected software is turned into a **CPE name** — the identifier NVD
//! uses (e.g. `cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*`) — for the
//! vulnerability lookup.
//!
//! Security: we only read what services send, send fixed well-known probe
//! requests, read at most 64 KiB per response with timeouts, and treat all
//! received text as untrusted (cleaned before display). HTTPS certificates of
//! *scanned devices* are not verified (home devices use self-signed ones) —
//! that HTTP client is separate from the one used for the vulnerability
//! database, which always verifies TLS.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use super::Finding;
use super::checks;
use crate::scanner::ports::service_name;

/// Most bytes read from one response.
const MAX_READ: usize = 64 * 1024;

/// One piece of software found on a port.
#[derive(Clone, Debug, PartialEq)]
pub struct Product {
    /// Display name, e.g. "OpenSSH".
    pub name: String,
    /// Version as announced, e.g. "9.6p1".
    pub version: String,
    /// NVD CPE 2.3 name, when the product is known to NVD.
    pub cpe: Option<String>,
    /// The version comes from a Linux distribution that back-ports fixes.
    pub backported: bool,
}

impl Product {
    /// `vendor`/`product` are NVD's names; `update` is e.g. "p1" for OpenSSH.
    fn new(name: &str, vendor: &str, product: &str, version: &str, update: Option<&str>) -> Product {
        let ok = |s: &str| {
            !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
        };
        let shown = match update {
            Some(u) if !u.is_empty() => format!("{version}{u}"),
            _ => version.to_string(),
        };
        let cpe = (ok(version) && update.is_none_or(|u| u.is_empty() || ok(u))).then(|| {
            let upd = update.filter(|u| !u.is_empty()).unwrap_or("*");
            format!("cpe:2.3:a:{vendor}:{product}:{version}:{upd}:*:*:*:*:*:*")
        });
        Product { name: name.into(), version: clean(&shown, 40), cpe, backported: false }
    }

    pub fn label(&self) -> String {
        if self.version.is_empty() { self.name.clone() } else { format!("{} {}", self.name, self.version) }
    }
}

/// What was found on one open port.
#[derive(Clone, Debug)]
pub struct Service {
    pub ip: Ipv4Addr,
    pub port: u16,
    /// Protocol / service label, e.g. "SSH", "HTTPS (secure web)".
    pub name: String,
    pub products: Vec<Product>,
    /// First line the service sent, or the web server header (cleaned).
    pub banner: Option<String>,
}

/// Shared settings for probing.
pub struct ProbeCtx {
    pub timeout: Duration,
    /// Try anonymous FTP / MQTT access.
    pub safe_logins: bool,
    /// HTTP client for scanned devices (TLS verification off, no proxy, no redirects).
    http: ureq::Agent,
}

impl ProbeCtx {
    pub fn new(timeout: Duration, safe_logins: bool) -> ProbeCtx {
        let tls = ureq::tls::TlsConfig::builder().disable_verification(true).build();
        let http: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .proxy(None) // talk to the device directly, never through a proxy
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_connect(Some(timeout * 2))
            .timeout_global(Some(timeout * 6))
            .user_agent("Mozilla/5.0 (compatible; ProtonIPScanner)")
            .build()
            .into();
        ProbeCtx { timeout, safe_logins, http }
    }
}

const HTTPS_PORTS: [u16; 7] = [443, 4443, 5001, 8443, 9443, 10443, 7443];
const HTTP_PORTS: [u16; 17] =
    [80, 81, 591, 2375, 3000, 5000, 7547, 8000, 8008, 8080, 8081, 8088, 8090, 8888, 9000, 9200, 32400];

/// Identify the service on `ip:port` and run the checks that apply to it.
pub fn probe(ip: Ipv4Addr, port: u16, ctx: &ProbeCtx) -> (Service, Vec<Finding>) {
    let mut svc = Service { ip, port, name: label_for(port), products: Vec::new(), banner: None };
    let mut findings = Vec::new();

    match port {
        p if HTTPS_PORTS.contains(&p) => http_probe(&mut svc, &mut findings, ctx, "https"),
        p if HTTP_PORTS.contains(&p) => http_probe(&mut svc, &mut findings, ctx, "http"),
        3306 => mysql_probe(&mut svc, &mut findings, ctx),
        6379 => redis_probe(&mut svc, &mut findings, ctx),
        5900..=5903 => vnc_probe(&mut svc, &mut findings, ctx),
        11211 => memcached_probe(&mut svc, &mut findings, ctx),
        1883 => mqtt_probe(&mut svc, &mut findings, ctx),
        21 => ftp_probe(&mut svc, &mut findings, ctx),
        23 => {
            svc.name = "Telnet".into();
            findings.push(checks::TELNET.finding(ip, port, "Telnet", "Port 23 accepts Telnet connections."));
        }
        3389 => findings.push(checks::RDP_EXPOSED.finding(ip, port, &svc.name, "Port 3389 is open.")),
        445 | 139 => findings.push(checks::SMB_EXPOSED.finding(ip, port, &svc.name, format!("Port {port} is open."))),
        _ => generic_probe(&mut svc, &mut findings, ctx),
    }

    // One informational finding listing the detected software versions.
    let versions: Vec<String> = svc.products.iter().filter(|p| !p.version.is_empty()).map(Product::label).collect();
    if !versions.is_empty() {
        let mut f = checks::VERSION_DISCLOSED.finding(ip, port, &svc.name, versions.join(", "));
        f.product = Some(versions.join(", "));
        findings.push(f);
    }
    (svc, findings)
}

fn label_for(port: u16) -> String {
    let s = service_name(port);
    if s.is_empty() { format!("TCP {port}") } else { s.to_string() }
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// Unknown port: read a greeting; recognise SSH / FTP / SMTP; else try HTTP.
fn generic_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let banner = connect(svc.ip, svc.port, ctx.timeout).and_then(|mut s| read_line(&mut s, ctx.timeout));
    match banner {
        Some(b) if b.starts_with("SSH-") => {
            svc.name = "SSH".into();
            svc.products.extend(parse_ssh_banner(&b));
            svc.banner = Some(b);
        }
        Some(b) if b.starts_with("220") => {
            let l = b.to_ascii_lowercase();
            if !l.contains("smtp") && (l.contains("ftp") || parse_ftp_banner(&b).is_some()) {
                // FTP on an unusual port: run the full FTP checks (fresh connection).
                ftp_probe(svc, findings, ctx);
            } else {
                svc.name = if l.contains("smtp") { "SMTP (mail)".into() } else { svc.name.clone() };
                svc.products.extend(parse_smtp_banner(&b));
                svc.banner = Some(b);
            }
        }
        Some(b) => svc.banner = Some(b),
        None => {
            // Silent service: one neutral probe tells the common silent
            // protocols apart. "INFO server" is a read-only Redis command;
            // other servers just answer with an error.
            let reply = connect(svc.ip, svc.port, ctx.timeout)
                .map(|mut s| {
                    let _ = s.write_all(b"INFO server\r\n");
                    read_some(&mut s, 4096, ctx.timeout)
                })
                .unwrap_or_default();
            let text = String::from_utf8_lossy(&reply);
            if text.contains("redis_version:") || text.starts_with("-NOAUTH") || text.starts_with("-DENIED") {
                redis_probe(svc, findings, ctx);
            } else if text.starts_with("ERROR") {
                memcached_probe(svc, findings, ctx);
            } else if reply.starts_with(&[0x15, 0x03]) {
                // A TLS alert: the service speaks TLS, most likely HTTPS.
                http_probe(svc, findings, ctx, "https");
            } else if text.starts_with("HTTP/") || reply.is_empty() {
                http_probe(svc, findings, ctx, "http");
            }
        }
    }
}

fn http_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx, scheme: &str) {
    let (ip, port) = (svc.ip, svc.port);
    let path = if port == 2375 { "/version" } else { "/" };
    let Some(resp) = http_get(ctx, scheme, ip, port, path) else { return };
    if scheme == "https" && !svc.name.contains("HTTPS") {
        svc.name = "HTTPS".into();
    } else if scheme == "http" && svc.name.starts_with("TCP ") {
        svc.name = "HTTP".into();
    }
    if let Some(server) = &resp.server {
        svc.banner = Some(format!("Server: {server}"));
        svc.products.extend(parse_server_header(server));
    }
    if let Some(p) = &resp.powered_by {
        svc.products.extend(parse_server_header(p));
    }

    // Docker Engine API (no TLS, no auth).
    if port == 2375 && resp.body.contains("\"ApiVersion\"") {
        svc.name = "Docker Engine API".into();
        if let Some(v) = json_str(&resp.body, &["Version"]) {
            svc.products.push(Product::new("Docker Engine", "mobyproject", "moby", &v, None));
        }
        findings.push(checks::DOCKER_API.finding(ip, port, &svc.name, "GET /version answered without authentication."));
    }
    // Elasticsearch.
    if resp.body.contains("You Know, for Search") {
        svc.name = "Elasticsearch".into();
        if let Some(v) = json_str(&resp.body, &["version", "number"]) {
            svc.products.push(Product::new("Elasticsearch", "elastic", "elasticsearch", &v, None));
        }
        if resp.status == 200 {
            findings.push(checks::ELASTIC_NOAUTH.finding(
                ip,
                port,
                &svc.name,
                "GET / returned cluster information without credentials.",
            ));
        }
    }
    // Password field on a page served without TLS.
    let body = resp.body.to_ascii_lowercase();
    if scheme == "http"
        && (body.contains("type=\"password\"") || body.contains("type='password'") || body.contains("type=password"))
    {
        findings.push(checks::HTTP_CLEARTEXT_LOGIN.finding(
            ip,
            port,
            &svc.name,
            format!("http://{ip}:{port}/ contains a password input field."),
        ));
    }
}

struct HttpResp {
    status: u16,
    server: Option<String>,
    powered_by: Option<String>,
    body: String,
}

fn http_get(ctx: &ProbeCtx, scheme: &str, ip: Ipv4Addr, port: u16, path: &str) -> Option<HttpResp> {
    // The URL is built only from a parsed address, a constant scheme/path and a number.
    let url = format!("{scheme}://{ip}:{port}{path}");
    let mut resp = ctx.http.get(&url).call().ok()?;
    let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(|s| clean(s, 120));
    let (server, powered_by) = (header("server"), header("x-powered-by"));
    let mut raw = Vec::new();
    let _ = resp.body_mut().as_reader().take(MAX_READ as u64).read_to_end(&mut raw);
    Some(HttpResp {
        status: resp.status().as_u16(),
        server,
        powered_by,
        body: String::from_utf8_lossy(&raw).into_owned(),
    })
}

fn mysql_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    let pkt = read_some(&mut s, 512, ctx.timeout);
    // Packet: 3-byte length, 1-byte sequence, then protocol version 10 and a
    // NUL-terminated server version string. 0xFF = error packet (e.g. "host
    // not allowed"), which still proves it is MySQL/MariaDB.
    match pkt.get(4) {
        Some(10) => {
            let ver: String = pkt.iter().skip(5).take_while(|&&b| b != 0).take(60).map(|&b| b as char).collect();
            svc.name = "MySQL / MariaDB".into();
            svc.banner = Some(clean(&ver, 60));
            svc.products.extend(parse_mysql_version(&ver));
            findings.push(checks::DATABASE_EXPOSED.finding(
                svc.ip,
                svc.port,
                &svc.name,
                format!("Server version {}", clean(&ver, 60)),
            ));
        }
        Some(0xFF) => svc.name = "MySQL / MariaDB (refuses this host)".into(),
        _ => {}
    }
}

fn redis_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    if s.write_all(b"INFO server\r\n").is_err() {
        return;
    }
    let reply = String::from_utf8_lossy(&read_some(&mut s, 8192, ctx.timeout)).into_owned();
    if reply.contains("redis_version:") {
        svc.name = "Redis".into();
        if let Some(v) = reply.lines().find_map(|l| l.strip_prefix("redis_version:")) {
            svc.products.push(Product::new("Redis", "redis", "redis", v.trim(), None));
        }
        findings.push(checks::REDIS_NOAUTH.finding(
            svc.ip,
            svc.port,
            "Redis",
            "INFO command answered without a password.",
        ));
    } else if reply.starts_with("-NOAUTH") || reply.contains("Authentication required") {
        svc.name = "Redis (password required)".into();
        svc.products.push(Product { name: "Redis".into(), version: String::new(), cpe: None, backported: false });
    }
}

fn vnc_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    let hello = read_some(&mut s, 12, ctx.timeout);
    let Some(ver) = std::str::from_utf8(&hello).ok().filter(|v| v.starts_with("RFB ")) else { return };
    svc.name = "VNC".into();
    svc.banner = Some(clean(ver, 20));
    let minor: u32 = ver.get(8..11).and_then(|m| m.parse().ok()).unwrap_or(3);
    // Answer with the same protocol version (3.3, 3.7 or 3.8).
    let ours: &[u8] = if minor >= 8 {
        b"RFB 003.008\n"
    } else if minor == 7 {
        b"RFB 003.007\n"
    } else {
        b"RFB 003.003\n"
    };
    if s.write_all(ours).is_err() {
        return;
    }
    let reply = read_some(&mut s, 64, ctx.timeout);
    // 3.3: a 4-byte security type chosen by the server. 3.7+: a count and a list.
    let no_auth = if minor < 7 {
        reply.get(0..4) == Some(&[0, 0, 0, 1])
    } else {
        let n = *reply.first().unwrap_or(&0) as usize;
        reply.iter().skip(1).take(n).any(|&t| t == 1)
    };
    if no_auth {
        findings.push(checks::VNC_NOAUTH.finding(svc.ip, svc.port, "VNC", "Server offers security type 1 (None)."));
    }
}

fn memcached_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    if s.write_all(b"version\r\n").is_err() {
        return;
    }
    let reply = String::from_utf8_lossy(&read_some(&mut s, 256, ctx.timeout)).into_owned();
    if let Some(v) = reply.strip_prefix("VERSION ") {
        svc.name = "memcached".into();
        svc.products.push(Product::new("memcached", "memcached", "memcached", v.trim(), None));
        findings.push(checks::MEMCACHED_NOAUTH.finding(
            svc.ip,
            svc.port,
            "memcached",
            "'version' answered without authentication.",
        ));
    }
}

fn mqtt_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    if !ctx.safe_logins {
        return;
    }
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    // CONNECT, MQTT 3.1.1, clean session, keep-alive 60 s, client id "proton-scan", no credentials.
    const CONNECT: [u8; 25] = [
        0x10, 23, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 11, b'p', b'r', b'o', b't', b'o', b'n', b'-', b's',
        b'c', b'a', b'n',
    ];
    if s.write_all(&CONNECT).is_err() {
        return;
    }
    let ack = read_some(&mut s, 4, ctx.timeout);
    if ack.first() == Some(&0x20) {
        svc.name = "MQTT".into();
        if ack.get(3) == Some(&0) {
            findings.push(checks::MQTT_ANONYMOUS.finding(
                svc.ip,
                svc.port,
                "MQTT",
                "CONNECT without credentials was accepted (CONNACK 0).",
            ));
        }
        let _ = s.write_all(&[0xE0, 0]); // DISCONNECT
    }
}

fn ftp_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    let Some(greeting) = ftp_reply(&mut s, ctx.timeout) else { return };
    if !greeting.starts_with("220") {
        return;
    }
    svc.name = "FTP".into();
    svc.banner = Some(greeting.clone());
    svc.products.extend(parse_ftp_banner(&greeting));
    findings.push(checks::FTP_CLEARTEXT.finding(svc.ip, svc.port, "FTP", greeting.clone()));

    if ctx.safe_logins {
        // Documented anonymous access only; we log out immediately.
        let _ = s.write_all(b"USER anonymous\r\n");
        let mut reply = ftp_reply(&mut s, ctx.timeout).unwrap_or_default();
        if reply.starts_with("331") {
            let _ = s.write_all(b"PASS proton-scan@example.com\r\n");
            reply = ftp_reply(&mut s, ctx.timeout).unwrap_or_default();
        }
        if reply.starts_with("230") {
            findings.push(checks::FTP_ANONYMOUS.finding(
                svc.ip,
                svc.port,
                "FTP",
                format!("Login as 'anonymous' accepted: {reply}"),
            ));
        }
        let _ = s.write_all(b"QUIT\r\n");
    }
}

// ---------------------------------------------------------------------------
// Banner parsers (pure functions, unit-tested)
// ---------------------------------------------------------------------------

/// `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` → OpenSSH 9.6p1.
pub fn parse_ssh_banner(b: &str) -> Option<Product> {
    let software = b.splitn(3, '-').nth(2)?; // "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    let distro = is_distro_build(software);
    let first = software.split_whitespace().next()?;
    let mut p = if let Some(v) = first.strip_prefix("OpenSSH_") {
        // "9.6p1" → version 9.6, update p1 (NVD's convention).
        let (ver, upd) = match v.find('p') {
            Some(i) => (&v[..i], Some(&v[i..])),
            None => (v, None),
        };
        Product::new("OpenSSH", "openbsd", "openssh", ver, upd)
    } else {
        let v = first.strip_prefix("dropbear_")?;
        Product::new("Dropbear SSH", "dropbear_ssh_project", "dropbear_ssh", v, None)
    };
    p.backported = distro;
    Some(p)
}

/// `Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13` → [Apache httpd 2.4.58, OpenSSL 3.0.13].
pub fn parse_server_header(h: &str) -> Vec<Product> {
    let distro = is_distro_build(h);
    let mut out = Vec::new();
    for token in h.split_whitespace() {
        // "Name/version" or "Jetty(9.4.53.v20231009)"
        let (name, ver) = match token.split_once('/') {
            Some((n, v)) => (n, v),
            None => match token.split_once('(') {
                Some((n, v)) => (n, v.trim_end_matches(')')),
                None => continue,
            },
        };
        let ver = ver.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let p = match name.to_ascii_lowercase().as_str() {
            "apache" => Product::new("Apache httpd", "apache", "http_server", ver, None),
            "nginx" => Product::new("nginx", "f5", "nginx", ver, None),
            "lighttpd" => Product::new("lighttpd", "lighttpd", "lighttpd", ver, None),
            "microsoft-iis" => Product::new("Microsoft IIS", "microsoft", "internet_information_services", ver, None),
            "openssl" => {
                // "1.1.1f" → version 1.1.1, update f (NVD's convention for old OpenSSL).
                let split = ver.find(|c: char| c.is_ascii_alphabetic());
                match split {
                    Some(i) if ver.starts_with("1.") => {
                        Product::new("OpenSSL", "openssl", "openssl", &ver[..i], Some(&ver[i..]))
                    }
                    _ => Product::new("OpenSSL", "openssl", "openssl", ver, None),
                }
            }
            "php" => Product::new("PHP", "php", "php", ver.split('-').next().unwrap_or(ver), None),
            "miniserv" => Product::new("Webmin", "webmin", "webmin", ver, None),
            "jetty" => {
                Product::new("Jetty", "eclipse", "jetty", &ver.split('.').take(3).collect::<Vec<_>>().join("."), None)
            }
            "openresty" => Product::new("OpenResty", "openresty", "openresty", ver, None),
            "gunicorn" => Product::new("Gunicorn", "gunicorn", "gunicorn", ver, None),
            "werkzeug" => Product::new("Werkzeug", "palletsprojects", "werkzeug", ver, None),
            _ => continue,
        };
        out.push(Product { backported: distro, ..p });
    }
    out
}

/// FTP greetings: vsftpd, ProFTPD, FileZilla Server.
pub fn parse_ftp_banner(b: &str) -> Option<Product> {
    // Drop the reply code: "220 " or "220-" (multi-line reply).
    let b = match b.as_bytes() {
        [a, b2, c, b'-' | b' ', ..] if [a, b2, c].iter().all(|x| x.is_ascii_digit()) => &b[4..],
        _ => b,
    };
    let words: Vec<&str> =
        b.split(|c: char| c.is_whitespace() || c == '(' || c == ')').filter(|w| !w.is_empty()).collect();
    for (i, w) in words.iter().enumerate() {
        let next = words.get(i + 1).copied().unwrap_or("");
        match w.to_ascii_lowercase().as_str() {
            "vsftpd" => return Some(Product::new("vsftpd", "beasts", "vsftpd", next, None)),
            "proftpd" => {
                // "1.3.5e" → 1.3.5 + update e
                let split = next.find(|c: char| c.is_ascii_alphabetic());
                let (v, u) = match split {
                    Some(i) => (&next[..i], Some(&next[i..])),
                    None => (next, None),
                };
                return Some(Product::new("ProFTPD", "proftpd", "proftpd", v, u));
            }
            "filezilla" if words.get(i + 1) == Some(&"Server") => {
                let v = words.get(i + 2).copied().unwrap_or("");
                return Some(Product::new("FileZilla Server", "filezilla-project", "filezilla_server", v, None));
            }
            _ => {}
        }
    }
    None
}

/// SMTP greetings: Exim and Sendmail announce versions.
pub fn parse_smtp_banner(b: &str) -> Option<Product> {
    let words: Vec<&str> = b.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        let next = words.get(i + 1).map(|v| v.trim_end_matches([';', ',', '/'])).unwrap_or("");
        match *w {
            "Exim" => return Some(Product::new("Exim", "exim", "exim", next, None)),
            "Sendmail" => {
                return Some(Product::new(
                    "Sendmail",
                    "sendmail",
                    "sendmail",
                    next.split('/').next().unwrap_or(next),
                    None,
                ));
            }
            _ => {}
        }
    }
    None
}

/// `5.7.44-log` → MySQL 5.7.44; `5.5.5-10.11.6-MariaDB-0+deb12u1` → MariaDB 10.11.6.
pub fn parse_mysql_version(v: &str) -> Option<Product> {
    if v.contains("MariaDB") {
        let parts: Vec<&str> = v.split('-').collect();
        // Newer MariaDB prefixes "5.5.5-" for old clients.
        let ver = if parts.first() == Some(&"5.5.5") { parts.get(1)? } else { parts.first()? };
        let mut p = Product::new("MariaDB", "mariadb", "mariadb", ver, None);
        p.backported = is_distro_build(v);
        Some(p)
    } else {
        let ver = v.split('-').next()?;
        let mut p = Product::new("MySQL", "oracle", "mysql", ver, None);
        p.backported = is_distro_build(v);
        Some(p)
    }
}

/// Distribution packages keep the upstream version number but receive
/// security fixes, so version-based matches may be false positives.
fn is_distro_build(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["ubuntu", "debian", "deb1", "raspbian", "red hat", "centos", "fedora", "el7", "el8", "el9", "suse"]
        .iter()
        .any(|d| l.contains(d))
}

// ---------------------------------------------------------------------------
// Small socket helpers
// ---------------------------------------------------------------------------

fn connect(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let s = TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(ip, port)), timeout).ok()?;
    s.set_read_timeout(Some(timeout * 2)).ok()?;
    s.set_write_timeout(Some(timeout * 2)).ok()?;
    Some(s)
}

/// Read up to `max` bytes, waiting at most about `timeout × 2` in total.
fn read_some(s: &mut TcpStream, max: usize, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout * 2;
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while out.len() < max && Instant::now() < deadline {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n.min(max - out.len())]);
                // Most probes get their whole answer in one packet.
                if n < buf.len() {
                    break;
                }
            }
        }
    }
    out
}

/// First non-empty line the service sends by itself.
fn read_line(s: &mut TcpStream, timeout: Duration) -> Option<String> {
    let data = read_some(s, 1024, timeout);
    let line = data.split(|&b| b == b'\n' || b == b'\r').find(|l| !l.is_empty())?;
    let text = clean(&String::from_utf8_lossy(line), 160);
    (!text.is_empty()).then_some(text)
}

/// Read an FTP reply, including multi-line replies ("220-…" … "220 …").
fn ftp_reply(s: &mut TcpStream, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout * 3;
    let mut text = String::new();
    while Instant::now() < deadline && text.len() < 4096 {
        let chunk = read_some(s, 1024, timeout);
        if chunk.is_empty() {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&chunk));
        // Finished when the last line is "ddd text" (code followed by a space).
        if let Some(last) = text.lines().last()
            && last.len() >= 4
            && last.as_bytes()[..3].iter().all(u8::is_ascii_digit)
            && last.as_bytes()[3] == b' '
        {
            break;
        }
    }
    let joined = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
    (!joined.is_empty()).then(|| clean(&joined, 200))
}

/// Read a string at a JSON path, e.g. `["version", "number"]`.
fn json_str(body: &str, path: &[&str]) -> Option<String> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut cur = &root;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(|s| clean(s, 40))
}

/// Remove control characters and cap the length (text from the network is
/// untrusted).
pub fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh() {
        let p = parse_ssh_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5").unwrap();
        assert_eq!(p.label(), "OpenSSH 9.6p1");
        assert_eq!(p.cpe.as_deref(), Some("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"));
        assert!(p.backported);
        let d = parse_ssh_banner("SSH-2.0-dropbear_2022.83").unwrap();
        assert_eq!(d.cpe.as_deref(), Some("cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.83:*:*:*:*:*:*:*"));
        assert!(!d.backported);
        assert!(parse_ssh_banner("SSH-2.0-Cisco-1.25").is_none());
    }

    #[test]
    fn server_headers() {
        let v = parse_server_header("Apache/2.4.58 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3-4ubuntu2");
        let labels: Vec<_> = v.iter().map(Product::label).collect();
        assert_eq!(labels, ["Apache httpd 2.4.58", "OpenSSL 1.1.1f", "PHP 7.4.3"]);
        assert_eq!(v[1].cpe.as_deref(), Some("cpe:2.3:a:openssl:openssl:1.1.1:f:*:*:*:*:*:*"));
        assert!(v[0].backported);
        assert_eq!(
            parse_server_header("nginx/1.24.0")[0].cpe.as_deref(),
            Some("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
        );
        assert!(parse_server_header("nginx").is_empty());
        assert_eq!(parse_server_header("Jetty(9.4.53.v20231009)")[0].version, "9.4.53");
        assert_eq!(parse_server_header("MiniServ/2.105")[0].name, "Webmin");
    }

    #[test]
    fn hostile_versions_get_no_cpe() {
        let v = parse_server_header("Apache/2.4:*:evil&x=1");
        assert!(v.iter().all(|p| p.cpe.is_none()));
        let long = format!("Apache/{}", "9".repeat(100));
        assert!(parse_server_header(&long)[0].cpe.is_none());
    }

    #[test]
    fn ftp_smtp_mysql() {
        assert_eq!(parse_ftp_banner("220 (vsFTPd 3.0.5)").unwrap().label(), "vsftpd 3.0.5");
        let p = parse_ftp_banner("220 ProFTPD 1.3.5e Server (Debian)").unwrap();
        assert_eq!(p.cpe.as_deref(), Some("cpe:2.3:a:proftpd:proftpd:1.3.5:e:*:*:*:*:*:*"));
        assert_eq!(parse_ftp_banner("220-FileZilla Server 0.9.60 beta").unwrap().version, "0.9.60");
        assert_eq!(
            parse_smtp_banner("220 mail.example.com ESMTP Exim 4.96 Mon, 2 Nov 2026").unwrap().label(),
            "Exim 4.96"
        );
        assert_eq!(parse_mysql_version("5.5.5-10.11.6-MariaDB-0+deb12u1").unwrap().label(), "MariaDB 10.11.6");
        assert_eq!(
            parse_mysql_version("8.0.36").unwrap().cpe.as_deref(),
            Some("cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn json_paths_and_clean() {
        assert_eq!(json_str(r#"{"version":{"number":"7.10.2"}}"#, &["version", "number"]).as_deref(), Some("7.10.2"));
        assert_eq!(json_str("not json", &["x"]), None);
        assert_eq!(clean("a\u{1b}[31mb\r\n", 10), "a[31mb");
    }

    /// End-to-end: a fake FTP server that allows anonymous login.
    #[test]
    fn ftp_anonymous_detected() {
        use std::io::BufRead;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"220 (vsFTPd 3.0.3)\r\n").unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            s.write_all(b"331 Please specify the password.\r\n").unwrap();
            line.clear();
            r.read_line(&mut line).unwrap();
            s.write_all(b"230 Login successful.\r\n").unwrap();
        });
        let ctx = ProbeCtx::new(Duration::from_millis(500), true);
        let mut svc = Service { ip: Ipv4Addr::LOCALHOST, port, name: String::new(), products: vec![], banner: None };
        let mut f = Vec::new();
        ftp_probe(&mut svc, &mut f, &ctx);
        t.join().unwrap();
        assert_eq!(svc.products[0].label(), "vsftpd 3.0.3");
        assert!(f.iter().any(|x| x.id == "PIS-0002"));
        assert!(f.iter().any(|x| x.id == "PIS-0013"));
    }

    /// End-to-end: a fake Redis without a password.
    #[test]
    fn redis_noauth_detected() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 64];
            let _ = s.read(&mut b);
            s.write_all(b"$60\r\n# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\n\r\n").unwrap();
        });
        let ctx = ProbeCtx::new(Duration::from_millis(500), true);
        let mut svc = Service { ip: Ipv4Addr::LOCALHOST, port, name: String::new(), products: vec![], banner: None };
        let mut f = Vec::new();
        redis_probe(&mut svc, &mut f, &ctx);
        t.join().unwrap();
        assert_eq!(svc.products[0].cpe.as_deref(), Some("cpe:2.3:a:redis:redis:6.0.16:*:*:*:*:*:*:*"));
        assert_eq!(f[0].id, "PIS-0003");
    }

    /// End-to-end: an HTTP device with a cleartext login form.
    #[test]
    fn http_login_and_server_header() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b);
            let body = "<form><input type=\"password\" name=pw></form>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.59\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        });
        let ctx = ProbeCtx::new(Duration::from_millis(500), true);
        let mut svc = Service { ip: Ipv4Addr::LOCALHOST, port, name: "TCP".into(), products: vec![], banner: None };
        let mut f = Vec::new();
        http_probe(&mut svc, &mut f, &ctx, "http");
        t.join().unwrap();
        assert_eq!(svc.products[0].label(), "lighttpd 1.4.59");
        assert!(f.iter().any(|x| x.id == "PIS-0009"));
    }
}
