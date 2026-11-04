//! Parsing of Nmap's XML output (`-oX -`).
//!
//! Nmap writes one `<host>…</host>` block per scanned address as soon as
//! that address is finished, plus `<taskprogress …/>` lines (because we ask
//! for `--stats-every`). [`Stream`] collects the lines of one block and hands
//! the complete block to [`parse_host`], so results appear while the scan is
//! still running and memory stays bounded (one host at a time).
//!
//! Everything Nmap reports about a device (product names, script output,
//! certificate fields …) originally came from that device, so it is
//! **untrusted**: every string is cleaned of control characters and capped
//! in length, numbers are range-checked, CVE ids must have the CVE format and
//! links must be `http(s)://`. The XML parser (`roxmltree`) builds an
//! in-memory tree only, never loads external entities, and is given a node
//! limit.

use std::net::Ipv4Addr;

/// Largest `<host>` block we accept (a host with many scripts is ~100 KB).
pub const MAX_HOST_XML: usize = 8 * 1024 * 1024;
/// Most script results kept per port / per host.
const MAX_SCRIPTS: usize = 64;
/// Most open ports kept per host.
const MAX_PORTS: usize = 65_536;

/// One scanned device, as reported by Nmap.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NmapHost {
    pub ip: Option<Ipv4Addr>,
    /// `AA:BB:CC:DD:EE:FF` (only when Nmap ran with admin rights on the LAN).
    pub mac: Option<String>,
    pub mac_vendor: Option<String>,
    pub hostname: Option<String>,
    /// Best operating-system guess (deep scan only).
    pub os: Option<OsGuess>,
    /// Open TCP ports.
    pub ports: Vec<NmapPort>,
    /// Host-level script results (e.g. SMB security mode).
    pub scripts: Vec<Script>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OsGuess {
    pub name: String,
    /// Nmap's confidence, 0–100 %.
    pub accuracy: u8,
    /// "general purpose", "router", "printer", "phone" …
    pub device_type: Option<String>,
}

impl OsGuess {
    pub fn label(&self) -> String {
        match &self.device_type {
            Some(t) => format!("{} ({}%, {t})", self.name, self.accuracy),
            None => format!("{} ({}%)", self.name, self.accuracy),
        }
    }
}

/// One open TCP port.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NmapPort {
    pub port: u16,
    /// Nmap's service name: "ssh", "http", "microsoft-ds" …
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    /// Operating system the service reported ("Linux", "Windows").
    pub ostype: Option<String>,
    /// The service runs inside TLS/SSL.
    pub tls: bool,
    /// CPE 2.2 names as Nmap reported them, validated (`cpe:/a:vendor:product[:version]`).
    pub cpes: Vec<String>,
    pub scripts: Vec<Script>,
}

impl NmapPort {
    /// "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)".
    pub fn description(&self) -> Option<String> {
        let mut s = String::new();
        for part in [&self.product, &self.version].into_iter().flatten() {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(part);
        }
        if let Some(e) = &self.extrainfo {
            if s.is_empty() {
                s.push_str(e);
            } else {
                s.push_str(&format!(" ({e})"));
            }
        }
        (!s.is_empty()).then_some(s)
    }
}

/// The result of one NSE script.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Script {
    /// Script name, e.g. "ssl-cert" (letters, digits, `-`, `_` only).
    pub id: String,
    /// Human-readable output (newlines kept, other control characters removed).
    pub output: String,
    /// Vulnerabilities in the standard NSE `vulns` format.
    pub vulns: Vec<ScriptVuln>,
    /// Structured values flattened to `key.path = value`, e.g.
    /// `validity.notAfter = 2021-01-01T00:00:00`.
    pub elems: Vec<(String, String)>,
}

impl Script {
    /// First structured value whose key path is `path`.
    pub fn elem(&self, path: &str) -> Option<&str> {
        self.elems.iter().find(|(k, _)| k == path).map(|(_, v)| v.as_str())
    }

    /// The script failed or timed out (Nmap reports this as output text).
    pub fn failed(&self) -> bool {
        self.output.starts_with("ERROR:") || self.output.contains("Script execution failed")
    }
}

/// One vulnerability reported by an NSE script (NSE `vulns` library format).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScriptVuln {
    pub title: String,
    /// "VULNERABLE", "LIKELY VULNERABLE", "VULNERABLE (Exploitable)" …
    pub state: String,
    /// CVE ids (validated).
    pub cves: Vec<String>,
    pub description: String,
    /// "HIGH", "MEDIUM", "LOW" when the script states one.
    pub risk: Option<String>,
    pub disclosure: Option<String>,
    /// `http(s)://` links only.
    pub refs: Vec<String>,
}

impl ScriptVuln {
    /// The script says the device *is* (or likely is) vulnerable.
    pub fn positive(&self) -> bool {
        let s = self.state.to_ascii_uppercase();
        s.contains("VULNERABLE") && !s.contains("NOT VULNERABLE")
    }
}

/// What a line of Nmap output was, for [`Stream::push_line`].
#[derive(Debug, PartialEq)]
pub enum Item {
    /// A complete `<host>` block (up hosts only).
    Host(Box<NmapHost>),
    /// `<taskprogress>`: task name and percent.
    Progress(String, f32),
    /// `<finished>`: Nmap's exit status ("success" / "error") and error message.
    Finished(String, Option<String>),
    /// A host block was too large or not valid XML and was skipped.
    Skipped,
}

/// Incremental reader for Nmap's XML output, fed line by line.
#[derive(Default)]
pub struct Stream {
    /// Lines of the `<host>` block being collected.
    block: Option<String>,
    too_big: bool,
}

impl Stream {
    /// Feed one line (without the newline). Returns what it completed, if anything.
    pub fn push_line(&mut self, line: &str) -> Option<Item> {
        let t = line.trim_start();
        if let Some(block) = &mut self.block {
            if !self.too_big {
                if block.len() + line.len() + 1 > MAX_HOST_XML {
                    self.too_big = true;
                    block.clear();
                } else {
                    block.push('\n');
                    block.push_str(line);
                }
            }
            // A host block ends with `</host>` (possibly after other content).
            if t.trim_end().ends_with("</host>") {
                let block = self.block.take().unwrap_or_default();
                if std::mem::take(&mut self.too_big) {
                    return Some(Item::Skipped);
                }
                return match parse_host(&block) {
                    Ok(Some(h)) => Some(Item::Host(Box::new(h))),
                    Ok(None) => None, // host down
                    Err(_) => Some(Item::Skipped),
                };
            }
            return None;
        }
        if t.starts_with("<host ") || t.starts_with("<host>") {
            if t.trim_end().ends_with("</host>") {
                return match parse_host(t) {
                    Ok(Some(h)) => Some(Item::Host(Box::new(h))),
                    Ok(None) => None,
                    Err(_) => Some(Item::Skipped),
                };
            }
            if line.len() > MAX_HOST_XML {
                self.too_big = true;
                self.block = Some(String::new());
            } else {
                self.block = Some(line.to_string());
            }
            return None;
        }
        if t.starts_with("<taskprogress ") {
            return parse_progress(t);
        }
        if let Some(i) = t.find("<finished ") {
            return parse_finished(&t[i..]);
        }
        None
    }
}

fn options<'a>() -> roxmltree::ParsingOptions<'a> {
    roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 2_000_000, ..Default::default() }
}

/// `<taskprogress task="Service scan" percent="50.00" …/>`.
fn parse_progress(line: &str) -> Option<Item> {
    let doc = roxmltree::Document::parse_with_options(line.trim(), options()).ok()?;
    let n = doc.root_element();
    let task = clean(n.attribute("task")?, 40);
    let pct: f32 = n.attribute("percent")?.parse().ok()?;
    pct.is_finite().then(|| Item::Progress(task, pct.clamp(0.0, 100.0)))
}

/// `<finished … exit="error" errormsg="…"/>`, possibly followed by more XML on the line.
fn parse_finished(s: &str) -> Option<Item> {
    let end = s.find("/>")? + 2;
    let doc = roxmltree::Document::parse_with_options(&s[..end], options()).ok()?;
    let n = doc.root_element();
    Some(Item::Finished(clean(n.attribute("exit").unwrap_or(""), 20), n.attribute("errormsg").map(|e| clean(e, 300))))
}

/// Parse one `<host>` block. `Ok(None)` = the host is down / has no IPv4 address.
pub fn parse_host(xml: &str) -> Result<Option<NmapHost>, String> {
    let doc = roxmltree::Document::parse_with_options(xml, options()).map_err(|e| e.to_string())?;
    let host = doc.root_element();
    if !host.has_tag_name("host") {
        return Err("not a host element".into());
    }
    let up = host
        .children()
        .find(|n| n.has_tag_name("status"))
        .and_then(|s| s.attribute("state"))
        .is_some_and(|s| s == "up");
    if !up {
        return Ok(None);
    }
    let mut h = NmapHost::default();
    for n in host.children().filter(|n| n.is_element()) {
        match n.tag_name().name() {
            "address" => match n.attribute("addrtype") {
                Some("ipv4") => h.ip = n.attribute("addr").and_then(|a| a.parse().ok()),
                Some("mac") => {
                    h.mac = n.attribute("addr").filter(|a| is_mac(a)).map(|a| a.to_ascii_uppercase());
                    h.mac_vendor = n.attribute("vendor").map(|v| clean(v, 64)).filter(|v| !v.is_empty());
                }
                _ => {}
            },
            "hostnames" => {
                h.hostname = n
                    .children()
                    .filter(|c| c.has_tag_name("hostname"))
                    .filter_map(|c| c.attribute("name"))
                    .map(crate::scanner::names::sanitize)
                    .find(|s| !s.is_empty());
            }
            "ports" => {
                for p in n.children().filter(|c| c.has_tag_name("port")) {
                    if h.ports.len() >= MAX_PORTS {
                        break;
                    }
                    if let Some(port) = parse_port(p) {
                        h.ports.push(port);
                    }
                }
            }
            "os" => h.os = parse_os(n),
            "hostscript" => h.scripts = parse_scripts(n),
            _ => {}
        }
    }
    if h.ip.is_none() {
        return Ok(None);
    }
    Ok(Some(h))
}

/// An open TCP `<port>`; closed/filtered ports and UDP are ignored.
fn parse_port(p: roxmltree::Node) -> Option<NmapPort> {
    if p.attribute("protocol") != Some("tcp") {
        return None;
    }
    let port: u16 = p.attribute("portid")?.parse().ok().filter(|&p| p > 0)?;
    let state = p.children().find(|c| c.has_tag_name("state"))?.attribute("state")?;
    if state != "open" {
        return None;
    }
    let mut out = NmapPort { port, ..Default::default() };
    if let Some(s) = p.children().find(|c| c.has_tag_name("service")) {
        let attr = |name: &str, max: usize| s.attribute(name).map(|v| clean(v, max)).filter(|v| !v.is_empty());
        out.service = attr("name", 40).unwrap_or_default();
        out.product = attr("product", 80);
        out.version = attr("version", 60);
        out.extrainfo = attr("extrainfo", 120);
        out.ostype = attr("ostype", 40);
        out.tls = s.attribute("tunnel") == Some("ssl");
        out.cpes = s
            .children()
            .filter(|c| c.has_tag_name("cpe"))
            .filter_map(|c| c.text())
            .map(str::trim)
            .filter(|c| is_cpe22(c))
            .map(str::to_string)
            .take(8)
            .collect();
    }
    out.scripts = parse_scripts(p);
    Some(out)
}

fn parse_os(n: roxmltree::Node) -> Option<OsGuess> {
    // Nmap lists matches best first.
    let m = n.children().find(|c| c.has_tag_name("osmatch"))?;
    let name = clean(m.attribute("name")?, 100);
    let accuracy: u8 = m.attribute("accuracy")?.parse().ok().filter(|a| *a <= 100)?;
    let device_type = m
        .children()
        .find(|c| c.has_tag_name("osclass"))
        .and_then(|c| c.attribute("type"))
        .map(|t| clean(t, 40))
        .filter(|t| !t.is_empty());
    (!name.is_empty()).then_some(OsGuess { name, accuracy, device_type })
}

fn parse_scripts(parent: roxmltree::Node) -> Vec<Script> {
    parent.children().filter(|c| c.has_tag_name("script")).take(MAX_SCRIPTS).filter_map(parse_script).collect()
}

fn parse_script(s: roxmltree::Node) -> Option<Script> {
    let id = s.attribute("id")?;
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    let mut script = Script {
        id: id.to_string(),
        output: clean_multiline(s.attribute("output").unwrap_or(""), 4_000),
        ..Default::default()
    };
    flatten(s, "", &mut script.elems, 0);
    // NSE `vulns` format: a <table> per vulnerability with a "state" element.
    for t in s.children().filter(|c| c.has_tag_name("table")) {
        if let Some(v) = parse_vuln(t) {
            script.vulns.push(v);
        }
    }
    Some(script)
}

fn parse_vuln(t: roxmltree::Node) -> Option<ScriptVuln> {
    let elem = |key: &str| {
        t.children().find(|c| c.has_tag_name("elem") && c.attribute("key") == Some(key)).and_then(|c| c.text())
    };
    let table = |key: &str| t.children().find(|c| c.has_tag_name("table") && c.attribute("key") == Some(key));
    let items = |key: &str| -> Vec<String> {
        table(key)
            .map(|tb| {
                tb.children().filter(|c| c.has_tag_name("elem")).filter_map(|c| c.text()).map(str::to_string).collect()
            })
            .unwrap_or_default()
    };
    let state = clean(elem("state")?, 40);
    let title = clean(elem("title").unwrap_or(""), 200);
    let mut cves: Vec<String> = items("ids")
        .iter()
        .filter_map(|i| i.trim().strip_prefix("CVE:"))
        .filter(|c| crate::vuln::nvd::is_cve_id(c))
        .map(str::to_string)
        .collect();
    // The table key is often the CVE id itself.
    if let Some(k) = t.attribute("key").filter(|k| crate::vuln::nvd::is_cve_id(k))
        && !cves.iter().any(|c| c == k)
    {
        cves.insert(0, k.to_string());
    }
    cves.truncate(16);
    let description = clean(&items("description").join(" "), 2_000);
    let refs = items("refs")
        .into_iter()
        .map(|r| r.trim().to_string())
        .filter(|r| (r.starts_with("https://") || r.starts_with("http://")) && r.len() <= 300)
        .filter(|r| r.chars().all(|c| c.is_ascii_graphic()))
        .take(10)
        .collect();
    Some(ScriptVuln {
        title,
        state,
        cves,
        description,
        risk: elem("risk_factor").map(|r| clean(r, 12).to_ascii_uppercase()),
        disclosure: elem("disclosure").map(|d| clean(d, 20)),
        refs,
    })
}

/// Flatten nested `<table>`/`<elem>` into `key.path = value` pairs (bounded).
fn flatten(n: roxmltree::Node, prefix: &str, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 8 {
        return;
    }
    for c in n.children().filter(|c| c.is_element()) {
        if out.len() >= 200 {
            return;
        }
        let key = clean(c.attribute("key").unwrap_or(""), 60);
        let path = match (prefix.is_empty(), key.is_empty()) {
            (true, _) => key.clone(),
            (false, true) => prefix.to_string(),
            (false, false) => format!("{prefix}.{key}"),
        };
        match c.tag_name().name() {
            "elem" => out.push((path, clean(c.text().unwrap_or(""), 300))),
            "table" => flatten(c, &path, out, depth + 1),
            _ => {}
        }
    }
}

/// `cpe:/a:vendor:product[:version…]` with a safe character set.
fn is_cpe22(c: &str) -> bool {
    c.len() <= 120
        && (c.starts_with("cpe:/a:") || c.starts_with("cpe:/o:") || c.starts_with("cpe:/h:"))
        && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ":/._-~%".contains(ch))
}

fn is_mac(s: &str) -> bool {
    s.len() == 17
        && s.split(':').count() == 6
        && s.split(':').all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Remove control characters and cap the length.
pub fn clean(s: &str, max: usize) -> String {
    crate::vuln::detect::clean(s, max)
}

/// Like [`clean`] but keeps line breaks (script output is multi-line).
pub fn clean_multiline(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, line) in s.lines().map(|l| clean(l, 300)).filter(|l| !l.is_empty()).take(80).enumerate() {
        if out.len() + line.len() > max {
            break;
        }
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(xml: &str) -> Vec<Item> {
        let mut s = Stream::default();
        xml.lines().filter_map(|l| s.push_line(l)).collect()
    }

    fn hosts(xml: &str) -> Vec<NmapHost> {
        stream(xml)
            .into_iter()
            .filter_map(|i| match i {
                Item::Host(h) => Some(*h),
                _ => None,
            })
            .collect()
    }

    /// Real Nmap 7.94 output: fake vsftpd + OpenSSH on 127.0.0.1.
    #[test]
    fn real_service_scan() {
        let items = stream(include_str!("testdata/services.xml"));
        assert!(items.iter().any(|i| matches!(i, Item::Finished(e, None) if e == "success")));
        let h = hosts(include_str!("testdata/services.xml"));
        assert_eq!(h.len(), 1);
        let h = &h[0];
        assert_eq!(h.ip, Some(Ipv4Addr::LOCALHOST));
        // 4 open, 1 closed (ignored).
        assert_eq!(h.ports.len(), 4);
        let ftp = &h.ports[0];
        assert_eq!((ftp.port, ftp.service.as_str()), (12121, "ftp"));
        assert_eq!(ftp.cpes, ["cpe:/a:vsftpd:vsftpd:3.0.3"]);
        assert_eq!(ftp.scripts[0].id, "ftp-anon");
        assert!(ftp.scripts[0].output.starts_with("Anonymous FTP login allowed"));
        assert!(ftp.scripts[0].output.contains('\n'));
        let ssh = &h.ports[1];
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("8.9p1 Ubuntu 3ubuntu0.1"));
        assert_eq!(ssh.description().unwrap(), "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)");
        assert_eq!(ssh.cpes.len(), 2);
    }

    /// Real Nmap output for a TLS service with an expired certificate.
    #[test]
    fn real_tls_scan() {
        let h = hosts(include_str!("testdata/tls.xml"));
        let p = &h[0].ports[0];
        assert!(p.tls);
        let cert = p.scripts.iter().find(|s| s.id == "ssl-cert").unwrap();
        assert_eq!(cert.elem("validity.notAfter"), Some("2021-01-01T00:00:00"));
        assert_eq!(cert.elem("subject.commonName"), Some("old.lan"));
        assert!(p.scripts.iter().any(|s| s.id == "tls-ticketbleed" && s.failed()));
    }

    #[test]
    fn vulns_os_mac_and_host_scripts() {
        let items = stream(include_str!("testdata/vulns.xml"));
        assert!(items.contains(&Item::Progress("Service scan".into(), 50.0)));
        let h = hosts(include_str!("testdata/vulns.xml"));
        assert_eq!(h.len(), 1, "the down host is skipped");
        let h = &h[0];
        assert_eq!(h.mac.as_deref(), Some("00:11:32:AA:BB:CC"));
        assert_eq!(h.hostname.as_deref(), Some("nas.lan"));
        assert_eq!(h.os.as_ref().unwrap().label(), "Linux 4.15 - 5.8 (96%, general purpose)");
        // filtered 8080 and UDP 161 are not open TCP ports
        assert_eq!(h.ports.iter().map(|p| p.port).collect::<Vec<_>>(), [443, 445, 6000]);
        let hb = &h.ports[0].scripts[0];
        assert_eq!(hb.vulns.len(), 1);
        let v = &hb.vulns[0];
        assert!(v.positive());
        assert_eq!(v.cves, ["CVE-2014-0160"]);
        assert_eq!(v.refs.len(), 1, "javascript: link dropped");
        let poodle = &h.ports[0].scripts[1];
        assert!(!poodle.vulns[0].positive());
        let ms17 = &h.scripts[1].vulns[0];
        assert!(ms17.positive());
        assert_eq!(ms17.risk.as_deref(), Some("HIGH"));
        assert_eq!(ms17.cves, ["CVE-2017-0143"]);
    }

    #[test]
    fn hostile_input() {
        // Control characters, oversized and malformed values.
        let xml = "<host><status state=\"up\"/><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>\
                   <address addr=\"evil\" addrtype=\"mac\"/>\
                   <ports><port protocol=\"tcp\" portid=\"99999\"><state state=\"open\"/></port>\
                   <port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
                   <service name=\"http&#x9;&#xd;[31m\" product=\"x&#xa;y\"><cpe>cpe:/a:a b:c</cpe></service>\
                   <script id=\"../../x\" output=\"a\"/></port></ports></host>";
        let h = parse_host(xml).unwrap().unwrap();
        assert_eq!(h.mac, None);
        assert_eq!(h.ports.len(), 1);
        assert_eq!(h.ports[0].service, "http[31m");
        assert_eq!(h.ports[0].product.as_deref(), Some("xy"));
        assert!(h.ports[0].cpes.is_empty());
        assert!(h.ports[0].scripts.is_empty());
        // Entity declarations (billion laughs) are refused.
        let bomb = "<!DOCTYPE h [<!ENTITY a \"aaaa\">]><host>&a;</host>";
        assert!(parse_host(bomb).is_err());
        assert!(parse_host("<host><status state=\"up\"/>").is_err());
        // Oversized block is skipped, not kept.
        let mut s = Stream::default();
        assert_eq!(s.push_line("<host>"), None);
        let big = "x".repeat(1024 * 1024);
        for _ in 0..9 {
            assert_eq!(s.push_line(&big), None);
        }
        assert_eq!(s.push_line("</host>"), Some(Item::Skipped));
        assert!(s.block.is_none());
    }

    /// Random bytes and mutations of real output never panic.
    #[test]
    fn fuzz_never_panics() {
        let samples = [
            include_str!("testdata/services.xml"),
            include_str!("testdata/tls.xml"),
            include_str!("testdata/vulns.xml"),
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..3_000 {
            let base = samples[i % samples.len()].as_bytes();
            let mut b = base.to_vec();
            for _ in 0..(next() % 20 + 1) {
                let pos = (next() as usize) % b.len();
                match next() % 3 {
                    0 => b[pos] = next() as u8,
                    1 => {
                        b.remove(pos);
                    }
                    _ => b.insert(pos, b"<>\"&;/="[(next() % 7) as usize]),
                }
            }
            let text = String::from_utf8_lossy(&b);
            let mut s = Stream::default();
            for line in text.lines() {
                let _ = s.push_line(line);
            }
        }
    }
}
