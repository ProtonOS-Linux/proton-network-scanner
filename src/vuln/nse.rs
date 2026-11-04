//! Using Nmap's results in a vulnerability assessment (Nmap engine).
//!
//! * [`products`] turns Nmap's service detection (CPE 2.2 names such as
//!   `cpe:/a:openbsd:openssh:8.9p1`) into [`Product`]s with the CPE 2.3 names
//!   NVD uses, so the normal CVE lookup works on them.
//! * [`merge`] adds what Nmap found to the service Proton identified itself.
//! * [`findings`] turns the output of Nmap's safe NSE scripts into findings:
//!   - vulnerabilities reported in NSE's standard `vulns` format
//!     ("State: VULNERABLE"), keyed by CVE id when the script gives one, so
//!     they are scored with NVD/EPSS data like any other CVE;
//!   - a few well-known configuration results, mapped to Proton checks
//!     PIS-0015 … PIS-0019 (SMB signing, SSLv2, expired certificate, risky
//!     HTTP methods, open X11) and PIS-0002 (anonymous FTP).
//!
//! Script output is informational otherwise and is shown in the service
//! details (`Service::nse`).

use std::net::Ipv4Addr;

use super::checks;
use super::detect::{self, Product, Service};
use super::nvd::CveRecord;
use super::score::{self, Severity};
use super::{Finding, offline};
use crate::nmap::{NmapPort, Script};

/// NVD's names for products Nmap files under other vendor/product names.
fn nvd_names<'a>(vendor: &'a str, product: &'a str) -> (&'a str, &'a str) {
    match (vendor, product) {
        ("igor_sysoev", "nginx") => ("f5", "nginx"),
        ("mysql", "mysql") => ("oracle", "mysql"),
        ("vsftpd", "vsftpd") => ("beasts", "vsftpd"),
        ("matt_johnston", "dropbear_ssh_server") => ("dropbear_ssh_project", "dropbear_ssh"),
        ("microsoft", "iis") => ("microsoft", "internet_information_services"),
        _ => (vendor, product),
    }
}

/// NVD splits some versions into version + update: OpenSSH `8.9p1` →
/// `8.9` / `p1`, OpenSSL 1.x `1.1.1f` → `1.1.1` / `f`, ProFTPD `1.3.5e`.
fn split_version<'a>(product: &str, v: &'a str) -> (&'a str, Option<&'a str>) {
    match product {
        "openssh" => match v.find('p') {
            Some(i) if i > 0 => (&v[..i], Some(&v[i..])),
            _ => (v, None),
        },
        "openssl" | "proftpd" => {
            let b = v.as_bytes();
            match b.len() {
                n if n >= 2 && b[n - 1].is_ascii_alphabetic() && b[n - 2].is_ascii_digit() => {
                    (&v[..n - 1], Some(&v[n - 1..]))
                }
                _ => (v, None),
            }
        }
        _ => (v, None),
    }
}

/// "dropbear_ssh" → "Dropbear ssh" (used when Nmap gives no product name).
fn pretty(s: &str) -> String {
    let s = s.replace('_', " ");
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => s,
    }
}

/// Software products in Nmap's service detection, with NVD CPE names.
pub fn products(p: &NmapPort) -> Vec<Product> {
    let distro = detect::is_distro_build(&format!(
        "{} {}",
        p.version.as_deref().unwrap_or(""),
        p.extrainfo.as_deref().unwrap_or("")
    ));
    let mut out: Vec<Product> = Vec::new();
    for (i, cpe) in p.cpes.iter().filter(|c| c.starts_with("cpe:/a:")).enumerate() {
        let parts: Vec<&str> = cpe["cpe:/a:".len()..].split(':').collect();
        let (Some(vendor), Some(product)) = (parts.first(), parts.get(1)) else { continue };
        let (vendor, product) = nvd_names(vendor, product);
        // The version is in the CPE; for the main product (the first CPE)
        // Nmap's version field can fill it in ("OpenSSL" + "1.1.1f").
        let version = match parts.get(2) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ if i == 0 => p.version.as_deref().and_then(|v| v.split_whitespace().next()).unwrap_or("").to_string(),
            _ => String::new(),
        };
        let name = match (&p.product, i) {
            (Some(n), 0) => n.clone(),
            _ => pretty(product),
        };
        // Only an exact version is used for CVE matching; an approximate one
        // ("4", "3.X - 4.X") is shown but gets no CPE (see is_precise_version).
        if !super::nvd::is_precise_version(&version) {
            let approx = match (&p.version, i) {
                (Some(v), 0) => v.clone(),
                _ => version.clone(),
            };
            let shown = if approx.is_empty() { name.clone() } else { format!("{name} {approx}") };
            let mut prod = Product::new(&detect::clean(&shown, 60), vendor, product, "", None);
            prod.backported = distro;
            if !out.iter().any(|o| o.cpe.is_none() && o.name == prod.name) {
                out.push(prod);
            }
            continue;
        }
        let (ver, upd) = split_version(product, &version);
        let mut prod = Product::new(&name, vendor, product, ver, upd);
        prod.backported = distro;
        if !out.iter().any(|o| o.cpe.is_some() && o.cpe == prod.cpe && o.name == prod.name) {
            out.push(prod);
        }
    }
    out
}

/// `vendor:product` of a CPE 2.3 name, with NVD's aliases.
fn product_key(cpe: &str) -> Vec<(String, String)> {
    let p: Vec<&str> = cpe.split(':').collect();
    match (p.get(3), p.get(4)) {
        (Some(v), Some(pr)) => offline::aliases(v, pr),
        _ => Vec::new(),
    }
}

/// Add Nmap's results for this port to the service Proton identified.
pub fn merge(svc: &mut Service, p: &NmapPort) {
    for prod in products(p) {
        let keys = prod.cpe.as_deref().map(product_key).unwrap_or_default();
        let known = svc.products.iter().any(|q| {
            q.cpe.as_deref().is_some_and(|c| product_key(c).iter().any(|k| keys.contains(k)))
                || (q.cpe.is_none() && q.name.eq_ignore_ascii_case(&prod.name))
        });
        if !known {
            svc.products.push(prod);
        }
    }
    if svc.banner.is_none() {
        svc.banner = p.description().map(|d| detect::clean(&d, 200));
    }
    if svc.name.starts_with("TCP ") && !p.service.is_empty() && p.service != "tcpwrapped" && p.service != "unknown" {
        svc.name = if p.tls { format!("{} (TLS)", p.service) } else { p.service.clone() };
    }
    add_scripts(svc, &p.scripts);
}

/// Keep script output for the details view (failed scripts left out).
pub fn add_scripts(svc: &mut Service, scripts: &[Script]) {
    for s in scripts.iter().filter(|s| !s.failed() && !s.output.is_empty()) {
        if svc.nse.len() < 32 && !svc.nse.iter().any(|(id, _)| id == &s.id) {
            svc.nse.push((s.id.clone(), s.output.clone()));
        }
    }
}

/// Rough CVSS-like impact for a severity (when no CVSS score is known).
pub fn severity_impact(s: Severity) -> f32 {
    match s {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 0.0,
    }
}

/// Findings from the scripts that ran on `ip:port`.
///
/// Returns `(final findings, script-confirmed CVEs)`: the second list still
/// needs CVSS/KEV (from NVD or the offline database) and EPSS.
pub fn findings(
    ip: Ipv4Addr,
    port: u16,
    service: &str,
    scripts: &[Script],
    today: &str,
) -> (Vec<Finding>, Vec<Finding>) {
    let (mut done, mut cves) = (Vec::new(), Vec::new());
    for s in scripts.iter().filter(|s| !s.failed()) {
        for v in s.vulns.iter().filter(|v| v.positive()) {
            let f = vuln_finding(ip, port, service, s, v);
            if f.is_cve() { cves.push(f) } else { done.push(f) }
        }
        let out = s.output.as_str();
        let check = match s.id.as_str() {
            "ftp-anon" if out.starts_with("Anonymous FTP login allowed") => Some(&checks::FTP_ANONYMOUS),
            "sslv2" if out.contains("SSLv2 supported") => Some(&checks::SSLV2),
            "smb2-security-mode" if out.contains("not required") => Some(&checks::SMB_SIGNING),
            "smb-security-mode"
                if s.elem("message_signing") == Some("disabled") || out.contains("message_signing: disabled") =>
            {
                Some(&checks::SMB_SIGNING)
            }
            "x11-access" if out.contains("access is granted") => Some(&checks::X11_OPEN),
            "ssl-cert" => match s.elem("validity.notAfter") {
                // ISO dates compare correctly as text.
                Some(end) if end.len() >= 10 && end.is_char_boundary(10) && &end[..10] < today => {
                    Some(&checks::CERT_EXPIRED)
                }
                _ => None,
            },
            "http-methods" => {
                let risky: Vec<&str> = s
                    .elems
                    .iter()
                    .filter(|(k, _)| k == "Potentially risky methods")
                    .map(|(_, v)| v.as_str())
                    .filter(|m| ["PUT", "DELETE", "TRACE", "TRACK", "CONNECT"].contains(m))
                    .collect();
                (!risky.is_empty()).then_some(&checks::HTTP_RISKY_METHODS)
            }
            _ => None,
        };
        if let Some(c) = check {
            let first = out.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
            let evidence = match s.id.as_str() {
                "ssl-cert" => format!(
                    "Nmap script ssl-cert: certificate for '{}' valid until {}.",
                    s.elem("subject.commonName").unwrap_or("?"),
                    s.elem("validity.notAfter").unwrap_or("?")
                ),
                _ => format!("Nmap script {}: {}", s.id, detect::clean(first, 200)),
            };
            done.push(c.finding(ip, port, service, evidence));
        }
    }
    (done, cves)
}

fn vuln_finding(ip: Ipv4Addr, port: u16, service: &str, s: &Script, v: &crate::nmap::parse::ScriptVuln) -> Finding {
    let severity = match v.risk.as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::High, // NSE vuln scripts only report serious issues
    };
    let id = v.cves.first().cloned().unwrap_or_else(|| format!("NSE-{}", s.id));
    let title =
        if v.title.is_empty() { format!("Vulnerability reported by Nmap script {}", s.id) } else { v.title.clone() };
    let mut evidence = format!("Confirmed by Nmap script {} (state: {}).", s.id, v.state);
    if v.cves.len() > 1 {
        evidence.push_str(&format!(" Also listed as: {}.", v.cves[1..].join(", ")));
    }
    let mut references = Vec::new();
    if id.starts_with("CVE-") {
        references.push(format!("https://nvd.nist.gov/vuln/detail/{id}"));
    }
    references.extend(v.refs.iter().cloned());
    // "Likely" results are weighted a little lower than confirmed ones.
    let threat = if v.state.to_ascii_uppercase().starts_with("LIKELY") { 5.0 } else { 6.0 };
    Finding {
        id,
        title,
        ip,
        port,
        service: service.to_string(),
        product: None,
        severity,
        cvss: None,
        epss: None,
        kev: false,
        ppr: score::ppr(severity_impact(severity), threat),
        description: if v.description.is_empty() { v.title.clone() } else { v.description.clone() },
        solution: "Install the vendor's security update for this issue (see the references), or disable the \
                   affected service until it can be updated."
            .into(),
        evidence,
        references,
        published: v.disclosure.clone(),
    }
}

/// Fill a script-confirmed CVE finding with NVD data (CVSS, KEV, dates).
pub fn enrich(f: &mut Finding, r: &CveRecord) {
    if let Some(c) = &r.cvss {
        f.severity = Severity::from_score(c.score);
        f.cvss = Some(c.clone());
    }
    f.kev = r.kev;
    if !r.description.is_empty() {
        f.description = r.description.clone();
    }
    if r.published.is_some() {
        f.published = r.published.clone();
    }
    if let Some(sol) = &r.solution {
        f.solution = sol.clone();
    }
    for link in &r.references {
        if f.references.len() < 20 && !f.references.contains(link) {
            f.references.push(link.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::parse::parse_host;

    fn host() -> crate::nmap::NmapHost {
        let xml = include_str!("../nmap/testdata/vulns.xml");
        let start = xml.find("<host ").unwrap();
        let end = xml.find("</host>").unwrap() + 7;
        parse_host(&xml[start..end]).unwrap().unwrap()
    }

    #[test]
    fn nmap_cpes_become_nvd_cpes() {
        let mut p = NmapPort {
            port: 22,
            product: Some("OpenSSH".into()),
            version: Some("8.9p1 Ubuntu 3ubuntu0.1".into()),
            extrainfo: Some("Ubuntu Linux; protocol 2.0".into()),
            cpes: vec!["cpe:/a:openbsd:openssh:8.9p1".into(), "cpe:/o:linux:linux_kernel".into()],
            ..Default::default()
        };
        let v = products(&p);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].cpe.as_deref(), Some("cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"));
        assert_eq!(v[0].label(), "OpenSSH 8.9p1");
        assert!(v[0].backported);
        p.cpes = vec!["cpe:/a:igor_sysoev:nginx:1.18.0".into()];
        p.product = Some("nginx".into());
        p.extrainfo = None;
        p.version = Some("1.18.0".into());
        assert_eq!(products(&p)[0].cpe.as_deref(), Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"));
        // Version only in Nmap's version field.
        p.cpes = vec!["cpe:/a:openssl:openssl".into()];
        p.product = Some("OpenSSL".into());
        p.version = Some("1.1.1f".into());
        assert_eq!(products(&p)[0].cpe.as_deref(), Some("cpe:2.3:a:openssl:openssl:1.1.1:f:*:*:*:*:*:*"));
        // No version anywhere → shown, but no CPE (no guessing).
        p.version = None;
        assert_eq!(products(&p)[0].cpe, None);
        // Approximate versions (real Nmap Samba fingerprints) → no CPE, no CVE flood.
        p.cpes = vec!["cpe:/a:samba:samba".into()];
        p.product = Some("Samba smbd".into());
        for v in ["3.X - 4.X", "4", "4.X"] {
            p.version = Some(v.into());
            let prod = &products(&p)[0];
            assert_eq!(prod.cpe, None, "{v}");
            assert_eq!(prod.label(), format!("Samba smbd {v}"));
        }
        p.cpes = vec!["cpe:/a:samba:samba:4".into()];
        assert_eq!(products(&p)[0].cpe, None);
        p.cpes = vec!["cpe:/a:samba:samba:4.6.2".into()];
        assert_eq!(products(&p)[0].cpe.as_deref(), Some("cpe:2.3:a:samba:samba:4.6.2:*:*:*:*:*:*:*"));
        // Hostile version strings never reach a CPE.
        p.cpes = vec!["cpe:/a:apache:http_server:2.4%3a*".into()];
        assert_eq!(products(&p)[0].cpe, None);
    }

    #[test]
    fn merge_adds_without_duplicates() {
        let h = host();
        let p443 = &h.ports[0];
        let mut svc = Service {
            ip: Ipv4Addr::new(192, 168, 1, 20),
            port: 443,
            name: "TCP 443".into(),
            products: detect::parse_server_header("nginx/1.18.0"),
            banner: None,
            nse: vec![],
        };
        merge(&mut svc, p443);
        assert_eq!(svc.products.len(), 1, "nginx under two vendor names is the same product");
        assert_eq!(svc.name, "http (TLS)");
        assert_eq!(svc.banner.as_deref(), Some("nginx 1.18.0"));
        assert!(svc.nse.iter().any(|(id, _)| id == "ssl-heartbleed"));
    }

    #[test]
    fn script_findings() {
        let h = host();
        let ip = h.ip.unwrap();
        let (done, cves) = findings(ip, 443, "HTTPS", &h.ports[0].scripts, "2026-11-04");
        assert_eq!(cves.len(), 1);
        assert_eq!(cves[0].id, "CVE-2014-0160");
        assert!(cves[0].evidence.contains("ssl-heartbleed"));
        let ids: Vec<&str> = done.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["PIS-0018", "PIS-0016"], "risky methods + SSLv2; POODLE was NOT VULNERABLE");
        let (done, cves) = findings(ip, 445, "SMB", &h.scripts, "2026-11-04");
        assert_eq!(done.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["PIS-0015"]);
        assert_eq!(cves[0].id, "CVE-2017-0143");
        let (done, _) = findings(ip, 6000, "X11", &h.ports[2].scripts, "2026-11-04");
        assert_eq!(done[0].id, "PIS-0019");
        assert_eq!(done[0].severity, Severity::Critical);
    }

    #[test]
    fn expired_certificate_from_real_output() {
        let xml = include_str!("../nmap/testdata/tls.xml");
        let start = xml.find("<host ").unwrap();
        let end = xml.find("</host>").unwrap() + 7;
        let h = parse_host(&xml[start..end]).unwrap().unwrap();
        let (done, _) = findings(Ipv4Addr::LOCALHOST, 18443, "HTTPS", &h.ports[0].scripts, "2026-11-04");
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].id, "PIS-0017");
        assert!(done[0].evidence.contains("old.lan"));
        let (done, _) = findings(Ipv4Addr::LOCALHOST, 18443, "HTTPS", &h.ports[0].scripts, "2020-06-01");
        assert!(done.is_empty(), "not expired yet on that day");
    }
}
