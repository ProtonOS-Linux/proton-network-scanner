//! Public vulnerability data, fetched over HTTPS.
//!
//! | Data | Source | Used for |
//! |---|---|---|
//! | CVEs, descriptions, CVSS v4.0 / v3.x / v2 | NIST **NVD** API 2.0 (`services.nvd.nist.gov`) | which CVEs affect a product version, severity |
//! | Known exploited (CISA **KEV**) | the `cisaExploitAdd` field NVD includes | priority rating |
//! | **EPSS** probability + percentile | **FIRST** EPSS API (`api.first.org`) | priority rating |
//!
//! What leaves the computer: product names and versions (as CPE names) and
//! CVE numbers. **No IP addresses, host names or scan results are sent.**
//!
//! Limits and politeness:
//! * NVD allows 5 requests per 30 s without an API key and 50 with one. We
//!   wait 6.5 s (0.7 s with a key) between NVD requests, and back off 30 s if
//!   NVD answers 403/429/503.
//! * **Nothing is cached between scans.** Each assessment starts fresh and
//!   asks NVD again, so results always reflect the latest data and nothing
//!   from an earlier scan can leak into a new one. (Within one scan, each
//!   product version is looked up only once.) For computers without internet,
//!   see [`super::offline`].
//! * TLS certificates are always verified (operating system trust store).
//!
//! All text received is cleaned and length-limited before use.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::detect::clean;
use super::score::{Cvss, Epss};

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// Most CVEs kept per product (old software can have hundreds).
const MAX_CVES_PER_PRODUCT: usize = 400;

/// One CVE, reduced to what the scanner needs.
#[derive(Clone, Debug, PartialEq)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub cvss: Option<Cvss>,
    /// Listed in CISA's Known Exploited Vulnerabilities catalog.
    pub kev: bool,
    pub published: Option<String>,
    pub references: Vec<String>,
    /// NVD's own remediation note, when it has one.
    pub solution: Option<String>,
    /// Which product versions are vulnerable (from the CVE's configurations);
    /// used for offline matching.
    pub rules: Vec<CpeRule>,
    /// EPSS, when known (filled in for the offline database).
    pub epss: Option<Epss>,
}

/// One "vulnerable" CPE match criterion of a CVE, e.g. OpenSSH
/// `versionStartIncluding 8.5p1`, `versionEndExcluding 9.8p1`.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CpeRule {
    pub vendor: String,
    pub product: String,
    /// Exact version, or `*` for "any version within the bounds".
    pub version: String,
    /// Update (e.g. `p1`), or `*`.
    pub update: String,
    pub start_incl: Option<String>,
    pub start_excl: Option<String>,
    pub end_incl: Option<String>,
    pub end_excl: Option<String>,
}

/// Client for NVD and FIRST (no persistent cache — see the module notes).
pub struct VulnDb {
    agent: ureq::Agent,
    api_key: Option<String>,
    last_nvd: Option<Instant>,
}

impl VulnDb {
    pub fn new(api_key: Option<String>) -> VulnDb {
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(concat!("ProtonIPScanner/", env!("CARGO_PKG_VERSION"), " (+https://www.protonos.org)"))
            .build()
            .into();
        // Keys are 36-character UUIDs; anything else is ignored.
        let api_key = api_key
            .map(|k| k.trim().to_string())
            .filter(|k| k.len() <= 64 && !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        VulnDb { agent, api_key, last_nvd: None }
    }

    /// All CVEs that NVD lists as affecting this exact CPE (product + version).
    pub fn cves_for_cpe(&mut self, cpe: &str, cancel: &AtomicBool) -> Result<Vec<CveRecord>, String> {
        // `cpeName` + `isVulnerable` returns CVEs whose configurations mark
        // this product version as vulnerable (version ranges included). If
        // NVD rejects the name (not in its dictionary), fall back to
        // `virtualMatchString`, which matches the CVEs' match criteria directly.
        let enc = percent_encode(cpe);
        let mut out = Vec::new();
        let mut query = format!("cpeName={enc}&isVulnerable");
        let mut start = 0usize;
        let mut fell_back = false;
        loop {
            let url = format!("{NVD_URL}?{query}&resultsPerPage=2000&startIndex={start}");
            let (status, body) = self.nvd_get(&url, cancel)?;
            if (status == 404 || status == 400) && !fell_back {
                fell_back = true;
                query = format!("virtualMatchString={enc}");
                continue;
            }
            if status != 200 {
                return Err(format!("NVD answered HTTP {status}"));
            }
            let v: Value = serde_json::from_str(&body).map_err(|e| format!("NVD sent invalid data: {e}"))?;
            let (total, records) = parse_nvd(&v);
            let got = records.len();
            out.extend(records);
            start += got;
            if got == 0 || start >= total || out.len() >= MAX_CVES_PER_PRODUCT {
                break;
            }
        }
        out.truncate(MAX_CVES_PER_PRODUCT);
        Ok(out)
    }

    /// Every CVE NVD lists for a product, all versions (for the offline
    /// database). `virtualMatchString=cpe:2.3:a:<vendor>:<product>` matches the
    /// CVEs' match criteria; each record keeps its version rules.
    pub fn cves_for_product(
        &mut self,
        vendor: &str,
        product: &str,
        cancel: &AtomicBool,
    ) -> Result<Vec<CveRecord>, String> {
        let enc = percent_encode(&format!("cpe:2.3:a:{vendor}:{product}"));
        let mut out = Vec::new();
        let mut start = 0usize;
        loop {
            let url = format!("{NVD_URL}?virtualMatchString={enc}&resultsPerPage=2000&startIndex={start}");
            let (status, body) = self.nvd_get(&url, cancel)?;
            if status != 200 {
                return Err(format!("NVD answered HTTP {status}"));
            }
            let v: Value = serde_json::from_str(&body).map_err(|e| format!("NVD sent invalid data: {e}"))?;
            let (total, records) = parse_nvd(&v);
            let got = records.len();
            out.extend(records);
            start += got;
            // Safety cap: no product we detect has anywhere near 20 000 CVEs.
            if got == 0 || start >= total || out.len() >= 20_000 {
                break;
            }
        }
        Ok(out)
    }

    /// One CVE by its id (for vulnerabilities an Nmap script confirmed).
    pub fn cve_by_id(&mut self, id: &str, cancel: &AtomicBool) -> Result<Option<CveRecord>, String> {
        if !is_cve_id(id) {
            return Ok(None);
        }
        let (status, body) = self.nvd_get(&format!("{NVD_URL}?cveId={id}"), cancel)?;
        if status == 404 {
            return Ok(None);
        }
        if status != 200 {
            return Err(format!("NVD answered HTTP {status}"));
        }
        let v: Value = serde_json::from_str(&body).map_err(|e| format!("NVD sent invalid data: {e}"))?;
        Ok(parse_nvd(&v).1.into_iter().find(|r| r.id == id))
    }

    /// EPSS scores for these CVE ids (missing ids simply have no score yet).
    pub fn epss(&mut self, ids: &[String], cancel: &AtomicBool) -> Result<HashMap<String, Epss>, String> {
        let mut out = HashMap::new();
        // ≤ 2000 characters per request → 100 ids of up to ~19 characters.
        for chunk in ids.chunks(100) {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let url = format!("{EPSS_URL}?cve={}&limit=100", chunk.join(","));
            let mut resp = self.agent.get(&url).call().map_err(|e| format!("could not reach FIRST EPSS: {e}"))?;
            if resp.status() != 200 {
                return Err(format!("FIRST EPSS answered HTTP {}", resp.status()));
            }
            let body =
                resp.body_mut().with_config().limit(4 * 1024 * 1024).read_to_string().map_err(|e| e.to_string())?;
            let v: Value = serde_json::from_str(&body).map_err(|e| format!("EPSS sent invalid data: {e}"))?;
            out.extend(parse_epss(&v));
        }
        Ok(out)
    }

    /// GET from NVD, respecting the rate limit; retries once after a 30 s back-off.
    fn nvd_get(&mut self, url: &str, cancel: &AtomicBool) -> Result<(u16, String), String> {
        for attempt in 0..2 {
            let gap = if self.api_key.is_some() { Duration::from_millis(700) } else { Duration::from_millis(6_500) };
            if let Some(last) = self.last_nvd {
                let wait = gap.saturating_sub(last.elapsed());
                crate::scanner::pause(wait.as_millis() as u64, cancel);
            }
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("stopped".into());
            }
            let mut req = self.agent.get(url);
            if let Some(k) = &self.api_key {
                req = req.header("apiKey", k);
            }
            self.last_nvd = Some(Instant::now());
            let mut resp = req.call().map_err(|e| format!("could not reach NVD: {e}"))?;
            let status = resp.status().as_u16();
            if matches!(status, 403 | 429 | 503) && attempt == 0 {
                crate::scanner::pause(30_000, cancel);
                continue;
            }
            let body = resp
                .body_mut()
                .with_config()
                .limit(64 * 1024 * 1024)
                .read_to_string()
                .map_err(|e| format!("NVD download failed: {e}"))?;
            return Ok((status, body));
        }
        Err("NVD rate limit reached; try again in a minute or add a free NVD API key in Settings".into())
    }
}

// ---------------------------------------------------------------------------
// Parsing (pure functions, unit-tested with NVD/FIRST-shaped documents)
// ---------------------------------------------------------------------------

/// Parse one NVD API 2.0 page → (totalResults, records).
pub fn parse_nvd(v: &Value) -> (usize, Vec<CveRecord>) {
    let total = v["totalResults"].as_u64().unwrap_or(0) as usize;
    let mut out = Vec::new();
    for item in v["vulnerabilities"].as_array().into_iter().flatten() {
        let c = &item["cve"];
        let Some(id) = c["id"].as_str().filter(|s| is_cve_id(s)) else { continue };
        if c["vulnStatus"].as_str() == Some("Rejected") {
            continue;
        }
        let description = c["descriptions"]
            .as_array()
            .and_then(|d| d.iter().find(|x| x["lang"] == "en").or(d.first()))
            .and_then(|x| x["value"].as_str())
            .map(|s| clean(s, 2_000))
            .unwrap_or_default();
        let references = c["references"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["url"].as_str())
            .filter(|u| (u.starts_with("https://") || u.starts_with("http://")) && u.len() <= 300)
            .take(5)
            .map(|u| clean(u, 300))
            .collect();
        out.push(CveRecord {
            id: id.to_string(),
            description,
            cvss: best_cvss(&c["metrics"]),
            kev: c["cisaExploitAdd"].is_string(),
            published: c["published"].as_str().map(|s| clean(s, 10)),
            references,
            solution: c["evaluatorSolution"].as_str().map(|s| clean(s, 500)),
            rules: parse_rules(&c["configurations"]),
            epss: None,
        });
    }
    (total, out)
}

/// Prefer CVSS v4.0, then v3.1, v3.0, v2; within a version prefer NVD's own
/// ("Primary") score over the CNA's ("Secondary").
fn best_cvss(metrics: &Value) -> Option<Cvss> {
    for (key, version) in
        [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]
    {
        let Some(list) = metrics[key].as_array() else { continue };
        let pick = list.iter().find(|m| m["type"] == "Primary").or(list.first());
        if let Some(m) = pick {
            let d = &m["cvssData"];
            if let Some(score) = d["baseScore"].as_f64() {
                return Some(Cvss {
                    version: version.into(),
                    score: (score as f32).clamp(0.0, 10.0),
                    vector: d["vectorString"].as_str().map(|s| clean(s, 200)).unwrap_or_default(),
                });
            }
        }
    }
    None
}

/// Vulnerable CPE criteria from a CVE's `configurations` (all nodes; "running
/// on" platform conditions are ignored, which can over-match slightly).
fn parse_rules(configs: &Value) -> Vec<CpeRule> {
    let mut out = Vec::new();
    for cfg in configs.as_array().into_iter().flatten().take(50) {
        for node in cfg["nodes"].as_array().into_iter().flatten().take(50) {
            for m in node["cpeMatch"].as_array().into_iter().flatten().take(500) {
                if m["vulnerable"] != true {
                    continue;
                }
                let Some(crit) = m["criteria"].as_str() else { continue };
                let parts: Vec<&str> = crit.split(':').collect();
                if parts.len() < 7 || parts[0] != "cpe" {
                    continue;
                }
                let field = |s: &str| clean(s, 40);
                let bound = |k: &str| m[k].as_str().map(|v| clean(v, 40));
                out.push(CpeRule {
                    vendor: field(parts[3]),
                    product: field(parts[4]),
                    version: field(parts[5]),
                    update: field(parts[6]),
                    start_incl: bound("versionStartIncluding"),
                    start_excl: bound("versionStartExcluding"),
                    end_incl: bound("versionEndIncluding"),
                    end_excl: bound("versionEndExcluding"),
                });
                if out.len() >= 2_000 {
                    return out;
                }
            }
        }
    }
    out
}

impl CpeRule {
    /// Does this rule cover `vendor:product` at `version`/`update`?
    pub fn matches(&self, vendor: &str, product: &str, version: &str, update: &str) -> bool {
        if self.vendor != vendor || self.product != product {
            return false;
        }
        let any = |s: &str| s == "*" || s == "-" || s.is_empty();
        if !any(&self.version) {
            // Exact version (and update, if the rule names one).
            return self.version == version && (any(&self.update) || self.update == update);
        }
        // Range: compare the full version, e.g. "9.6" + "p1" → "9.6p1".
        let full = if any(update) { version.to_string() } else { format!("{version}{update}") };
        let cmp = |b: &String| cmp_version(&full, b);
        use std::cmp::Ordering::*;
        self.start_incl.as_ref().is_none_or(|b| cmp(b) != Less)
            && self.start_excl.as_ref().is_none_or(|b| cmp(b) == Greater)
            && self.end_incl.as_ref().is_none_or(|b| cmp(b) != Greater)
            && self.end_excl.as_ref().is_none_or(|b| cmp(b) == Less)
        // A rule with "*" and no bounds at all means every version.
    }
}

/// Compare version strings piece by piece: numbers numerically, letters
/// alphabetically (`1.1.1f < 1.1.1k`, `9.3 < 9.3p2 < 9.10`).
/// Is this an exact version that CVE version ranges can be compared with?
///
/// Network fingerprints sometimes only know a family: Nmap reports Samba as
/// "4" or "3.X - 4.X". Compared with NVD ranges, "4" is older than every
/// fixed 4.x release, so it would "match" nearly every CVE ever published for
/// the product — false positives. An exact version has at least
/// `major.minor`, no wildcard (`X`) and no range.
pub fn is_precise_version(v: &str) -> bool {
    let v = v.trim();
    if v.is_empty() || !v.starts_with(|c: char| c.is_ascii_digit()) || v.contains(char::is_whitespace) {
        return false;
    }
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() >= 2
        && parts[1].starts_with(|c: char| c.is_ascii_digit())
        && !parts.iter().any(|p| p.eq_ignore_ascii_case("x") || p.eq_ignore_ascii_case("*"))
}

pub fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    fn pieces(s: &str) -> Vec<(bool, String)> {
        let mut out: Vec<(bool, String)> = Vec::new();
        for c in s.chars() {
            if !c.is_ascii_alphanumeric() {
                out.push((false, String::new())); // separator
                continue;
            }
            let digit = c.is_ascii_digit();
            match out.last_mut() {
                Some((d, p)) if !p.is_empty() && *d == digit => p.push(c),
                _ => out.push((digit, c.to_string())),
            }
        }
        out.into_iter().filter(|(_, p)| !p.is_empty()).collect()
    }
    let (pa, pb) = (pieces(a), pieces(b));
    for i in 0..pa.len().max(pb.len()) {
        let ord = match (pa.get(i), pb.get(i)) {
            (Some((true, x)), Some((true, y))) => {
                let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                x.len().cmp(&y.len()).then_with(|| x.cmp(y))
            }
            (Some((false, x)), Some((false, y))) => x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()),
            (Some((true, _)), Some((false, _))) => std::cmp::Ordering::Greater,
            (Some((false, _)), Some((true, _))) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (None, None) => std::cmp::Ordering::Equal,
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

/// Delete lookup caches written by version 1.1.0 (which cached NVD answers
/// for 24 h). From 1.1.1 on, nothing is cached between scans.
pub fn clear_old_cache() {
    let Some(dir) = dirs::cache_dir().map(|d| d.join("proton-ip-scanner")) else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let ours = (name.starts_with("nvd-") || name.starts_with("epss"))
            && (name.ends_with(".json") || name.ends_with(".tmp"));
        if ours && e.file_type().is_ok_and(|t| t.is_file()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let _ = std::fs::remove_dir(&dir); // only succeeds if now empty
}

/// Parse a FIRST EPSS response (`epss` and `percentile` are strings there).
pub fn parse_epss(v: &Value) -> Vec<(String, Epss)> {
    v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| {
            let id = d["cve"].as_str().filter(|s| is_cve_id(s))?;
            let num = |k: &str| d[k].as_str().and_then(|s| s.parse::<f32>().ok()).or(d[k].as_f64().map(|f| f as f32));
            Some((
                id.to_string(),
                Epss { probability: num("epss")?.clamp(0.0, 1.0), percentile: num("percentile")?.clamp(0.0, 1.0) },
            ))
        })
        .collect()
}

/// `CVE-YYYY-NNNN…`
pub fn is_cve_id(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() <= 20
        && s.starts_with("CVE-")
        && b.len() >= 13
        && b[4..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'-'
        && b[9..].iter().all(u8::is_ascii_digit)
}

/// Percent-encode everything except unreserved URL characters.
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {

    #[test]
    fn precise_versions() {
        for v in ["8.9", "1.1.1", "2022.83", "4.6.2", "10.0.17763"] {
            assert!(is_precise_version(v), "{v}");
        }
        for v in ["", "4", "4.X", "3.X - 4.X", "4.x", "*", "x.1", "4.", "v4.1", "4 .1"] {
            assert!(!is_precise_version(v), "{v}");
        }
    }
    use super::*;
    use serde_json::json;

    /// Shaped like a real NVD API 2.0 answer (fields trimmed).
    fn sample_nvd() -> Value {
        json!({
          "resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "format": "NVD_CVE", "version": "2.0",
          "vulnerabilities": [
            { "cve": {
                "id": "CVE-2024-6387", "vulnStatus": "Modified", "published": "2024-07-01T13:15:06.467",
                "descriptions": [{"lang": "es", "value": "Una condición de carrera"}, {"lang": "en", "value": "A signal handler race condition was found in OpenSSH's server (sshd)."}],
                "metrics": {
                  "cvssMetricV31": [{"source": "secalert@redhat.com", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 8.1, "baseSeverity": "HIGH"}}]
                },
                "references": [{"url": "https://www.openssh.com/txt/release-9.8"}, {"url": "javascript:alert(1)"}],
                "cisaExploitAdd": null
            }},
            { "cve": {
                "id": "CVE-2023-38408", "vulnStatus": "Analyzed", "published": "2023-07-20T03:15:10.170",
                "descriptions": [{"lang": "en", "value": "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path.\u{1b}[31m"}],
                "metrics": {
                  "cvssMetricV40": [{"source": "cna@example.org", "type": "Secondary", "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
                  "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}]
                },
                "references": [], "cisaExploitAdd": "2023-08-01"
            }},
            { "cve": { "id": "not-a-cve" } }
          ]
        })
    }

    #[test]
    fn parses_nvd() {
        let (total, r) = parse_nvd(&sample_nvd());
        assert_eq!(total, 2);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].id, "CVE-2024-6387");
        assert!(r[0].description.starts_with("A signal handler"));
        assert_eq!(r[0].cvss.as_ref().unwrap().version, "3.1");
        assert_eq!(r[0].references, vec!["https://www.openssh.com/txt/release-9.8".to_string()]);
        assert!(!r[0].kev);
        // v4.0 is preferred over v3.1 when both exist.
        let c = r[1].cvss.as_ref().unwrap();
        assert_eq!((c.version.as_str(), c.score), ("4.0", 9.3));
        assert!(r[1].kev);
        assert!(!r[1].description.contains('\u{1b}'));
        assert_eq!(r[1].published.as_deref(), Some("2023-07-20"));
    }

    #[test]
    fn version_order() {
        use std::cmp::Ordering::*;
        assert_eq!(cmp_version("8.9p1", "9.8p1"), Less);
        assert_eq!(cmp_version("9.3", "9.3p2"), Less);
        assert_eq!(cmp_version("9.10", "9.9"), Greater);
        assert_eq!(cmp_version("1.1.1f", "1.1.1k"), Less);
        assert_eq!(cmp_version("2.4.49", "2.4.49"), Equal);
        assert_eq!(cmp_version("10.11.06", "10.11.6"), Equal);
        assert_eq!(cmp_version("2.4.58", "2.4.6"), Greater);
    }

    #[test]
    fn rules_match_versions() {
        let r = CpeRule {
            vendor: "openbsd".into(),
            product: "openssh".into(),
            version: "*".into(),
            update: "*".into(),
            start_incl: Some("8.5p1".into()),
            end_excl: Some("9.8p1".into()),
            ..Default::default()
        };
        assert!(r.matches("openbsd", "openssh", "9.6", "p1"));
        assert!(r.matches("openbsd", "openssh", "8.5", "p1"));
        assert!(!r.matches("openbsd", "openssh", "9.8", "p1"));
        assert!(!r.matches("openbsd", "openssh", "8.4", "p1"));
        assert!(!r.matches("other", "openssh", "9.6", "p1"));
        let exact = CpeRule {
            vendor: "apache".into(),
            product: "http_server".into(),
            version: "2.4.49".into(),
            update: "*".into(),
            ..Default::default()
        };
        assert!(exact.matches("apache", "http_server", "2.4.49", "*"));
        assert!(!exact.matches("apache", "http_server", "2.4.50", "*"));
    }

    #[test]
    fn parses_configurations() {
        let v = json!({"totalResults": 1, "vulnerabilities": [{"cve": {
            "id": "CVE-2024-6387", "descriptions": [{"lang": "en", "value": "x"}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"},
                {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
                {"vulnerable": true, "criteria": "broken"}
            ]}]}]
        }}]});
        let (_, r) = parse_nvd(&v);
        assert_eq!(r[0].rules.len(), 1);
        assert!(r[0].rules[0].matches("openbsd", "openssh", "9.6", "p1"));
    }

    #[test]
    fn parses_epss() {
        let v = json!({"status":"OK","data":[
            {"cve":"CVE-2024-6387","epss":"0.385420000","percentile":"0.971730000","date":"2026-11-01"},
            {"cve":"CVE-2023-38408","epss":"bad","percentile":"0.5"}]});
        let e = parse_epss(&v);
        assert_eq!(e.len(), 1);
        assert!((e[0].1.probability - 0.38542).abs() < 1e-6);
    }

    #[test]
    fn helpers() {
        assert!(is_cve_id("CVE-2024-6387"));
        assert!(is_cve_id("CVE-2021-1234567"));
        assert!(!is_cve_id("CVE-24-1"));
        assert!(!is_cve_id("CVE-2024-63a7"));
        assert_eq!(percent_encode("cpe:2.3:a:x:y:1.0:*"), "cpe%3A2.3%3Aa%3Ax%3Ay%3A1.0%3A%2A");
    }
}
