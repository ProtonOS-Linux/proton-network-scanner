//! Offline vulnerability database ("pack"), for computers without internet.
//!
//! **How it works**
//! 1. On a computer with internet, *Database → Download / update* asks NVD for
//!    every CVE of every product the scanner can recognise (OpenSSH, Apache,
//!    nginx, OpenSSL, MySQL, Redis… — see [`PRODUCTS`]), all versions, with the
//!    exact version ranges each CVE affects, plus EPSS scores from FIRST and the
//!    CISA KEV flag. That is a few thousand CVEs, about 1–3 MB compressed.
//! 2. The pack is installed in the user's data folder and can be **exported**
//!    to a file (`proton-vulndb-YYYYMMDD-HHMMSS.json.gz`), copied to the
//!    offline computer (USB stick, file share) and **imported** there.
//! 3. When the scan's CVE source is *Offline database* — or *Online* but NVD
//!    cannot be reached — detected versions are matched against the pack's
//!    version ranges locally ([`super::nvd::CpeRule::matches`]). Nothing is
//!    sent anywhere.
//!
//! Update the pack regularly (weekly is a good habit): new CVEs appear daily,
//! and EPSS scores change every day.
//!
//! Security: an imported pack may come from anywhere, so it is treated as
//! untrusted input — size-limited (32 MB compressed, 256 MB unpacked), parsed
//! with `serde_json`, and every field is validated exactly like data from NVD
//! (CVE id format, scores clamped, text cleaned and capped, only http(s)
//! links). The installed copy is written atomically (new file + rename).

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::detect::clean;
use super::nvd::{CpeRule, CveRecord, VulnDb, is_cve_id};
use super::score::{Cvss, Epss};

/// Every (NVD vendor, NVD product) the service detector can report.
pub const PRODUCTS: &[(&str, &str)] = &[
    ("openbsd", "openssh"),
    ("dropbear_ssh_project", "dropbear_ssh"),
    ("apache", "http_server"),
    ("f5", "nginx"),
    ("nginx", "nginx"),
    ("lighttpd", "lighttpd"),
    ("microsoft", "internet_information_services"),
    ("openssl", "openssl"),
    ("php", "php"),
    ("webmin", "webmin"),
    ("eclipse", "jetty"),
    ("openresty", "openresty"),
    ("gunicorn", "gunicorn"),
    ("palletsprojects", "werkzeug"),
    ("beasts", "vsftpd"),
    ("proftpd", "proftpd"),
    ("filezilla-project", "filezilla_server"),
    ("exim", "exim"),
    ("sendmail", "sendmail"),
    ("mariadb", "mariadb"),
    ("oracle", "mysql"),
    ("redis", "redis"),
    ("memcached", "memcached"),
    ("elastic", "elasticsearch"),
    ("mobyproject", "moby"),
];

/// NVD lists some products under two vendors over time (nginx moved to F5).
pub fn aliases(vendor: &str, product: &str) -> Vec<(String, String)> {
    let mut v = vec![(vendor.to_string(), product.to_string())];
    if (vendor, product) == ("f5", "nginx") {
        v.push(("nginx".into(), "nginx".into()));
    }
    v
}

const FORMAT: &str = "proton-vulndb";
const MAX_PACKED: u64 = 32 * 1024 * 1024;
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;

/// A loaded offline database.
pub struct OfflineDb {
    /// When it was downloaded (Unix seconds).
    pub created: u64,
    pub cves: Vec<CveRecord>,
}

/// Short description of the installed database (kept in a small side file,
/// so the app can show it without loading the whole pack).
#[derive(Clone, Debug, PartialEq)]
pub struct DbInfo {
    pub created: u64,
    pub cves: usize,
}

impl DbInfo {
    pub fn label(&self) -> String {
        format!("{} CVEs, updated {}", self.cves, date(self.created))
    }
    /// Hours since the database was downloaded.
    pub fn age_hours(&self) -> u64 {
        now().saturating_sub(self.created) / 3_600
    }
    /// Days since the database was downloaded.
    pub fn age_days(&self) -> u64 {
        now().saturating_sub(self.created) / 86_400
    }
}

fn data_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("proton-ip-scanner"))
}

fn installed_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("vulndb.json.gz"))
}

fn info_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("vulndb-info.json"))
}

/// Information about the installed database, if there is one.
pub fn installed_info() -> Option<DbInfo> {
    let v: Value = serde_json::from_slice(&fs::read(info_path()?).ok()?).ok()?;
    Some(DbInfo { created: v["created"].as_u64()?, cves: v["cves"].as_u64()? as usize })
}

impl OfflineDb {
    /// Load the installed database (`Ok(None)` if none is installed).
    pub fn load_installed() -> Result<Option<OfflineDb>, String> {
        let Some(p) = installed_path().filter(|p| p.exists()) else { return Ok(None) };
        OfflineDb::load_file(&p).map(Some)
    }

    /// Load and validate a pack file (installed or to be imported).
    pub fn load_file(path: &Path) -> Result<OfflineDb, String> {
        let meta = fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if meta.len() > MAX_PACKED {
            return Err("the file is too large to be a Proton vulnerability database".into());
        }
        let packed = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        OfflineDb::from_bytes(&packed)
    }

    pub fn from_bytes(packed: &[u8]) -> Result<OfflineDb, String> {
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(packed)
            .take(MAX_UNPACKED)
            .read_to_end(&mut json)
            .map_err(|_| "not a Proton vulnerability database (bad gzip data)".to_string())?;
        let v: Value =
            serde_json::from_slice(&json).map_err(|_| "the database file is damaged (bad JSON)".to_string())?;
        if v["format"] != FORMAT || v["version"] != 1 {
            return Err("not a Proton vulnerability database (wrong format)".into());
        }
        let created = v["created"].as_u64().ok_or("the database has no creation date")?;
        let cves: Vec<CveRecord> = v["cves"].as_array().into_iter().flatten().filter_map(record_from_json).collect();
        if cves.is_empty() {
            return Err("the database contains no CVEs".into());
        }
        Ok(OfflineDb { created, cves })
    }

    /// Compressed pack bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let doc = json!({
            "format": FORMAT,
            "version": 1,
            "created": self.created,
            "generator": concat!("Proton IP Scanner ", env!("CARGO_PKG_VERSION")),
            "cves": self.cves.iter().map(record_to_json).collect::<Vec<_>>(),
        });
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let _ = std::io::Write::write_all(&mut enc, doc.to_string().as_bytes());
        enc.finish().unwrap_or_default()
    }

    pub fn info(&self) -> DbInfo {
        DbInfo { created: self.created, cves: self.cves.len() }
    }

    /// Make this the installed database (atomic replace).
    pub fn install(&self) -> Result<DbInfo, String> {
        let dir = data_dir().ok_or("no data folder for this user")?;
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let bytes = self.to_bytes();
        write_atomic(&dir.join("vulndb.json.gz"), &bytes)?;
        let info = self.info();
        write_atomic(
            &dir.join("vulndb-info.json"),
            json!({"created": info.created, "cves": info.cves}).to_string().as_bytes(),
        )?;
        Ok(info)
    }

    /// A CVE by id, if the database has it.
    pub fn by_id(&self, id: &str) -> Option<CveRecord> {
        self.cves.iter().find(|c| c.id == id).cloned()
    }

    /// CVEs whose version rules cover this product CPE
    /// (`cpe:2.3:a:vendor:product:version:update:…`).
    pub fn lookup(&self, cpe: &str) -> Vec<CveRecord> {
        let p: Vec<&str> = cpe.split(':').collect();
        let (Some(v), Some(pr), Some(ver), Some(upd)) = (p.get(3), p.get(4), p.get(5), p.get(6)) else { return vec![] };
        let names = aliases(v, pr);
        self.cves
            .iter()
            .filter(|c| c.rules.iter().any(|r| names.iter().any(|(nv, np)| r.matches(nv, np, ver, upd))))
            .cloned()
            .collect()
    }
}

/// Delete the installed database.
pub fn uninstall() {
    for p in [installed_path(), info_path()].into_iter().flatten() {
        let _ = fs::remove_file(p);
    }
}

/// Download a fresh database from NVD + FIRST. `progress(done, total, label)`
/// is called before each product. Takes ~3 minutes without an NVD API key
/// (NVD's rate limit), well under a minute with one.
pub fn build(
    api_key: Option<String>,
    cancel: &AtomicBool,
    progress: &dyn Fn(usize, usize, &str),
) -> Result<OfflineDb, String> {
    let mut db = VulnDb::new(api_key);
    let mut by_id: HashMap<String, CveRecord> = HashMap::new();
    let total = PRODUCTS.len() + 1;
    for (i, (vendor, product)) in PRODUCTS.iter().enumerate() {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("stopped".into());
        }
        progress(i, total, &format!("NVD: {vendor} {product}"));
        for r in db.cves_for_product(vendor, product, cancel)? {
            // Keep only the rules that concern products we can detect.
            let rules: Vec<CpeRule> = r
                .rules
                .iter()
                .filter(|x| PRODUCTS.iter().any(|(v, p)| x.vendor == *v && x.product == *p))
                .cloned()
                .collect();
            if rules.is_empty() {
                continue;
            }
            let entry = by_id.entry(r.id.clone()).or_insert_with(|| CveRecord { rules: Vec::new(), ..r.clone() });
            for rule in rules {
                if !entry.rules.contains(&rule) {
                    entry.rules.push(rule);
                }
            }
        }
    }
    progress(PRODUCTS.len(), total, "FIRST: EPSS scores");
    let mut ids: Vec<String> = by_id.keys().cloned().collect();
    ids.sort();
    let epss = db.epss(&ids, cancel)?;
    let mut cves: Vec<CveRecord> = by_id.into_values().collect();
    for c in &mut cves {
        c.epss = epss.get(&c.id).copied();
    }
    cves.sort_by(|a, b| a.id.cmp(&b.id));
    if cves.is_empty() {
        return Err("NVD returned no CVEs".into());
    }
    Ok(OfflineDb { created: now(), cves })
}

/// Pack files the user may want to import: `proton-vulndb-*.json.gz` in the
/// Documents and Downloads folders, newest first.
pub fn import_candidates() -> Vec<PathBuf> {
    let mut out: Vec<(SystemTime, PathBuf)> = Vec::new();
    for dir in [dirs::document_dir(), dirs::download_dir(), dirs::home_dir()].into_iter().flatten() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("proton-vulndb")
                && name.ends_with(".json.gz")
                && e.file_type().is_ok_and(|t| t.is_file())
            {
                let t = e.metadata().and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
                out.push((t, e.path()));
            }
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.0));
    out.dedup_by(|a, b| a.1 == b.1);
    out.into_iter().map(|(_, p)| p).take(20).collect()
}

/// Copy the installed database to the Documents folder for another computer.
pub fn export_installed() -> Result<PathBuf, String> {
    let p = installed_path().filter(|p| p.exists()).ok_or("no offline database is installed yet")?;
    let bytes = fs::read(p).map_err(|e| e.to_string())?;
    crate::export::save_bytes("proton-vulndb", "json.gz", &bytes).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Serialisation (compact field names keep the file small)
// ---------------------------------------------------------------------------

fn record_to_json(c: &CveRecord) -> Value {
    json!({
        "id": c.id, "d": c.description, "kev": c.kev, "p": c.published, "r": c.references, "s": c.solution,
        "cv": c.cvss.as_ref().map(|x| json!([x.version, x.score, x.vector])),
        "e": c.epss.map(|e| json!([e.probability, e.percentile])),
        "m": c.rules.iter().map(|r| json!([r.vendor, r.product, r.version, r.update, r.start_incl, r.start_excl, r.end_incl, r.end_excl])).collect::<Vec<_>>(),
    })
}

/// Parse one record from a pack, validating every field (packs are untrusted).
fn record_from_json(c: &Value) -> Option<CveRecord> {
    let id = c["id"].as_str().filter(|s| is_cve_id(s))?;
    let text = |k: &str, max: usize| c[k].as_str().map(|s| clean(s, max));
    let cvss = c["cv"].as_array().and_then(|a| {
        Some(Cvss {
            version: clean(a.first()?.as_str()?, 4),
            score: (a.get(1)?.as_f64()? as f32).clamp(0.0, 10.0),
            vector: clean(a.get(2)?.as_str()?, 200),
        })
    });
    let epss = c["e"].as_array().and_then(|a| {
        Some(Epss {
            probability: (a.first()?.as_f64()? as f32).clamp(0.0, 1.0),
            percentile: (a.get(1)?.as_f64()? as f32).clamp(0.0, 1.0),
        })
    });
    let rules = c["m"]
        .as_array()
        .into_iter()
        .flatten()
        .take(2_000)
        .filter_map(|m| {
            let a = m.as_array()?;
            let s = |i: usize| a.get(i).and_then(|v| v.as_str()).map(|v| clean(v, 40));
            Some(CpeRule {
                vendor: s(0)?,
                product: s(1)?,
                version: s(2)?,
                update: s(3)?,
                start_incl: s(4),
                start_excl: s(5),
                end_incl: s(6),
                end_excl: s(7),
            })
        })
        .collect();
    Some(CveRecord {
        id: id.into(),
        description: text("d", 2_000).unwrap_or_default(),
        cvss,
        kev: c["kev"].as_bool().unwrap_or(false),
        published: text("p", 10),
        references: c["r"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|u| u.as_str())
            .filter(|u| (u.starts_with("https://") || u.starts_with("http://")) && u.len() <= 300)
            .take(5)
            .map(|u| clean(u, 300))
            .collect(),
        solution: text("s", 500),
        rules,
        epss,
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let res = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
        .and_then(|_| fs::rename(&tmp, path));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(|e| format!("could not save the database: {e}"))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Unix seconds → "2026-11-03".
pub fn date(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{m:02}-{d:02}", yoe + era * 400 + i64::from(m <= 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OfflineDb {
        let rule = |v: &str, p: &str, end: &str| CpeRule {
            vendor: v.into(),
            product: p.into(),
            version: "*".into(),
            update: "*".into(),
            end_excl: Some(end.into()),
            ..Default::default()
        };
        let rec = |id: &str, rules: Vec<CpeRule>| CveRecord {
            id: id.into(),
            description: "test".into(),
            cvss: Some(Cvss { version: "3.1".into(), score: 8.1, vector: "CVSS:3.1/AV:N".into() }),
            kev: id.ends_with('1'),
            published: Some("2024-07-01".into()),
            references: vec!["https://example.com/a".into()],
            solution: None,
            rules,
            epss: Some(Epss { probability: 0.4, percentile: 0.97 }),
        };
        OfflineDb {
            created: 1_793_419_506,
            cves: vec![
                rec("CVE-2024-0001", vec![rule("openbsd", "openssh", "9.8p1")]),
                rec("CVE-2024-0002", vec![rule("nginx", "nginx", "1.20.1")]),
                rec("CVE-2024-0003", vec![rule("apache", "http_server", "2.4.50")]),
            ],
        }
    }

    #[test]
    fn roundtrip_and_lookup() {
        let db = OfflineDb::from_bytes(&sample().to_bytes()).unwrap();
        assert_eq!(db.cves.len(), 3);
        assert_eq!(db.cves[0], sample().cves[0]);
        let hits = db.lookup("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*");
        assert_eq!(hits.len(), 1);
        assert!(db.lookup("cpe:2.3:a:openbsd:openssh:9.9:p1:*:*:*:*:*:*").is_empty());
        // nginx detected as f5:nginx still matches CVEs filed under nginx:nginx.
        assert_eq!(db.lookup("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*").len(), 1);
        assert!(db.lookup("garbage").is_empty());
    }

    #[test]
    fn hostile_packs_are_rejected_or_cleaned() {
        assert!(OfflineDb::from_bytes(b"not gzip").is_err());
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, br#"{"format":"other","version":1,"created":1,"cves":[]}"#).unwrap();
        assert!(OfflineDb::from_bytes(&enc.finish().unwrap()).is_err());
        let evil = json!({"format": FORMAT, "version": 1, "created": 5, "cves": [
            {"id": "CVE-2024-0009", "d": "x\u{1b}[31m", "cv": ["3.1", 99.0, "v"], "e": [7.0, -1.0], "r": ["javascript:alert(1)", "https://ok.example"], "m": [["a","b","*","*",null,null,null,"2"]]},
            {"id": "../../etc/passwd"}
        ]});
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, evil.to_string().as_bytes()).unwrap();
        let db = OfflineDb::from_bytes(&enc.finish().unwrap()).unwrap();
        assert_eq!(db.cves.len(), 1);
        let c = &db.cves[0];
        assert_eq!(c.cvss.as_ref().unwrap().score, 10.0);
        assert_eq!(c.epss.unwrap().probability, 1.0);
        assert_eq!(c.references, vec!["https://ok.example".to_string()]);
        assert!(!c.description.contains('\u{1b}'));
    }

    /// Writes a small sample pack when `PROTON_PACK_OUT` is set (used to test
    /// `--import-db` and offline scans end to end).
    #[test]
    fn write_sample_pack() {
        if let Ok(path) = std::env::var("PROTON_PACK_OUT") {
            std::fs::write(path, sample().to_bytes()).unwrap();
        }
    }

    #[test]
    fn dates() {
        assert_eq!(date(1_793_419_506), "2026-10-31");
        assert_eq!(date(0), "1970-01-01");
    }
}
