//! Robustness tests: every parser that reads data from the network or the
//! internet is fed thousands of random and mutated inputs. None may panic
//! (a panic would close the app, since release builds use `panic = "abort"`).

use crate::scanner::Rng;
use crate::scanner::names::fuzz_entry as names_fuzz;
use crate::vuln::{detect, nvd};

/// Random bytes, with a bias towards small values and DNS-like structure.
fn random_bytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    let len = rng.between(0, max as u64) as usize;
    (0..len).map(|_| if rng.next().is_multiple_of(4) { (rng.next() % 16) as u8 } else { rng.next() as u8 }).collect()
}

#[test]
fn network_parsers_never_panic() {
    let mut rng = Rng(0xC0FFEE);
    for _ in 0..20_000 {
        let b = random_bytes(&mut rng, 600);
        names_fuzz(&b);
        let text = String::from_utf8_lossy(&b);
        let _ = detect::parse_ssh_banner(&text);
        let _ = detect::parse_ssh_banner(&format!("SSH-2.0-OpenSSH_{text}"));
        let _ = detect::parse_server_header(&text);
        let _ = detect::parse_server_header(&format!("Apache/{text} OpenSSL/{text}"));
        let _ = detect::parse_ftp_banner(&format!("220 ProFTPD {text}"));
        let _ = detect::parse_smtp_banner(&format!("220 x Exim {text}"));
        let _ = detect::parse_mysql_version(&text);
    }
}

#[test]
fn json_parsers_never_panic() {
    let mut rng = Rng(0xBEEF);
    let shapes = [
        r#"{"totalResults": 5, "vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 99}}]}}}]}"#,
        r#"{"vulnerabilities": [{"cve": {"id": 5, "descriptions": "x", "references": [{"url": 1}]}}]}"#,
        r#"{"vulnerabilities": "nope"}"#,
        r#"{"data": [{"cve": "CVE-2024-0001", "epss": "1e9", "percentile": "-4"}]}"#,
        r#"[]"#,
        r#"null"#,
    ];
    for s in shapes {
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        let (_, recs) = nvd::parse_nvd(&v);
        for r in recs {
            assert!(r.cvss.is_none_or(|c| (0.0..=10.0).contains(&c.score)), "score must be clamped");
        }
        for (_, e) in nvd::parse_epss(&v) {
            assert!((0.0..=1.0).contains(&e.probability) && (0.0..=1.0).contains(&e.percentile));
        }
    }
    for _ in 0..5_000 {
        let b = random_bytes(&mut rng, 300);
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
            let _ = nvd::parse_nvd(&v);
            let _ = nvd::parse_epss(&v);
        }
    }
}

#[test]
fn offline_database_import_never_panics() {
    use crate::vuln::offline::OfflineDb;
    let mut rng = Rng(0xD00D);
    for _ in 0..3_000 {
        let b = random_bytes(&mut rng, 400);
        let _ = OfflineDb::from_bytes(&b);
        // Valid gzip around random JSON-ish bytes reaches the JSON validator.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let _ = std::io::Write::write_all(&mut enc, &b);
        if let Ok(gz) = enc.finish() {
            let _ = OfflineDb::from_bytes(&gz);
        }
    }
    // Structurally valid pack with wrong types everywhere.
    let doc = r#"{"format":"proton-vulndb","version":1,"created":1,"cves":[{"id":"CVE-2024-1234","m":[[1,2,3],"x",[null]],"cv":"no","e":{"a":1},"r":[5]}]}"#;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut enc, doc.as_bytes()).unwrap();
    let db = OfflineDb::from_bytes(&enc.finish().unwrap()).unwrap();
    assert!(db.cves[0].rules.is_empty() && db.cves[0].cvss.is_none());
}
