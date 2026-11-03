//! Vulnerability reports: Excel workbook ([`xlsx`]) and PDF ([`pdf`]).
//!
//! Both are built from the same [`ReportData`], and both group findings the
//! way Nessus reports do: one entry per vulnerability, listing every affected
//! host, so a CVE present on 20 machines is described once.

pub mod pdf;
pub mod xlsx;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::vuln::detect::Service;
use crate::vuln::score::Severity;
use crate::vuln::{Finding, TopItem};

/// Everything a report shows.
pub struct ReportData<'a> {
    /// e.g. "2026-11-02 21:40 UTC"
    pub generated: String,
    pub targets: String,
    pub speed: String,
    pub duration_secs: f64,
    pub hosts: usize,
    /// Where CVE data came from, e.g. "NVD + FIRST EPSS (online)".
    pub cve_data: String,
    pub services: &'a [Service],
    pub findings: &'a [Finding],
    pub top10: &'a [TopItem],
    pub notes: &'a [String],
}

/// One vulnerability and every host:port it was found on.
pub struct Group<'a> {
    pub finding: &'a Finding,
    pub locations: Vec<(Ipv4Addr, u16)>,
}

impl ReportData<'_> {
    /// Findings grouped by id, most urgent first.
    pub fn groups(&self) -> Vec<Group<'_>> {
        let mut map: BTreeMap<&str, Group<'_>> = BTreeMap::new();
        for f in self.findings {
            let g = map.entry(&f.id).or_insert_with(|| Group { finding: f, locations: Vec::new() });
            g.locations.push((f.ip, f.port));
            if f.rank_cmp(g.finding).is_lt() {
                g.finding = f;
            }
        }
        let mut groups: Vec<Group<'_>> = map.into_values().collect();
        for g in &mut groups {
            g.locations.sort();
            g.locations.dedup();
        }
        groups.sort_by(|a, b| a.finding.rank_cmp(b.finding));
        groups
    }

    /// Number of findings (host × vulnerability) per severity.
    pub fn counts(&self) -> [(Severity, usize); 5] {
        Severity::ALL.map(|s| (s, self.findings.iter().filter(|f| f.severity == s).count()))
    }
}

/// How the scores are calculated (same text in both reports and the app).
pub const METHOD_NOTES: &[(&str, &str)] = &[
    (
        "CVSS v4.0",
        "Common Vulnerability Scoring System from FIRST: how severe a vulnerability is (0-10). NVD's v4.0 score \
         is used when published; otherwise v3.1, v3.0 or v2.0, as shown next to each score. Proton's own \
         configuration checks (PIS-xxxx) are scored with CVSS v4.0.",
    ),
    (
        "EPSS",
        "Exploit Prediction Scoring System from FIRST: the probability that the vulnerability will be exploited \
         in the wild in the next 30 days, with its percentile among all CVEs. Updated daily.",
    ),
    (
        "KEV",
        "Listed in CISA's Known Exploited Vulnerabilities catalog: attackers are known to use it. Fix these first.",
    ),
    (
        "PPR (VPR-style)",
        "Proton Priority Rating, 0-10. Tenable's VPR is proprietary and cannot be reproduced; PPR follows the same \
         idea with public data: 60% CVSS impact + 40% threat, where threat is 10 for KEV entries, otherwise \
         10 x sqrt(EPSS) (2.0 when no EPSS exists yet). The Top 10 is ordered by PPR.",
    ),
    (
        "Version-based matching",
        "CVEs are matched from the software version each service announces, like remote version checks in other \
         scanners. Linux distributions back-port fixes without changing version numbers; such findings say so \
         and should be confirmed with the installed package version.",
    ),
];
