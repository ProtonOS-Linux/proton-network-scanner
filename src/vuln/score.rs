//! Severity, CVSS and the priority rating.
//!
//! ## Severity
//! From the CVSS base score, using the bands of CVSS v4.0 (the same as v3.x):
//! None/Info 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0.
//!
//! ## PPR — Proton Priority Rating (VPR-style)
//! Tenable's **VPR** (Vulnerability Priority Rating) is proprietary: its
//! inputs and model are not public, so no other tool can compute real VPR
//! scores. PPR follows the same *idea* with public data only — rank by how
//! likely something is to be exploited *now*, not only by how bad it would be:
//!
//! ```text
//! impact  = CVSS base score (v4.0 if available, else v3.1 / v3.0 / v2)
//! threat  = 10                 if listed in CISA KEV (known exploited)
//!         = 10 × √EPSS         otherwise, when an EPSS score exists
//!         = 2.0                when nothing is known (CVE without EPSS yet)
//!         = per-check value    for Proton's own configuration checks
//! PPR     = 0.6 × impact + 0.4 × threat      (0.0 when impact is 0)
//! ```
//!
//! √EPSS spreads the very skewed EPSS distribution: EPSS 1 % → threat 1.0,
//! 10 % → 3.2, 50 % → 7.1, 90 % → 9.5. A CVSS 9.8 bug nobody exploits
//! (EPSS 0.1 %) gets PPR ≈ 6.0, while a CVSS 7.5 bug in KEV gets 8.5.

/// Severity bands (sorted from worst to least).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub const ALL: [Severity; 5] =
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];

    pub fn from_score(score: f32) -> Severity {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    /// Colour used in the app and in reports (RGB).
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Severity::Critical => (185, 28, 28),
            Severity::High => (234, 88, 12),
            Severity::Medium => (202, 138, 4),
            Severity::Low => (37, 99, 235),
            Severity::Info => (107, 114, 128),
        }
    }
}

/// A CVSS base score as published.
#[derive(Clone, Debug, PartialEq)]
pub struct Cvss {
    /// "4.0", "3.1", "3.0" or "2.0".
    pub version: String,
    pub score: f32,
    pub vector: String,
}

/// EPSS: probability (0–1) of exploitation activity in the next 30 days,
/// and the percentile among all CVEs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Epss {
    pub probability: f32,
    pub percentile: f32,
}

/// Threat component of PPR for a CVE.
pub fn cve_threat(kev: bool, epss: Option<Epss>) -> f32 {
    if kev {
        10.0
    } else if let Some(e) = epss {
        10.0 * e.probability.clamp(0.0, 1.0).sqrt()
    } else {
        2.0
    }
}

/// Proton Priority Rating, rounded to one decimal.
pub fn ppr(impact: f32, threat: f32) -> f32 {
    if impact <= 0.0 {
        return 0.0;
    }
    let v = 0.6 * impact.clamp(0.0, 10.0) + 0.4 * threat.clamp(0.0, 10.0);
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands() {
        assert_eq!(Severity::from_score(9.3), Severity::Critical);
        assert_eq!(Severity::from_score(7.0), Severity::High);
        assert_eq!(Severity::from_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_score(0.1), Severity::Low);
        assert_eq!(Severity::from_score(0.0), Severity::Info);
    }

    #[test]
    fn priority_examples_from_docs() {
        let low_epss = Epss { probability: 0.001, percentile: 0.3 };
        assert_eq!(ppr(9.8, cve_threat(false, Some(low_epss))), 6.0);
        assert_eq!(ppr(7.5, cve_threat(true, None)), 8.5);
        assert_eq!(ppr(0.0, 10.0), 0.0);
        assert!((cve_threat(false, Some(Epss { probability: 0.5, percentile: 0.9 })) - 7.07).abs() < 0.01);
    }
}
