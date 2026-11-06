//! Vulnerability assessment ("Vulnerability Scanner" tab).
//!
//! A scan runs in four phases on one background thread (plus small worker
//! pools), reporting through a channel like the network scanner:
//!
//! 1. **Find live hosts** in the target range (skipped when the targets come
//!    from the Network Scanner tab).
//! 2. **Port scan** the live hosts.
//! 3. **Identify services** on every open port and run Proton's safe
//!    configuration checks ([`detect`], [`checks`]).
//! 4. **Look up known vulnerabilities** for each detected product version in
//!    NVD, then add EPSS scores and compute the priority rating ([`nvd`],
//!    [`score`]).
//!
//! Like Nessus' "remote version checks", CVE matches are based on the version
//! a service announces. They are reliable for software installed from the
//! vendor, but Linux distributions back-port fixes without changing the
//! version, so such findings are flagged for manual confirmation.
//!
//! All pacing (workers, pauses, shuffled order) follows the chosen
//! [`Speed`], so "Slow / stealthy" applies to every phase that touches the
//! scanned devices.

pub mod checks;
pub mod detect;
pub mod nse;
pub mod nvd;
pub mod offline;
pub mod score;

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::scanner::{self, Event, LocalNet, Settings, Speed};
use detect::{ProbeCtx, Service};
use score::{Cvss, Epss, Severity};

/// One problem found on one host/port.
#[derive(Clone, Debug)]
pub struct Finding {
    /// `CVE-…` or a Proton check id `PIS-…`.
    pub id: String,
    pub title: String,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub service: String,
    /// Affected software, e.g. "OpenSSH 8.9p1".
    pub product: Option<String>,
    pub severity: Severity,
    pub cvss: Option<Cvss>,
    pub epss: Option<Epss>,
    /// In CISA's Known Exploited Vulnerabilities catalog.
    pub kev: bool,
    /// Proton Priority Rating (VPR-style), 0–10.
    pub ppr: f32,
    pub description: String,
    pub solution: String,
    /// What we saw that triggered the finding.
    pub evidence: String,
    pub references: Vec<String>,
    pub published: Option<String>,
    /// How sure the scanner is that this finding is real.
    pub confidence: Confidence,
    /// Ticked by the user in the details panel once the finding was looked at.
    pub reviewed: bool,
    /// The user's note about this finding (see [`clean_comment`]).
    pub comment: String,
}

/// Longest comment kept per finding.
pub const MAX_COMMENT: usize = 2_000;

/// Make user-typed comment text safe to keep and print: control characters
/// removed (line breaks and tabs kept), length capped at [`MAX_COMMENT`].
/// The PDF and Excel writers escape it again when writing.
pub fn clean_comment(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(MAX_COMMENT)
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// How a finding was established — shown next to every finding so false
/// positives are easy to spot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Confidence {
    /// Observed directly: a configuration check, or an Nmap script that
    /// tested for the vulnerability.
    #[default]
    Confirmed,
    /// The service announced an exact version inside a vulnerable range.
    VersionMatch,
    /// Version match on a Linux distribution build: distributions back-port
    /// fixes without changing the version, so it may already be fixed.
    Backported,
    /// Only an approximate version is known ("Samba 4"): the CVE could apply
    /// or not — check manually.
    Unverified,
}

impl Confidence {
    /// Name shown in the UI and reports.
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Confirmed => "Confirmed",
            Confidence::VersionMatch => "Version match",
            Confidence::Backported => "May be backported",
            Confidence::Unverified => "Unverified",
        }
    }

    /// One-line explanation (tooltips, reports).
    pub fn help(self) -> &'static str {
        match self {
            Confidence::Confirmed => "Seen directly: a configuration check, or an Nmap script that tested for it.",
            Confidence::VersionMatch => {
                "The service announced an exact version that NVD lists as vulnerable. Very likely real."
            }
            Confidence::Backported => {
                "Version match on a Linux distribution build. Distributions fix security bugs without changing the \
                 version number, so check the installed package version."
            }
            Confidence::Unverified => {
                "Only an approximate version is visible from the network, so this could not be confirmed. It may \
                 be a false positive: check the installed version on the device."
            }
        }
    }
}

impl Finding {
    /// Is this finding a CVE (id like CVE-2024-1234)?
    pub fn is_cve(&self) -> bool {
        self.id.starts_with("CVE-")
    }

    /// Order used everywhere: priority, then severity, then CVSS, then id.
    pub fn rank_cmp(&self, other: &Finding) -> std::cmp::Ordering {
        other
            .ppr
            .total_cmp(&self.ppr)
            .then(self.severity.cmp(&other.severity))
            .then(other.cvss_score().total_cmp(&self.cvss_score()))
            .then(self.id.cmp(&other.id))
            .then(self.ip.cmp(&other.ip))
    }

    /// CVSS base score, or 0 when not scored.
    pub fn cvss_score(&self) -> f32 {
        self.cvss.as_ref().map(|c| c.score).unwrap_or(0.0)
    }
}

/// One row of the "Top 10" list: a vulnerability and how many hosts have it.
#[derive(Clone, Debug)]
pub struct TopItem {
    pub finding: Finding,
    pub hosts: usize,
}

/// The 10 most urgent distinct vulnerabilities (Info findings excluded).
pub fn top10(findings: &[Finding]) -> Vec<TopItem> {
    let mut by_id: BTreeMap<&str, (Finding, std::collections::BTreeSet<Ipv4Addr>)> = BTreeMap::new();
    // Top 10 = real priorities: no Info, no "needs manual check" items.
    for f in findings
        .iter()
        .filter(|f| !matches!(f.severity, Severity::Info | Severity::Review) && f.confidence != Confidence::Unverified)
    {
        let e = by_id.entry(&f.id).or_insert_with(|| (f.clone(), Default::default()));
        e.1.insert(f.ip);
        if f.rank_cmp(&e.0).is_lt() {
            e.0 = f.clone();
        }
    }
    let mut items: Vec<TopItem> =
        by_id.into_values().map(|(finding, hosts)| TopItem { finding, hosts: hosts.len() }).collect();
    items.sort_by(|a, b| a.finding.rank_cmp(&b.finding).then(b.hosts.cmp(&a.hosts)));
    items.truncate(10);
    items
}

/// Where known-vulnerability (CVE) data comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CveSource {
    /// Ask NVD and FIRST during the scan (newest data). Falls back to the
    /// offline database automatically if they cannot be reached.
    #[default]
    Online,
    /// Use the downloaded offline database only — nothing is sent anywhere.
    Offline,
    /// No CVE matching: configuration checks only.
    Off,
}

impl CveSource {
    /// Every source, in menu order.
    pub const ALL: [CveSource; 3] = [CveSource::Online, CveSource::Offline, CveSource::Off];
    /// Name shown in menus and reports.
    pub fn label(self) -> &'static str {
        match self {
            CveSource::Online => "Online (NVD, newest)",
            CveSource::Offline => "Offline database",
            CveSource::Off => "Off (config checks only)",
        }
    }
}

/// Report text for a CVE source.
pub fn cve_data_label(source: CveSource) -> String {
    match source {
        CveSource::Online => "NVD (CVSS, CISA KEV) and FIRST EPSS, looked up online during the scan".into(),
        CveSource::Offline => match offline::installed_info() {
            Some(i) => format!("Offline database ({})", i.label()),
            None => "Offline database (not installed)".into(),
        },
        CveSource::Off => "None - configuration checks only".into(),
    }
}

/// Which engine identifies services.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Engine {
    /// Proton's own probes (always available).
    #[default]
    Builtin,
    /// Nmap's version detection and safe NSE scripts, plus Proton's checks.
    Nmap,
}

impl Engine {
    /// Name of the engine shown in menus ("Built-in" / "Nmap").
    pub fn label(self) -> &'static str {
        match self {
            Engine::Builtin => "Built-in",
            Engine::Nmap => "Nmap",
        }
    }
}

/// "Normal · Nmap 7.94SVN (deep)" for reports.
pub fn engine_label(speed: Speed, engine: Engine, deep: bool) -> String {
    match (engine, crate::nmap::find()) {
        (Engine::Nmap, Some(n)) => {
            format!("{} · {}{}", speed.label(), n.label(), if deep { " (deep scan)" } else { "" })
        }
        _ => format!("{} · built-in engine", speed.label()),
    }
}

/// Options chosen in the Vulnerability Scanner tab.
#[derive(Clone, Debug)]
pub struct VulnOptions {
    pub targets: Vec<Ipv4Addr>,
    /// Ping-sweep the targets first (false when they are known live devices).
    pub discover_first: bool,
    pub ports: Vec<u16>,
    pub speed: Speed,
    pub port_timeout_ms: u64,
    /// Where CVE data comes from.
    pub cve_source: CveSource,
    /// Try documented anonymous access (FTP, MQTT).
    pub safe_logins: bool,
    pub nvd_api_key: Option<String>,
    pub nets: Vec<LocalNet>,
    pub engine: Engine,
    /// List every CVE that *could* apply to software with an approximate
    /// version as its own (Unverified) finding, instead of one "needs manual
    /// check" finding per service ("paranoid" mode).
    pub show_unverified: bool,
    /// Nmap only: SYN scan + OS detection (asks for admin rights on Linux,
    /// for this one run).
    pub deep: bool,
}

/// Scan phases, shown in the status bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Discovery = 0,
    Ports = 1,
    Services = 2,
    Lookup = 3,
    Done = 4,
}

impl Phase {
    /// Phase from its stored number (anything unknown = Done).
    fn from_u8(v: u8) -> Phase {
        match v {
            0 => Phase::Discovery,
            1 => Phase::Ports,
            2 => Phase::Services,
            3 => Phase::Lookup,
            _ => Phase::Done,
        }
    }

    /// Text shown in the status bar for this phase.
    pub fn label(self) -> &'static str {
        match self {
            Phase::Discovery => "1/4 Finding live hosts",
            Phase::Ports => "2/4 Scanning ports",
            Phase::Services => "3/4 Identifying services and checking configuration",
            Phase::Lookup => "4/4 Looking up known vulnerabilities",
            Phase::Done => "Done",
        }
    }
}

/// Progress counters shared with the UI (read every frame, lock-free except
/// the short detail text).
#[derive(Default)]
pub struct Progress {
    phase: AtomicU8,
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    detail: Mutex<String>,
}

impl Progress {
    /// Current phase.
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }
    /// Extra detail for the status bar (e.g. which product is being looked up).
    pub fn detail(&self) -> String {
        self.detail.lock().map(|d| d.clone()).unwrap_or_default()
    }
    /// Enter a phase that has `total` steps.
    fn set(&self, phase: Phase, total: usize) {
        self.phase.store(phase as u8, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
        self.set_detail("");
    }
    /// Set the status-bar detail text.
    fn set_detail(&self, s: &str) {
        if let Ok(mut d) = self.detail.lock() {
            *d = s.to_string();
        }
    }
}

/// Messages from a running assessment.
pub enum VulnEvent {
    /// A live host is being assessed.
    Host,
    Service(Box<Service>),
    Finding(Box<Finding>),
    /// Something the user should know (e.g. "NVD unreachable").
    Note(String),
    Finished,
}

/// A running (or finished) assessment.
pub struct VulnJob {
    cancel: Arc<AtomicBool>,
    pub progress: Arc<Progress>,
    pub rx: Receiver<VulnEvent>,
    pub started: Instant,
    pub finished_at: Option<Instant>,
}

impl VulnJob {
    /// Ask the assessment to stop.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    /// Has Stop been pressed?
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    /// Time since the assessment started.
    pub fn elapsed(&self) -> Duration {
        self.finished_at.unwrap_or_else(Instant::now) - self.started
    }
}

/// Start an assessment in the background.
pub fn start(opts: VulnOptions) -> VulnJob {
    let cancel = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(Progress::default());
    let (tx, rx) = mpsc::channel();
    let (c, p, t) = (cancel.clone(), progress.clone(), tx.clone());
    let spawned = std::thread::Builder::new().name("vuln-scan".into()).spawn(move || {
        run(&opts, &t, &p, &c);
        p.set(Phase::Done, 0);
        let _ = t.send(VulnEvent::Finished);
    });
    if spawned.is_err() {
        let _ = tx.send(VulnEvent::Note("Could not start the scan (the system refused a new thread).".into()));
        let _ = tx.send(VulnEvent::Finished);
    }
    VulnJob { cancel, progress, rx, started: Instant::now(), finished_at: None }
}

/// The whole assessment, on its own thread: discovery → ports → services and
/// configuration checks (Proton and/or Nmap) → CVE lookups. Results are sent on `tx`.
fn run(opts: &VulnOptions, tx: &Sender<VulnEvent>, progress: &Progress, cancel: &AtomicBool) {
    let settings = Settings {
        speed: opts.speed,
        port_timeout_ms: opts.port_timeout_ms,
        grab_banners: false,
        // Names are not needed here; the Network Scanner tab provides them.
        resolve_dns: false,
        netbios: false,
        multicast_names: false,
        ..Settings::default()
    };

    // ---- Phase 1: live hosts -------------------------------------------
    let live: Vec<Ipv4Addr> = if opts.discover_first {
        progress.set(Phase::Discovery, opts.targets.len());
        let job = scanner::start_discovery(opts.targets.clone(), &settings, opts.nets.clone());
        let mut live = Vec::new();
        follow(&job, progress, cancel, |ev| {
            if let Event::Host(h) = ev {
                live.push(h.ip);
                let _ = tx.send(VulnEvent::Host);
            }
        });
        live
    } else {
        for _ in &opts.targets {
            let _ = tx.send(VulnEvent::Host);
        }
        opts.targets.clone()
    };
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    if live.is_empty() {
        let _ = tx.send(VulnEvent::Note("No live hosts found in the target range.".into()));
        return;
    }

    // ---- Phase 2: open ports -------------------------------------------
    // A deep Nmap scan does its own (SYN) port scan in phase 3.
    let use_nmap = opts.engine == Engine::Nmap;
    let deep = use_nmap && opts.deep;
    let mut open: Vec<(Ipv4Addr, u16)> = Vec::new();
    if !deep && !builtin_port_scan(&live, opts, &settings, tx, progress, cancel, &mut open) {
        return;
    }
    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // ---- Phase 3a: Nmap (optional) -------------------------------------
    let mut nm = NmapResults::default();
    if use_nmap {
        let ok = run_nmap(&live, &open, opts, deep, progress, cancel, tx, &mut nm);
        if deep {
            open = nm.ports.keys().copied().collect();
            if !ok && !cancel.load(Ordering::Relaxed) {
                // Nmap failed: fall back to the built-in port scan.
                if !builtin_port_scan(&live, opts, &settings, tx, progress, cancel, &mut open) {
                    return;
                }
            }
        }
    }
    open.sort();
    open.dedup();
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    if open.is_empty() {
        let _ =
            tx.send(VulnEvent::Note("No open ports found on the live hosts, so there was nothing to assess.".into()));
        return;
    }

    // ---- Phase 3b: services + configuration checks ---------------------
    progress.set(Phase::Services, open.len());
    let ctx = ProbeCtx::new(Duration::from_millis(opts.port_timeout_ms.clamp(300, 5_000)), opts.safe_logins);
    let services: Mutex<Vec<Service>> = Mutex::new(Vec::new());
    let script_cves: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let workers = match opts.speed {
        Speed::Normal => 16,
        Speed::Polite => 4,
        Speed::Slow => 1,
    };
    // Host-level Nmap results (SMB security mode, OS) go with one port per host.
    let mut anchor: HashMap<Ipv4Addr, u16> = HashMap::new();
    for &(ip, port) in &open {
        let a = anchor.entry(ip).or_insert(port);
        if port == 445 || (port == 139 && *a != 445) {
            *a = port;
        }
    }
    let today = offline::date(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    );
    run_paced(open.len(), workers, opts.speed, cancel, |i| {
        let Some(&(ip, port)) = open.get(i) else { return };
        let (mut svc, mut findings) = detect::probe(ip, port, &ctx);
        let mut confirmed = Vec::new();
        if let Some(np) = nm.ports.get(&(ip, port)) {
            nse::merge(&mut svc, np);
            let (done, cves) = nse::findings(ip, port, &svc.name, &np.scripts, &today);
            findings.extend(done);
            confirmed.extend(cves);
        }
        if anchor.get(&ip) == Some(&port) {
            if let Some(scripts) = nm.host_scripts.get(&ip) {
                nse::add_scripts(&mut svc, scripts);
                let (done, cves) = nse::findings(ip, port, &svc.name, scripts, &today);
                findings.extend(done);
                confirmed.extend(cves);
            }
            if let Some(os) = nm.os.get(&ip) {
                findings.push(os_finding(ip, port, &svc.name, os));
            }
        }
        // The same check can come from Proton and from an Nmap script.
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert(f.id.clone()));
        for f in findings {
            let _ = tx.send(VulnEvent::Finding(Box::new(f)));
        }
        let _ = tx.send(VulnEvent::Service(Box::new(svc.clone())));
        if let Ok(mut s) = services.lock() {
            s.push(svc);
        }
        if let Ok(mut c) = script_cves.lock() {
            c.extend(confirmed);
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
    });
    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // ---- Phase 4: known vulnerabilities --------------------------------
    let services = services.into_inner().unwrap_or_default();
    let mut script_cves = script_cves.into_inner().unwrap_or_default();
    script_cves.dedup_by(|a, b| a.id == b.id && a.ip == b.ip && a.port == b.port);
    if opts.cve_source == CveSource::Off {
        for f in script_cves {
            let _ = tx.send(VulnEvent::Finding(Box::new(f)));
        }
        let _ = tx.send(VulnEvent::Note("CVE matching is off, so only configuration checks were run.".into()));
        return;
    }
    // Unique CPEs → the services that run them. Software whose version is
    // only approximate ("Samba 4") is not version-matched — "4" would match
    // nearly every CVE of the product. It becomes one "needs manual check"
    // finding per service instead, listing the CVEs that could apply.
    let mut by_cpe: BTreeMap<String, Vec<(&Service, &detect::Product)>> = BTreeMap::new();
    let mut approx: Vec<Approx> = Vec::new();
    for s in &services {
        for p in &s.products {
            let Some(cpe) = &p.cpe else { continue };
            let parts: Vec<&str> = cpe.split(':').collect();
            let version = parts.get(5).copied().unwrap_or("");
            if nvd::is_precise_version(version) {
                by_cpe.entry(cpe.clone()).or_default().push((s, p));
            } else if let (Some(v), Some(pr)) = (parts.get(3), parts.get(4)) {
                let families = nvd::version_families(version);
                if !families.is_empty() {
                    approx.push(Approx { svc: s, product: p, key: (v.to_string(), pr.to_string()), families });
                }
            }
        }
    }
    // Every (vendor, product) with an approximate version, and the families seen.
    let mut approx_keys: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();
    for a in &approx {
        let fams = approx_keys.entry(a.key.clone()).or_default();
        fams.extend(&a.families);
        fams.sort_unstable();
        fams.dedup();
    }
    // CVE ids that Nmap scripts confirmed (looked up by id).
    let mut script_ids: Vec<String> = script_cves.iter().map(|f| f.id.clone()).collect();
    script_ids.sort();
    script_ids.dedup();
    script_ids.truncate(40);
    if by_cpe.is_empty() && script_ids.is_empty() && approx_keys.is_empty() {
        let _ = tx.send(VulnEvent::Note(
            "No software versions could be identified on the open ports, so no CVE lookups were needed.".into(),
        ));
        return;
    }
    let lookups = by_cpe.len() + script_ids.len() + approx_keys.len();
    progress.set(Phase::Lookup, lookups);

    // Records per CPE, from NVD (online) or the offline database.
    let mut records: BTreeMap<String, Vec<nvd::CveRecord>> = BTreeMap::new();
    let mut by_id: HashMap<String, nvd::CveRecord> = HashMap::new();
    // All CVEs of products known only approximately (filtered per service later).
    let mut approx_records: BTreeMap<(String, String), Vec<nvd::CveRecord>> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut use_offline = opts.cve_source == CveSource::Offline;
    let mut db = nvd::VulnDb::new(opts.nvd_api_key.clone());
    if !use_offline {
        'online: {
            for (cpe, users) in &by_cpe {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let label = users.first().map(|(_, p)| p.label()).unwrap_or_default();
                progress.set_detail(&format!("NVD: {label}"));
                let mut list = Vec::new();
                let mut failed = None;
                // nginx is filed under two vendors in NVD (nginx, later F5).
                for cpe_variant in cpe_aliases(cpe) {
                    match db.cves_for_cpe(&cpe_variant, cancel) {
                        Ok(r) => list.extend(r),
                        Err(e) => failed = Some(e),
                    }
                }
                if let Some(e) = failed {
                    if e.starts_with("could not reach") {
                        // No connection: switch to the offline database (if any) for everything.
                        use_offline = true;
                        break 'online;
                    }
                    errors.push(format!("{label}: {e}"));
                }
                list.sort_by(|a, b| a.id.cmp(&b.id));
                list.dedup_by(|a, b| a.id == b.id);
                records.insert(cpe.clone(), list);
                progress.done.fetch_add(1, Ordering::Relaxed);
            }
            for r in records.values().flatten() {
                by_id.entry(r.id.clone()).or_insert_with(|| r.clone());
            }
            for id in &script_ids {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                if !by_id.contains_key(id) {
                    progress.set_detail(&format!("NVD: {id}"));
                    match db.cve_by_id(id, cancel) {
                        Ok(Some(r)) => {
                            by_id.insert(id.clone(), r);
                        }
                        Ok(None) => {}
                        Err(e) if e.starts_with("could not reach") => {
                            use_offline = true;
                            break 'online;
                        }
                        Err(e) => errors.push(format!("{id}: {e}")),
                    }
                }
                progress.done.fetch_add(1, Ordering::Relaxed);
            }
            for (vendor, product) in approx_keys.keys() {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                progress.set_detail(&format!("NVD: all {product} CVEs (approximate version)"));
                let mut list = Vec::new();
                for (v, p) in offline::aliases(vendor, product) {
                    match db.cves_for_product(&v, &p, cancel) {
                        Ok(r) => list.extend(r),
                        Err(e) if e.starts_with("could not reach") => {
                            use_offline = true;
                            break 'online;
                        }
                        Err(e) => errors.push(format!("{product}: {e}")),
                    }
                }
                approx_records.insert((vendor.clone(), product.clone()), list);
                progress.done.fetch_add(1, Ordering::Relaxed);
            }
        }
        if use_offline {
            records.clear();
            by_id.clear();
            approx_records.clear();
            errors.clear();
        }
    }
    if use_offline {
        progress.set(Phase::Lookup, lookups);
        progress.set_detail("offline database");
        let fallback = opts.cve_source == CveSource::Online;
        match offline::OfflineDb::load_installed() {
            Ok(Some(off)) => {
                for cpe in by_cpe.keys() {
                    records.insert(cpe.clone(), off.lookup(cpe));
                    progress.done.fetch_add(1, Ordering::Relaxed);
                }
                for id in &script_ids {
                    if let Some(r) = off.by_id(id) {
                        by_id.insert(id.clone(), r);
                    }
                }
                for ((vendor, product), fams) in &approx_keys {
                    approx_records.insert((vendor.clone(), product.clone()), off.lookup_family(vendor, product, fams));
                }
                let info = off.info();
                let mut note = if fallback {
                    format!("NVD could not be reached, so the offline database ({}) was used instead.", info.label())
                } else {
                    format!("CVEs from the offline database ({}).", info.label())
                };
                if info.age_days() > 30 {
                    note.push_str(&format!(" It is {} days old — update it to see newer CVEs.", info.age_days()));
                }
                let _ = tx.send(VulnEvent::Note(note));
            }
            Ok(None) => {
                let _ = tx.send(VulnEvent::Note(if fallback {
                    "The vulnerability database could not be reached (no internet connection, or a firewall/proxy blocks \
                     services.nvd.nist.gov) and no offline database is installed. Configuration findings are complete; \
                     CVE matching was skipped. Tip: Database → Download (on a computer with internet), then Export / Import."
                        .into()
                } else {
                    "No offline vulnerability database is installed, so CVE matching was skipped. Use Database → Download, \
                     or import a database exported from a computer with internet."
                        .into()
                }));
                for f in script_cves {
                    let _ = tx.send(VulnEvent::Finding(Box::new(f)));
                }
                return;
            }
            Err(e) => {
                let _ = tx.send(VulnEvent::Note(format!("The offline vulnerability database could not be read: {e}")));
                for f in script_cves {
                    let _ = tx.send(VulnEvent::Finding(Box::new(f)));
                }
                return;
            }
        }
    }

    let mut cve_findings: Vec<Finding> = Vec::new();
    for (cpe, users) in &by_cpe {
        for (svc, product) in users {
            for r in records.get(cpe).into_iter().flatten() {
                cve_findings.push(cve_finding(svc, product, r));
            }
        }
    }
    // Approximate versions: one "needs manual check" finding per service, or
    // (show_unverified) each possible CVE as an Unverified finding.
    let mut reviews: Vec<Finding> = Vec::new();
    for a in &approx {
        let names = offline::aliases(&a.key.0, &a.key.1);
        let mut possible: Vec<&nvd::CveRecord> = approx_records
            .get(&a.key)
            .into_iter()
            .flatten()
            .filter(|r| r.rules.iter().any(|rule| names.iter().any(|(v, p)| rule.may_match_family(v, p, &a.families))))
            .collect();
        possible.sort_by(|x, y| x.id.cmp(&y.id));
        possible.dedup_by(|x, y| x.id == y.id);
        if possible.is_empty() {
            continue;
        }
        if opts.show_unverified {
            for r in possible {
                let mut f = cve_finding(a.svc, a.product, r);
                f.confidence = Confidence::Unverified;
                f.evidence = format!(
                    "Unverified: only an approximate version ({}) is visible on port {}, so this CVE may or may not \
                     apply. Check the installed version.",
                    a.product.label(),
                    a.svc.port
                );
                cve_findings.push(f);
            }
        } else {
            reviews.push(review_finding(a, &possible, &names));
        }
    }
    // A CVE an Nmap script confirmed replaces the version-based match.
    cve_findings.retain(|f| !script_cves.iter().any(|c| c.id == f.id && c.ip == f.ip && c.port == f.port));
    for mut f in script_cves {
        if let Some(r) = by_id.get(&f.id) {
            nse::enrich(&mut f, r);
        }
        cve_findings.push(f);
    }

    // EPSS (online: ask FIRST; offline: stored in the database), then priority.
    if !cve_findings.is_empty() {
        let epss: HashMap<String, Epss> = if use_offline {
            records.values().flatten().chain(by_id.values()).filter_map(|r| r.epss.map(|e| (r.id.clone(), e))).collect()
        } else {
            progress.set_detail("FIRST: EPSS scores");
            let mut ids: Vec<String> = cve_findings.iter().map(|f| f.id.clone()).collect();
            ids.sort();
            ids.dedup();
            match db.epss(&ids, cancel) {
                Ok(m) => m,
                Err(e) => {
                    errors.push(format!("EPSS: {e}"));
                    HashMap::new()
                }
            }
        };
        for f in &mut cve_findings {
            f.epss = epss.get(&f.id).copied();
            let impact = f.cvss.as_ref().map(|c| c.score).unwrap_or_else(|| {
                if f.evidence.starts_with("Confirmed by Nmap") { nse::severity_impact(f.severity) } else { 5.0 }
            });
            f.ppr = score::ppr(impact, score::cve_threat(f.kev, f.epss).max(confirmed_threat(f)));
        }
    }
    for f in cve_findings.into_iter().chain(reviews) {
        let _ = tx.send(VulnEvent::Finding(Box::new(f)));
    }
    if !errors.is_empty() {
        let first = errors.first().cloned().unwrap_or_default();
        let _ = tx.send(VulnEvent::Note(format!(
            "{} vulnerability lookup(s) failed, so results may be incomplete. First error: {first}",
            errors.len()
        )));
    }
}

/// A vulnerability an Nmap script confirmed on the device is more urgent
/// than a version-based match with the same EPSS.
fn confirmed_threat(f: &Finding) -> f32 {
    if f.evidence.starts_with("Confirmed by Nmap") { 6.0 } else { 0.0 }
}

/// What Nmap reported, per host and port.
#[derive(Default)]
struct NmapResults {
    ports: HashMap<(Ipv4Addr, u16), crate::nmap::NmapPort>,
    host_scripts: HashMap<Ipv4Addr, Vec<crate::nmap::Script>>,
    os: HashMap<Ipv4Addr, String>,
}

/// Proton's own port scan of the live hosts. Returns false if the scan could not run.
fn builtin_port_scan(
    live: &[Ipv4Addr],
    opts: &VulnOptions,
    settings: &Settings,
    tx: &Sender<VulnEvent>,
    progress: &Progress,
    cancel: &AtomicBool,
    open: &mut Vec<(Ipv4Addr, u16)>,
) -> bool {
    match scanner::start_port_scan(live.to_vec(), opts.ports.clone(), settings) {
        Ok(job) => {
            progress.set(Phase::Ports, job.total);
            follow(&job, progress, cancel, |ev| {
                if let Event::OpenPort(ip, p) = ev {
                    open.push((ip, p.port));
                }
            });
            true
        }
        Err(e) => {
            let _ = tx.send(VulnEvent::Note(e));
            false
        }
    }
}

/// Run Nmap on the hosts. Normal: only the ports found open (fast); deep:
/// every selected port with a SYN scan and OS detection. Returns false if
/// Nmap could not run (a note explains why).
#[allow(clippy::too_many_arguments)]
fn run_nmap(
    live: &[Ipv4Addr],
    open: &[(Ipv4Addr, u16)],
    opts: &VulnOptions,
    deep: bool,
    progress: &Progress,
    cancel: &AtomicBool,
    tx: &Sender<VulnEvent>,
    out: &mut NmapResults,
) -> bool {
    let (targets, ports): (Vec<Ipv4Addr>, Vec<u16>) = if deep {
        (live.to_vec(), opts.ports.clone())
    } else {
        let mut t: Vec<Ipv4Addr> = open.iter().map(|o| o.0).collect();
        let mut p: Vec<u16> = open.iter().map(|o| o.1).collect();
        t.sort();
        t.dedup();
        p.sort_unstable();
        p.dedup();
        (t, p)
    };
    if targets.is_empty() || ports.is_empty() {
        return true;
    }
    progress.set(Phase::Services, 100);
    progress.set_detail(if deep && cfg!(target_os = "linux") {
        "Nmap: waiting for administrator approval"
    } else {
        "Nmap: starting"
    });
    let req = crate::nmap::Request {
        targets,
        ports,
        speed: opts.speed,
        deep,
        scripts: crate::nmap::Scripts::Assess { logins: opts.safe_logins },
    };
    let result = crate::nmap::run(&req, cancel, |ev| match ev {
        crate::nmap::Event::Progress(task, pct) => {
            progress.set_detail(&format!("Nmap: {task} {pct:.0}%"));
            progress.done.store(pct as usize, Ordering::Relaxed);
        }
        crate::nmap::Event::Host(h) => {
            let Some(ip) = h.ip else { return };
            // Only addresses we asked about (Nmap output is not trusted blindly).
            if !req.targets.contains(&ip) {
                return;
            }
            if let Some(os) = &h.os {
                out.os.insert(ip, os.label());
            }
            if !h.scripts.is_empty() {
                out.host_scripts.insert(ip, h.scripts);
            }
            for p in h.ports {
                if req.ports.contains(&p.port) {
                    out.ports.insert((ip, p.port), p);
                }
            }
        }
    });
    match result {
        Ok(s) => {
            if s.skipped > 0 {
                let _ = tx.send(VulnEvent::Note(format!(
                    "{} host result(s) from Nmap were too large or malformed and were skipped.",
                    s.skipped
                )));
            }
            true
        }
        Err(e) => {
            let _ = tx.send(VulnEvent::Note(format!(
                "Nmap could not complete the scan ({e}). Proton's built-in engine was used instead."
            )));
            false
        }
    }
}

/// Informational finding with Nmap's operating-system guess.
fn os_finding(ip: Ipv4Addr, port: u16, service: &str, os: &str) -> Finding {
    Finding {
        id: "NMAP-OS".into(),
        title: format!("Operating system: {os}"),
        ip,
        port,
        service: service.to_string(),
        product: None,
        severity: Severity::Info,
        cvss: None,
        epss: None,
        kev: false,
        ppr: 0.0,
        description: "Nmap's operating-system detection (deep scan) compared how this device answers network \
                      probes with its database of known systems. The percentage is Nmap's confidence."
            .into(),
        solution: "No action needed. Check that the system is still supported by its vendor and receives updates."
            .into(),
        evidence: format!("Nmap OS detection: {os}"),
        references: vec![],
        published: None,
        confidence: Confidence::Confirmed,
        reviewed: false,
        comment: String::new(),
    }
}

/// The CPE plus the same product under NVD's other vendor names.
fn cpe_aliases(cpe: &str) -> Vec<String> {
    let p: Vec<&str> = cpe.split(':').collect();
    match (p.get(3), p.get(4)) {
        (Some(v), Some(pr)) => offline::aliases(v, pr)
            .into_iter()
            .map(|(nv, np)| {
                let mut q: Vec<String> = p.iter().map(|x| x.to_string()).collect();
                q[3] = nv;
                q[4] = np;
                q.join(":")
            })
            .collect(),
        _ => vec![cpe.to_string()],
    }
}

/// Build a CVE finding for one service/product.
fn cve_finding(svc: &Service, product: &detect::Product, r: &nvd::CveRecord) -> Finding {
    let severity = r.cvss.as_ref().map(|c| Severity::from_score(c.score)).unwrap_or(Severity::Medium);
    let first_sentence = r.description.split(". ").next().unwrap_or(&r.description);
    let mut short: String = first_sentence.chars().take(110).collect();
    if first_sentence.chars().count() > 110 {
        short.push('…');
    }
    let mut description = r.description.clone();
    if r.cvss.is_none() {
        description.push_str(" (NVD has not scored this CVE yet; severity shown as Medium until it does.)");
    }
    let mut evidence = format!("Version-based match: {} announced on port {}.", product.label(), svc.port);
    if product.backported {
        evidence.push_str(
            " The banner shows a Linux distribution build: distributions back-port security fixes without \
             changing the version number, so confirm with the installed package version.",
        );
    }
    Finding {
        id: r.id.clone(),
        title: format!("{}: {short}", product.label()),
        ip: svc.ip,
        port: svc.port,
        service: svc.name.clone(),
        product: Some(product.label()),
        severity,
        cvss: r.cvss.clone(),
        epss: None,
        kev: r.kev,
        ppr: 0.0,
        description,
        solution: r.solution.clone().unwrap_or_else(|| {
            format!(
                "Update {} to a version that fixes {} (see the vendor advisory in the references), or apply your \
                 distribution's security updates.",
                product.name, r.id
            )
        }),
        evidence,
        references: {
            let mut refs = vec![format!("https://nvd.nist.gov/vuln/detail/{}", r.id)];
            refs.extend(r.references.iter().cloned());
            refs
        },
        published: r.published.clone(),
        confidence: if product.backported { Confidence::Backported } else { Confidence::VersionMatch },
        reviewed: false,
        comment: String::new(),
    }
}

/// A product the scanner knows only approximately ("Samba smbd 4") on one service.
struct Approx<'a> {
    svc: &'a Service,
    product: &'a detect::Product,
    /// NVD vendor and product.
    key: (String, String),
    /// Major version families it could be (4 → `[4]`; 3.X-4.X → `[3, 4]`).
    families: Vec<u64>,
}

/// How to find the exact installed version, per product.
fn manual_check_hint(product: &str) -> &'static str {
    match product {
        "samba" => {
            "On the server run `smbd --version` (or `apt policy samba` on Debian/Ubuntu/Mint, `rpm -q samba` on \
                    Fedora/RHEL)."
        }
        "openssh" => "On the server run `ssh -V` (or `apt policy openssh-server` / `rpm -q openssh-server`).",
        "http_server" => "On the server run `apache2 -v` or `httpd -v` (or `apt policy apache2` / `rpm -q httpd`).",
        "nginx" => "On the server run `nginx -v` (or `apt policy nginx` / `rpm -q nginx`).",
        "openssl" => "On the server run `openssl version` (or `apt policy openssl` / `rpm -q openssl`).",
        _ => {
            "Look up the version in the device's admin page or settings, or on Linux with `apt policy <package>` \
              / `rpm -q <package>`."
        }
    }
}

/// One "needs manual check" finding: the exact version is unknown, these
/// CVEs could apply.
fn review_finding(a: &Approx, possible: &[&nvd::CveRecord], names: &[(String, String)]) -> Finding {
    let mut list = possible.to_vec();
    list.sort_by(|x, y| {
        y.kev
            .cmp(&x.kev)
            .then(y.cvss.as_ref().map_or(0.0, |c| c.score).total_cmp(&x.cvss.as_ref().map_or(0.0, |c| c.score)))
    });
    let kev = list.iter().filter(|r| r.kev).count();
    let n = list.len();
    let label = a.product.label();
    let mut title = format!("{label}: exact version unknown — {n} CVE{} could apply", if n == 1 { "" } else { "s" });
    if kev > 0 {
        title.push_str(&format!(" ({kev} known exploited)"));
    }
    let fams: Vec<String> = a.families.iter().map(|f| format!("{f}.x")).collect();
    let mut evidence = format!(
        "Seen on port {}: \"{label}\" — only the version family ({}) is visible from the network.\n\nCVEs that affect \
         some {} version, worst first:",
        a.svc.port,
        fams.join(", "),
        fams.join(" / ")
    );
    for r in list.iter().take(25) {
        let fixed = r
            .rules
            .iter()
            .find(|rule| names.iter().any(|(v, p)| rule.may_match_family(v, p, &a.families)))
            .and_then(|rule| rule.fixed_text());
        evidence.push_str(&format!(
            "\n• {}{}{}{}",
            r.id,
            r.cvss.as_ref().map(|c| format!(" · CVSS {:.1}", c.score)).unwrap_or_default(),
            if r.kev { " · KEV" } else { "" },
            fixed.map(|f| format!(" · {f}")).unwrap_or_default()
        ));
    }
    if n > 25 {
        evidence.push_str(&format!("\n… and {} more.", n - 25));
    }
    Finding {
        id: format!("REVIEW-{}", a.key.1),
        title,
        ip: a.svc.ip,
        port: a.svc.port,
        service: a.svc.name.clone(),
        product: Some(label.clone()),
        severity: Severity::Review,
        cvss: None,
        epss: None,
        kev: false,
        ppr: 0.0,
        description: format!(
            "The scanner can see that this is {} but not its exact version ({label}). Known vulnerabilities depend on \
             the exact version, so from the network they can be neither confirmed nor ruled out. If the software is \
             up to date, none of the CVEs listed in the evidence apply — this is not a confirmed vulnerability, it \
             needs a manual check.",
            a.product.name
        ),
        solution: format!(
            "Check the installed version: {} Compare it with the \"fixed in\" versions listed in the evidence. Linux \
             distributions back-port fixes, so with a distribution package also check that its security updates are \
             installed.",
            manual_check_hint(&a.key.1)
        ),
        evidence,
        references: list.iter().take(10).map(|r| format!("https://nvd.nist.gov/vuln/detail/{}", r.id)).collect(),
        published: None,
        confidence: Confidence::Unverified,
        reviewed: false,
        comment: String::new(),
    }
}

/// Wait for a scanner [`scanner::Job`], forwarding its events and progress,
/// and passing on Stop.
fn follow(job: &scanner::Job, progress: &Progress, cancel: &AtomicBool, mut on_event: impl FnMut(Event)) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            job.cancel();
        }
        progress.done.store(job.done(), Ordering::Relaxed);
        match job.rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Event::Finished) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(ev) => on_event(ev),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

/// Run `f(i)` for `i` in `0..n` on up to `workers` scoped threads, with the
/// pauses of `speed` between items. Returns when all are done or cancelled.
fn run_paced(n: usize, workers: usize, speed: Speed, cancel: &AtomicBool, f: impl Fn(usize) + Sync) {
    let next = AtomicUsize::new(0);
    let (lo, hi) = match speed {
        Speed::Normal => (0, 0),
        Speed::Polite => (150, 400),
        Speed::Slow => (1_000, 3_000),
    };
    std::thread::scope(|s| {
        for w in 0..workers.clamp(1, 32).min(n.max(1)) {
            let (next, f) = (&next, &f);
            let _ = std::thread::Builder::new().stack_size(512 * 1024).spawn_scoped(s, move || {
                let mut rng = scanner::Rng(scanner::seed() ^ (w as u64 + 7));
                while !cancel.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    f(i);
                    if hi > 0 {
                        scanner::pause(rng.between(lo, hi), cancel);
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, ip: u8, ppr: f32, sev: Severity) -> Finding {
        Finding {
            id: id.into(),
            title: id.into(),
            ip: Ipv4Addr::new(10, 0, 0, ip),
            port: 22,
            service: "SSH".into(),
            product: None,
            severity: sev,
            cvss: None,
            epss: None,
            kev: false,
            ppr,
            description: String::new(),
            solution: String::new(),
            evidence: String::new(),
            references: vec![],
            published: None,
            confidence: Confidence::VersionMatch,
            reviewed: false,
            comment: String::new(),
        }
    }

    #[test]
    fn comments_are_cleaned() {
        assert_eq!(clean_comment("ok\x1b[31m red\r\nline 2\t \n"), "ok[31m red\nline 2");
        assert_eq!(clean_comment(&"x".repeat(5_000)).len(), MAX_COMMENT);
    }

    /// Review marks and comments reach both reports; hostile comment text
    /// stays text.
    #[test]
    fn reviews_in_reports() {
        let mut a = f("CVE-2024-0001", 1, 5.0, Severity::Medium);
        a.reviewed = true;
        a.comment = "Patched (4.19.5) ) Tj ET =HYPERLINK(\"x\")".into();
        let b = f("CVE-2024-0001", 2, 5.0, Severity::Medium);
        let c = f("CVE-2024-0002", 1, 9.0, Severity::Critical);
        let findings = vec![a, b, c];
        let top = top10(&findings);
        let d = crate::report::ReportData {
            generated: "now".into(),
            targets: "10.0.0.0/24".into(),
            speed: "Normal".into(),
            duration_secs: 1.0,
            hosts: 2,
            cve_data: "test".into(),
            services: &[],
            findings: &findings,
            top10: &top,
            notes: &[],
        };
        assert_eq!(d.review_status("CVE-2024-0001"), "1 of 2");
        assert_eq!(d.review_status("CVE-2024-0002"), "");
        assert_eq!(
            d.comments("CVE-2024-0001"),
            [("10.0.0.1:22".to_string(), "Patched (4.19.5) ) Tj ET =HYPERLINK(\"x\")".to_string())]
        );
        assert_eq!(d.reviewed_count(), (1, 3));
        let pdf = crate::report::pdf::build(&d);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("Reviewed: 1 of 2"));
        // The parenthesis is escaped, so the comment cannot end the text object.
        assert!(text.contains("Patched \\(4.19.5\\) \\) Tj ET"));
        assert!(crate::report::xlsx::build(&d).is_ok());
    }

    #[test]
    fn top10_groups_and_ranks() {
        let mut list = vec![
            f("CVE-2024-0001", 1, 5.0, Severity::Medium),
            f("CVE-2024-0001", 2, 5.0, Severity::Medium),
            f("CVE-2024-0002", 1, 9.0, Severity::Critical),
            f("PIS-0012", 1, 0.0, Severity::Info),
        ];
        for i in 0..20 {
            list.push(f(&format!("CVE-2023-{:04}", i + 100), 3, 1.0 + i as f32 * 0.1, Severity::Low));
        }
        let top = top10(&list);
        assert_eq!(top.len(), 10);
        assert_eq!(top[0].finding.id, "CVE-2024-0002");
        assert_eq!(top[1].finding.id, "CVE-2024-0001");
        assert_eq!(top[1].hosts, 2);
        assert!(top.iter().all(|t| t.finding.severity != Severity::Info));
    }

    /// Full pipeline against local fake services, offline.
    #[test]
    fn assessment_end_to_end_offline() {
        use std::io::{Read, Write};
        let redis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = redis.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = redis.accept() {
                let mut b = [0u8; 64];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"SSH-2.0-OpenSSH_8.9p1\r\n");
            }
        });
        let job = start(VulnOptions {
            targets: vec![Ipv4Addr::LOCALHOST],
            discover_first: false,
            ports: vec![port],
            speed: Speed::Normal,
            port_timeout_ms: 500,
            cve_source: CveSource::Off,
            safe_logins: true,
            nvd_api_key: None,
            nets: vec![],
            engine: Engine::Builtin,
            show_unverified: false,
            deep: false,
        });
        let (mut services, mut notes) = (Vec::new(), Vec::new());
        for ev in job.rx.iter() {
            match ev {
                VulnEvent::Service(s) => services.push(*s),
                VulnEvent::Note(n) => notes.push(n),
                VulnEvent::Finished => break,
                _ => {}
            }
        }
        // The port scan's own connect consumed the first accept; either way
        // the job must finish cleanly and report the offline note.
        assert!(
            notes.iter().any(|n| n.contains("CVE matching is off"))
                || notes.iter().any(|n| n.contains("No open ports"))
        );
    }
}

#[cfg(test)]
mod nmap_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    /// Whole assessment with the Nmap engine against a local fake FTP server
    /// that allows anonymous login (skipped when Nmap is not installed).
    #[test]
    fn assessment_with_nmap_engine() {
        if crate::nmap::find().is_none() {
            return;
        }
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut w = s.try_clone().unwrap();
                    let _ = w.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = w.write_all(b"220 (vsFTPd 3.0.3)\r\n");
                    for line in BufReader::new(s).lines().map_while(Result::ok) {
                        let reply: &[u8] = if line.starts_with("USER") {
                            b"331 Please specify the password.\r\n"
                        } else if line.starts_with("PASS") {
                            b"230 Login successful.\r\n"
                        } else if line.starts_with("SYST") {
                            b"215 UNIX Type: L8\r\n"
                        } else if line.starts_with("QUIT") {
                            let _ = w.write_all(b"221 Goodbye.\r\n");
                            break;
                        } else {
                            b"500 Unknown command.\r\n"
                        };
                        if w.write_all(reply).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let job = start(VulnOptions {
            targets: vec![Ipv4Addr::LOCALHOST],
            discover_first: false,
            ports: vec![port],
            speed: Speed::Normal,
            port_timeout_ms: 800,
            cve_source: CveSource::Off,
            safe_logins: true,
            nvd_api_key: None,
            nets: vec![],
            engine: Engine::Nmap,
            show_unverified: false,
            deep: false,
        });
        let (mut findings, mut services, mut notes) = (Vec::new(), Vec::new(), Vec::new());
        for ev in job.rx.iter() {
            match ev {
                VulnEvent::Finding(f) => findings.push(*f),
                VulnEvent::Service(s) => services.push(*s),
                VulnEvent::Note(n) => notes.push(n),
                VulnEvent::Finished => break,
                VulnEvent::Host => {}
            }
        }
        assert!(!notes.iter().any(|n| n.contains("Nmap could not")), "{notes:?}");
        let svc = services.iter().find(|s| s.port == port).expect("service");
        // Nmap's vsftpd CPE becomes NVD's beasts:vsftpd.
        assert!(
            svc.products.iter().any(|p| p.cpe.as_deref() == Some("cpe:2.3:a:beasts:vsftpd:3.0.3:*:*:*:*:*:*:*")),
            "{:?}",
            svc.products
        );
        assert!(svc.nse.iter().any(|(id, _)| id == "ftp-anon"), "{:?}", svc.nse);
        // Found by Proton's check and by Nmap's ftp-anon script, reported once.
        assert_eq!(findings.iter().filter(|f| f.id == "PIS-0002").count(), 1, "{findings:?}");
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use std::io::{Read, Write};

    /// Fake services on 127.0.0.1 (an old Apache web server and an
    /// unprotected Redis), full pipeline with online lookups enabled.
    /// Ignored by default because the result depends on internet access:
    /// offline it must report the failed lookup and still show the
    /// configuration findings; online it adds the CVEs.
    #[test]
    #[ignore]
    fn assessment_with_online_lookup() {
        let web = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let redis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (wp, rp) = (web.local_addr().unwrap().port(), redis.local_addr().unwrap().port());
        std::thread::spawn(move || {
            for s in web.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        });
        std::thread::spawn(move || {
            for s in redis.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 64];
                if s.read(&mut b).unwrap_or(0) > 0 {
                    let _ = s.write_all(b"$40\r\n# Server\r\nredis_version:6.0.16\r\n\r\n");
                }
            }
        });
        let job = start(VulnOptions {
            targets: vec![Ipv4Addr::LOCALHOST],
            discover_first: false,
            ports: vec![wp, rp],
            speed: Speed::Normal,
            port_timeout_ms: 800,
            cve_source: CveSource::Online,
            safe_logins: true,
            nvd_api_key: None,
            nets: vec![],
            engine: Engine::Builtin,
            show_unverified: false,
            deep: false,
        });
        let (mut findings, mut notes, mut services) = (Vec::new(), Vec::new(), Vec::new());
        for ev in job.rx.iter() {
            match ev {
                VulnEvent::Finding(f) => findings.push(*f),
                VulnEvent::Note(n) => notes.push(n),
                VulnEvent::Service(s) => services.push(*s),
                VulnEvent::Finished => break,
                VulnEvent::Host => {}
            }
        }
        for s in &services {
            eprintln!(
                "SERVICE {}:{} {} {:?}",
                s.ip,
                s.port,
                s.name,
                s.products.iter().map(|p| (p.label(), p.cpe.clone())).collect::<Vec<_>>()
            );
        }
        for f in &findings {
            eprintln!("FINDING {} {:?} {} ppr={}", f.id, f.severity, f.title, f.ppr);
        }
        for n in &notes {
            eprintln!("NOTE {n}");
        }
        assert!(findings.iter().any(|f| f.id == "PIS-0003"), "Redis without password must be found");
        let cves = findings.iter().filter(|f| f.is_cve()).count();
        assert!(
            cves > 0 || notes.iter().any(|n| n.contains("lookup") || n.contains("could not be reached")),
            "either CVEs or a clear note about the lookup"
        );
    }
}
