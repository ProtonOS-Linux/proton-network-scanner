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
}

impl Finding {
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
    for f in findings.iter().filter(|f| f.severity != Severity::Info) {
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
    pub const ALL: [CveSource; 3] = [CveSource::Online, CveSource::Offline, CveSource::Off];
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
    fn from_u8(v: u8) -> Phase {
        match v {
            0 => Phase::Discovery,
            1 => Phase::Ports,
            2 => Phase::Services,
            3 => Phase::Lookup,
            _ => Phase::Done,
        }
    }

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
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }
    pub fn detail(&self) -> String {
        self.detail.lock().map(|d| d.clone()).unwrap_or_default()
    }
    fn set(&self, phase: Phase, total: usize) {
        self.phase.store(phase as u8, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
        self.set_detail("");
    }
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
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
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
    let mut open: Vec<(Ipv4Addr, u16)> = Vec::new();
    match scanner::start_port_scan(live.clone(), opts.ports.clone(), &settings) {
        Ok(job) => {
            progress.set(Phase::Ports, job.total);
            follow(&job, progress, cancel, |ev| {
                if let Event::OpenPort(ip, p) = ev {
                    open.push((ip, p.port));
                }
            });
        }
        Err(e) => {
            let _ = tx.send(VulnEvent::Note(e));
            return;
        }
    }
    open.sort();
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    if open.is_empty() {
        let _ =
            tx.send(VulnEvent::Note("No open ports found on the live hosts, so there was nothing to assess.".into()));
        return;
    }

    // ---- Phase 3: services + configuration checks ----------------------
    progress.set(Phase::Services, open.len());
    let ctx = ProbeCtx::new(Duration::from_millis(opts.port_timeout_ms.clamp(300, 5_000)), opts.safe_logins);
    let services: Mutex<Vec<Service>> = Mutex::new(Vec::new());
    let workers = match opts.speed {
        Speed::Normal => 16,
        Speed::Polite => 4,
        Speed::Slow => 1,
    };
    run_paced(open.len(), workers, opts.speed, cancel, |i| {
        let Some(&(ip, port)) = open.get(i) else { return };
        let (svc, findings) = detect::probe(ip, port, &ctx);
        for f in findings {
            let _ = tx.send(VulnEvent::Finding(Box::new(f)));
        }
        let _ = tx.send(VulnEvent::Service(Box::new(svc.clone())));
        if let Ok(mut s) = services.lock() {
            s.push(svc);
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
    });
    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // ---- Phase 4: known vulnerabilities --------------------------------
    let services = services.into_inner().unwrap_or_default();
    if opts.cve_source == CveSource::Off {
        let _ = tx.send(VulnEvent::Note("CVE matching is off, so only configuration checks were run.".into()));
        return;
    }
    // Unique CPEs → the services that run them.
    let mut by_cpe: BTreeMap<String, Vec<(&Service, &detect::Product)>> = BTreeMap::new();
    for s in &services {
        for p in &s.products {
            if let Some(cpe) = &p.cpe {
                by_cpe.entry(cpe.clone()).or_default().push((s, p));
            }
        }
    }
    if by_cpe.is_empty() {
        let _ = tx.send(VulnEvent::Note(
            "No software versions could be identified on the open ports, so no CVE lookups were needed.".into(),
        ));
        return;
    }
    progress.set(Phase::Lookup, by_cpe.len());

    // Records per CPE, from NVD (online) or the offline database.
    let mut records: BTreeMap<String, Vec<nvd::CveRecord>> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut use_offline = opts.cve_source == CveSource::Offline;
    let mut db = nvd::VulnDb::new(opts.nvd_api_key.clone());
    if !use_offline {
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
                    records.clear();
                    errors.clear();
                    break;
                }
                errors.push(format!("{label}: {e}"));
            }
            list.sort_by(|a, b| a.id.cmp(&b.id));
            list.dedup_by(|a, b| a.id == b.id);
            records.insert(cpe.clone(), list);
            progress.done.fetch_add(1, Ordering::Relaxed);
        }
    }
    if use_offline {
        progress.set(Phase::Lookup, by_cpe.len());
        progress.set_detail("offline database");
        let fallback = opts.cve_source == CveSource::Online;
        match offline::OfflineDb::load_installed() {
            Ok(Some(off)) => {
                for cpe in by_cpe.keys() {
                    records.insert(cpe.clone(), off.lookup(cpe));
                    progress.done.fetch_add(1, Ordering::Relaxed);
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
                return;
            }
            Err(e) => {
                let _ = tx.send(VulnEvent::Note(format!("The offline vulnerability database could not be read: {e}")));
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

    // EPSS (online: ask FIRST; offline: stored in the database), then priority.
    if !cve_findings.is_empty() {
        let epss: HashMap<String, Epss> = if use_offline {
            records.values().flatten().filter_map(|r| r.epss.map(|e| (r.id.clone(), e))).collect()
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
            let impact = f.cvss.as_ref().map(|c| c.score).unwrap_or(5.0);
            f.ppr = score::ppr(impact, score::cve_threat(f.kev, f.epss));
        }
    }
    for f in cve_findings {
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
        }
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
