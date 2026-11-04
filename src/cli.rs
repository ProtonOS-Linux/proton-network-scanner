//! Command-line mode, for scripts, servers without a desktop, or quick checks:
//!
//! ```text
//! proton-ip-scanner --scan 192.168.1.0/24
//! proton-ip-scanner --scan 192.168.1.1-254 --ports 22,80,443 --csv
//! proton-ip-scanner --scan auto --vuln --report pdf
//! proton-ip-scanner --scan auto --vuln --nmap --deep
//! ```

use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::export;
use crate::scanner::{self, Event, Host, Settings};

const HELP: &str = "\
Proton IP Scanner — find devices on your network.

Usage:
  proton-ip-scanner                      open the window
  proton-ip-scanner --scan <range> [options]
  proton-ip-scanner --scan <range> --vuln [--report pdf|xlsx] [--cve online|offline|off] [--slow|--stealth]
  proton-ip-scanner --update-db | --export-db | --import-db <file>

Range examples:
  192.168.1.0/24   192.168.1.1-254   10.0.0.1-10.0.1.254   192.168.1.5,192.168.1.9
  auto             (this computer's own network)

Options:
  --ports <list>     TCP ports to check on live devices (default: 28 common ports;
                     e.g. 22,80,443 or 1-1024)
  --no-ports         only find devices, skip the port check
  --threads <n>      parallel workers, 1-256 (default 64)
  --timeout <ms>     ping timeout in milliseconds (default 800)
  --banners          read the greeting line of open services
  --no-names         skip DNS, NetBIOS, mDNS and LLMNR name lookups
  --slow             polite, slower probing (fewer parallel probes, random pauses)
  --csv              print results as CSV instead of a table
  --nmap             identify services and the operating system with Nmap (if installed;
                     safe scripts only). With --vuln: use Nmap as the scan engine
  --deep             with --nmap: SYN scan + OS detection. Asks for the administrator
                     password (Linux, pkexec) for this one Nmap run only

Vulnerability assessment (--vuln):
  --vuln             find services and check them for known vulnerabilities
                     (default ports: the 52-port vulnerability set)
  --report pdf|xlsx  also save a report in your Documents folder
  --cve <source>     online  = ask NVD/FIRST during the scan (default; falls back to the
                               offline database when there is no internet)
                     offline = use the offline database only (nothing is sent)
                     off     = configuration checks only
  --offline          same as --cve offline

Offline vulnerability database (for computers without internet):
  --update-db        download/update it (needs internet; ~3 min, faster with NVD_API_KEY)
  --export-db        copy it to your Documents folder, to carry to another computer
  --import-db <file> install a database file exported on another computer
  --stealth          very slow probing (1-3 s random pauses) to avoid detection
  --no-logins        skip the anonymous FTP / MQTT login checks
  NVD_API_KEY=…      environment variable: free NVD key for faster lookups
  --help, --version

Only scan networks you own or have permission to scan.
";

/// Run the command line and return the process exit code.
pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("proton-ip-scanner: {msg}");
            2
        }
    }
}

fn run_inner(args: &[String]) -> Result<(), String> {
    let mut settings = Settings::default();
    let mut range: Option<String> = None;
    // Like the window, a normal scan also checks the common ports.
    let mut ports: Option<Vec<u16>> = Some(scanner::range::parse_ports(scanner::ports::PRESET_COMMON)?);
    let mut csv = false;
    let (mut vuln, mut report, mut logins, mut ports_given) = (false, None::<String>, true, false);
    let mut cve = crate::vuln::CveSource::Online;
    let (mut use_nmap, mut deep) = (false, false);

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        // Helper: the value after an option.
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("proton-ip-scanner {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--scan" => range = Some(value("--scan")?),
            "--ports" => {
                ports = Some(scanner::range::parse_ports(&value("--ports")?)?);
                ports_given = true;
            }
            "--vuln" => vuln = true,
            "--nmap" => use_nmap = true,
            "--deep" => deep = true,
            "--report" => {
                let r = value("--report")?;
                if r != "pdf" && r != "xlsx" {
                    return Err("--report must be pdf or xlsx".into());
                }
                report = Some(r);
            }
            "--offline" => cve = crate::vuln::CveSource::Offline,
            "--cve" => {
                cve = match value("--cve")?.as_str() {
                    "online" => crate::vuln::CveSource::Online,
                    "offline" => crate::vuln::CveSource::Offline,
                    "off" => crate::vuln::CveSource::Off,
                    _ => return Err("--cve must be online, offline or off".into()),
                }
            }
            "--update-db" => return update_db(),
            "--export-db" => {
                let p = crate::vuln::offline::export_installed()?;
                eprintln!("Exported to {}", p.display());
                return Ok(());
            }
            "--import-db" => return import_db(&value("--import-db")?),
            "--no-logins" => logins = false,
            "--stealth" => settings.speed = scanner::Speed::Slow,
            "--threads" => settings.threads = value("--threads")?.parse().map_err(|_| "--threads needs a number")?,
            "--timeout" => {
                settings.ping_timeout_ms = value("--timeout")?.parse().map_err(|_| "--timeout needs a number")?
            }
            "--banners" => settings.grab_banners = true,
            "--no-ports" => ports = None,
            "--slow" => settings.speed = scanner::Speed::Polite,
            "--no-names" => {
                settings.resolve_dns = false;
                settings.netbios = false;
                settings.multicast_names = false;
            }
            "--csv" => csv = true,
            other => {
                return Err(format!("unknown option \"{}\" (try --help)", other.chars().take(40).collect::<String>()));
            }
        }
    }

    let Some(range) = range else {
        print!("{HELP}");
        return Ok(());
    };
    if deep && !use_nmap {
        return Err("--deep needs --nmap".into());
    }
    if use_nmap {
        match crate::nmap::find() {
            Some(n) => eprintln!("Using {} ({}).", n.label(), n.path.display()),
            None => return Err(format!("--nmap: Nmap is not installed (get it from {})", crate::nmap::DOWNLOAD_URL)),
        }
    }

    let nets = scanner::local_networks();
    let range = if range == "auto" {
        let n = nets.first().ok_or("no active network found")?;
        scanner::range::network_range_text(n.addr, n.prefix_len)
    } else {
        range
    };
    let ips = scanner::range::parse_ip_ranges(&range)?;

    if vuln {
        let ports = match (ports_given, ports) {
            (true, Some(p)) => p,
            _ => scanner::range::parse_ports(scanner::ports::PRESET_VULN)?,
        };
        let engine = if use_nmap { crate::vuln::Engine::Nmap } else { crate::vuln::Engine::Builtin };
        let opts = VulnCli { speed: settings.speed, cve_source: cve, safe_logins: logins, engine, deep };
        return run_vuln(ips, range, ports, opts, report.as_deref(), nets);
    }

    eprintln!("Scanning {} address(es) ({range})…", ips.len());
    let started = Instant::now();
    let job = scanner::start_discovery(ips, &settings, nets);
    if !job.icmp {
        eprintln!("Note: ping is not available for this user; using TCP probes instead.");
    }
    let mut hosts: Vec<Host> = Vec::new();
    let mut swept = Vec::new();
    for ev in job.rx.iter() {
        match ev {
            Event::Host(h) => hosts.push(*h),
            Event::Names(list) => swept.extend(list),
            Event::Finished => break,
            Event::OpenPort(..) => {}
        }
    }
    // Names from the multicast sweep (may have arrived before or after the hosts).
    for (ip, kind, name) in &swept {
        if let Some(h) = hosts.iter_mut().find(|h| h.ip == *ip) {
            h.apply_swept(*kind, name);
        }
    }
    hosts.sort_by_key(|h| h.ip);

    if let Some(ports) = ports {
        let targets: Vec<Ipv4Addr> = hosts.iter().map(|h| h.ip).collect();
        eprintln!("Scanning {} port(s) on {} device(s)…", ports.len(), targets.len());
        for h in &mut hosts {
            h.ports = Some(Vec::new());
        }
        let job = scanner::start_port_scan(targets, ports.clone(), &settings)?;
        for ev in job.rx.iter() {
            match ev {
                Event::OpenPort(ip, p) => {
                    if let Some(list) = hosts.iter_mut().find(|h| h.ip == ip).and_then(|h| h.ports.as_mut()) {
                        list.push(p);
                    }
                }
                Event::Finished => break,
                Event::Host(_) | Event::Names(_) => {}
            }
        }
        for list in hosts.iter_mut().filter_map(|h| h.ports.as_mut()) {
            list.sort_by_key(|p| p.port);
        }
        if use_nmap {
            nmap_identify(&mut hosts, &ports, settings.speed, deep)?;
        }
    }

    let out = if csv { export::to_csv(&hosts) } else { table(&hosts) };
    // Ignore "broken pipe" (e.g. piping into `head`).
    let _ = std::io::stdout().write_all(out.as_bytes());
    eprintln!("{} live device(s) found in {:.1} s.", hosts.len(), started.elapsed().as_secs_f64());
    Ok(())
}

/// A plain-text table for the terminal.
fn table(hosts: &[Host]) -> String {
    let mut s = format!("{:<16} {:<17} {:<9} {:<26} {}\n", "IP", "MAC", "PING", "NAME", "MANUFACTURER");
    for h in hosts {
        let rtt =
            h.rtt.map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0)).unwrap_or_else(|| h.method.label().into());
        s.push_str(&format!(
            "{:<16} {:<17} {:<9} {:<26} {}\n",
            h.ip.to_string(),
            h.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
            rtt,
            truncate(h.display_name(), 26),
            h.vendor.unwrap_or("")
        ));
        if let Some(os) = &h.os {
            s.push_str(&format!("    OS: {os}\n"));
        }
        if let Some(ports) = &h.ports {
            for p in ports {
                let banner = p.banner.as_deref().map(|b| format!("  \"{b}\"")).unwrap_or_default();
                s.push_str(&format!("    {:>5}/tcp  {}{}\n", p.port, p.service, banner));
            }
        }
    }
    s
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n - 1).chain(['…']).collect() }
}

/// `--nmap` on a network scan: let Nmap identify the devices with open ports
/// (deep: every device, every listed port, with OS detection).
fn nmap_identify(hosts: &mut [Host], ports: &[u16], speed: scanner::Speed, deep: bool) -> Result<(), String> {
    let targets: Vec<Ipv4Addr> =
        hosts.iter().filter(|h| deep || h.ports.as_ref().is_some_and(|p| !p.is_empty())).map(|h| h.ip).collect();
    let mut found: Vec<u16> = hosts.iter().flat_map(|h| h.ports.iter().flatten().map(|p| p.port)).collect();
    found.sort_unstable();
    found.dedup();
    let ports = if deep { ports.to_vec() } else { found };
    if targets.is_empty() || ports.is_empty() {
        return Ok(());
    }
    eprintln!("Identifying {} device(s) with Nmap{}…", targets.len(), if deep { " (deep scan)" } else { "" });
    let req = crate::nmap::Request { targets, ports, speed, deep, scripts: crate::nmap::Scripts::Identify };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    crate::nmap::run(&req, &cancel, |ev| {
        if let crate::nmap::Event::Host(n) = ev
            && let Some(h) = hosts.iter_mut().find(|h| Some(h.ip) == n.ip)
        {
            crate::nmap::apply_to_host(h, &n);
        }
    })
    .map(|_| ())
    .map_err(|e| format!("Nmap: {e}"))
}

/// Assessment options from the command line.
struct VulnCli {
    speed: scanner::Speed,
    cve_source: crate::vuln::CveSource,
    safe_logins: bool,
    engine: crate::vuln::Engine,
    deep: bool,
}

/// `--vuln`: run an assessment and print the findings (most urgent first).
fn run_vuln(
    ips: Vec<Ipv4Addr>,
    range: String,
    ports: Vec<u16>,
    o: VulnCli,
    report: Option<&str>,
    nets: Vec<scanner::LocalNet>,
) -> Result<(), String> {
    use crate::vuln::{self, VulnEvent, VulnOptions};
    let VulnCli { speed, cve_source, safe_logins, engine, deep } = o;
    eprintln!(
        "Vulnerability assessment of {range} ({} ports, {}, {} engine{})…",
        ports.len(),
        speed.label(),
        engine.label(),
        if deep { ", deep" } else { "" }
    );
    let job = vuln::start(VulnOptions {
        targets: ips,
        discover_first: true,
        ports,
        speed,
        port_timeout_ms: 600,
        cve_source,
        safe_logins,
        nvd_api_key: std::env::var("NVD_API_KEY").ok(),
        nets,
        engine,
        deep,
    });
    let (mut findings, mut services, mut notes, mut hosts) = (Vec::new(), Vec::new(), Vec::new(), 0usize);
    let mut last_phase = None;
    loop {
        match job.rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(VulnEvent::Host) => hosts += 1,
            Ok(VulnEvent::Service(s)) => services.push(*s),
            Ok(VulnEvent::Finding(f)) => findings.push(*f),
            Ok(VulnEvent::Note(n)) => notes.push(n),
            Ok(VulnEvent::Finished) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        let phase = job.progress.phase();
        if last_phase != Some(phase) {
            eprintln!("  {}", phase.label());
            last_phase = Some(phase);
        }
    }
    findings.sort_by(|a, b| a.rank_cmp(b));
    let mut out = format!(
        "{:<9} {:<16} {:<21} {:>5} {:>5} {:>6} {:>4}  TITLE\n",
        "SEVERITY", "ID", "HOST", "CVSS", "PPR", "EPSS", "KEV"
    );
    for f in &findings {
        out.push_str(&format!(
            "{:<9} {:<16} {:<21} {:>5} {:>5.1} {:>6} {:>4}  {}\n",
            f.severity.label(),
            f.id,
            format!("{}:{}", f.ip, f.port),
            f.cvss.as_ref().map(|c| format!("{:.1}", c.score)).unwrap_or_else(|| "-".into()),
            f.ppr,
            f.epss.map(|e| format!("{:.1}%", e.probability * 100.0)).unwrap_or_else(|| "-".into()),
            if f.kev { "yes" } else { "" },
            truncate(&f.title, 90),
        ));
    }
    let _ = std::io::stdout().write_all(out.as_bytes());
    for n in &notes {
        eprintln!("Note: {n}");
    }
    eprintln!("{} host(s), {} service(s), {} finding(s).", hosts, services.len(), findings.len());

    if let Some(kind) = report {
        let top = vuln::top10(&findings);
        let data = crate::report::ReportData {
            generated: export::now_readable(),
            targets: range,
            speed: vuln::engine_label(speed, engine, deep),
            duration_secs: job.elapsed().as_secs_f64(),
            hosts,
            cve_data: crate::vuln::cve_data_label(cve_source),
            services: &services,
            findings: &findings,
            top10: &top,
            notes: &notes,
        };
        let bytes = if kind == "pdf" {
            crate::report::pdf::build(&data)
        } else {
            crate::report::xlsx::build(&data).map_err(|e| e.to_string())?
        };
        let path = export::save_bytes("proton-vulnerability-report", kind, &bytes).map_err(|e| e.to_string())?;
        eprintln!("Report saved: {}", path.display());
    }
    Ok(())
}

/// `--update-db`: download a fresh offline vulnerability database.
fn update_db() -> Result<(), String> {
    use crate::vuln::offline;
    let cancel = std::sync::atomic::AtomicBool::new(false);
    eprintln!("Downloading the offline vulnerability database from NVD and FIRST…");
    let db = offline::build(std::env::var("NVD_API_KEY").ok(), &cancel, &|done, total, label| {
        eprintln!("  [{done:>2}/{total}] {label}");
    })?;
    let info = db.install()?;
    eprintln!("Installed: {}.", info.label());
    Ok(())
}

/// `--import-db <file>`: validate and install a database file.
fn import_db(path: &str) -> Result<(), String> {
    let db = crate::vuln::offline::OfflineDb::load_file(std::path::Path::new(path))?;
    let info = db.install()?;
    eprintln!("Imported: {}.", info.label());
    Ok(())
}
