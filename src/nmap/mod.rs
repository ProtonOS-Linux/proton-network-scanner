//! Optional Nmap engine.
//!
//! When Nmap (<https://nmap.org>) is installed, Proton IP Scanner can use it
//! for deeper service/version identification, operating-system detection and
//! Nmap's **safe** NSE scripts. Nmap is never bundled or downloaded by the
//! app; it is found on the system, and the built-in engine is used when it is
//! missing.
//!
//! # Safety rules (see `docs/SECURITY-REVIEW.md`, section 17)
//!
//! * **No shell.** Nmap is started with [`Command`] and a fixed argument list.
//!   Nothing the user types and nothing a device sends is ever placed on the
//!   command line: the only variable parts are numbers (ports) built from
//!   `u16` values. Target addresses are written to Nmap's standard input
//!   (`-iL -`) as validated IPv4 addresses.
//! * **Safe scripts only.** [`SCRIPTS_ASSESS`] selects scripts that Nmap
//!   itself classifies as `safe` and removes every category that could harm a
//!   device or contact a third party (`intrusive`, `dos`, `exploit`, `brute`,
//!   `fuzzer`, `malware`, `external`, `broadcast`), plus two `safe` scripts
//!   that hold connections open (`http-slowloris-check`) or ask the FTP server
//!   to connect to another host (`ftp-bounce`).
//! * **Admin rights only for a deep scan, only for that one run.** Normal
//!   scans run Nmap as the current user (TCP connect scan). A deep scan
//!   (SYN scan + OS detection) needs raw sockets: on Linux it asks for the
//!   administrator password through `pkexec` for that single Nmap process —
//!   and only if Nmap is a root-owned file in a system directory, so a
//!   program the user (or malware running as the user) could replace is never
//!   started as root. On Windows, Nmap uses the Npcap driver (`--privileged`)
//!   and no elevation is requested. Nothing keeps running with admin rights
//!   after the scan.
//! * **Bounded resources.** Output is read line by line and one host is
//!   parsed at a time ([`parse::Stream`]); Stop ends the process.

pub mod parse;

pub use parse::{NmapHost, NmapPort, Script};

use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::scanner::Speed;

/// Where users can get Nmap (opened in the browser from the app).
pub const DOWNLOAD_URL: &str = "https://nmap.org/download.html";

/// Script selection for vulnerability assessments: Nmap's `default` and
/// `vuln` scripts that are also `safe`, without any risky category.
pub const SCRIPTS_ASSESS: &str = "(default or vuln) and safe and not (broadcast or external or brute or dos or \
                                  exploit or intrusive or fuzzer or malware or http-slowloris-check or ftp-bounce)";

/// Scripts that log in (anonymously) or test an authentication bypass; left
/// out when "Safe login checks" is switched off.
const LOGIN_SCRIPTS: &str = "ftp-anon or http-frontpage-login or realvnc-auth-bypass or netbus-auth-bypass or \
                             x11-access or mongodb-databases";

/// Script selection for device identification in the Network Scanner tab:
/// the `default` + `safe` scripts that tell what a device is (names, titles,
/// certificates, SMB/OS information), nothing vulnerability-related.
pub const SCRIPTS_IDENTIFY: &str = "default and safe and not (broadcast or external or brute or dos or exploit or \
                                    intrusive or fuzzer or malware or vuln or ftp-bounce or ftp-anon or \
                                    http-frontpage-login)";

/// The Nmap found on this computer.
#[derive(Clone, Debug, PartialEq)]
pub struct NmapInfo {
    pub path: PathBuf,
    /// e.g. "7.94SVN".
    pub version: String,
    /// Linux: owned by root, in a system directory, not writable by anyone
    /// else — the only kind of Nmap a deep scan will start as root.
    pub trusted: bool,
}

impl NmapInfo {
    /// "Nmap 7.94SVN" for the UI.
    pub fn label(&self) -> String {
        format!("Nmap {}", self.version)
    }
}

/// Cached result of looking for Nmap (outer None = not looked yet).
static FOUND: Mutex<Option<Option<NmapInfo>>> = Mutex::new(None);

/// Nmap on this computer (looked up once, then cached; see [`refresh`]).
pub fn find() -> Option<NmapInfo> {
    let mut cache = FOUND.lock().unwrap_or_else(|e| e.into_inner());
    if cache.is_none() {
        *cache = Some(locate());
    }
    cache.clone().flatten()
}

/// Look for Nmap again (after the user installed it).
pub fn refresh() -> Option<NmapInfo> {
    let found = locate();
    *FOUND.lock().unwrap_or_else(|e| e.into_inner()) = Some(found.clone());
    found
}

/// Candidate paths, most trusted first; only absolute directories from PATH
/// are used (a relative entry such as `.` could pick up a planted program).
fn candidates() -> Vec<PathBuf> {
    let exe = if cfg!(windows) { "nmap.exe" } else { "nmap" };
    let mut out: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    out.extend(["/usr/bin/nmap", "/usr/local/bin/nmap", "/usr/sbin/nmap", "/snap/bin/nmap"].map(PathBuf::from));
    #[cfg(windows)]
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(dir) = std::env::var_os(var) {
            out.push(PathBuf::from(dir).join("Nmap").join(exe));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
            out.push(dir.join(exe));
        }
    }
    let mut seen = Vec::new();
    out.retain(|p| {
        let new = !seen.contains(p);
        seen.push(p.clone());
        new
    });
    out
}

/// Why the Nmap features are unavailable, for tooltips and Settings.
pub fn missing_text() -> &'static str {
    "Optional: install Nmap (Linux: your package manager, e.g. 'sudo apt install nmap'; Windows: nmap.org), \
     then Settings → Look again."
}

/// Find the first candidate that is a working Nmap 7+.
fn locate() -> Option<NmapInfo> {
    for path in candidates() {
        if !path.is_file() {
            continue;
        }
        if let Some(version) = version_of(&path) {
            let trusted = is_trusted(&path);
            return Some(NmapInfo { path, version, trusted });
        }
    }
    None
}

/// Run `nmap --version` (5 s limit) and read "Nmap version 7.94SVN".
fn version_of(path: &Path) -> Option<String> {
    let mut cmd = Command::new(path);
    cmd.arg("--version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    hide_window(&mut cmd);
    let mut child = cmd.spawn().ok()?;
    let mut out = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.by_ref().take(16 * 1024).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let buf = rx.recv_timeout(Duration::from_secs(5)).ok();
    let _ = child.kill();
    let _ = child.wait();
    let text = String::from_utf8_lossy(&buf?).to_string();
    let v = text.lines().find_map(|l| l.trim().strip_prefix("Nmap version "))?.split_whitespace().next()?;
    let v = parse::clean(v, 20);
    // Nmap 7 or newer (2015+): the XML format and script categories we rely on.
    let major: u32 = v.split('.').next()?.parse().ok()?;
    (major >= 7).then_some(v)
}

/// Can this file safely be started as root? (Linux / Unix)
#[cfg(unix)]
pub fn is_trusted(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    /// The only folders an Nmap may be in to be started as root.
    const SYSTEM_DIRS: [&str; 5] = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"];
    let Ok(real) = std::fs::canonicalize(path) else { return false };
    if !real.parent().is_some_and(|d| SYSTEM_DIRS.iter().any(|s| d == Path::new(s))) {
        return false;
    }
    // The file and every directory above it: owned by root, not writable by
    // group or others (so nobody but root can replace it).
    let mut cur = Some(real.as_path());
    while let Some(p) = cur {
        match std::fs::metadata(p) {
            Ok(m) if m.uid() == 0 && m.mode() & 0o022 == 0 => {}
            _ => return false,
        }
        cur = p.parent();
    }
    true
}

/// Windows: never elevated, so nothing to check.
#[cfg(not(unix))]
pub fn is_trusted(_path: &Path) -> bool {
    // Windows never elevates Nmap (Npcap provides raw access).
    true
}

/// Are we already root? (`/proc/self/status`, effective uid.)
#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(2) == Some("0")))
        .unwrap_or(false)
}

/// Windows: start Nmap without flashing a console window.
#[cfg(windows)]
fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    /// Process creation flag that hides the console window.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

/// Other systems: nothing to hide.
#[cfg(not(windows))]
fn hide_window(_cmd: &mut Command) {}

/// What to run.
#[derive(Clone, Debug)]
pub struct Request {
    pub targets: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
    pub speed: Speed,
    /// SYN scan + OS detection (needs admin rights on Linux).
    pub deep: bool,
    pub scripts: Scripts,
}

/// Which NSE scripts Nmap runs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scripts {
    /// Version detection only (used by the tests: fastest).
    #[cfg_attr(not(test), allow(dead_code))]
    None,
    /// [`SCRIPTS_IDENTIFY`].
    Identify,
    /// [`SCRIPTS_ASSESS`]; `logins` keeps the anonymous-login scripts.
    Assess { logins: bool },
}

/// Something Nmap reported while running.
#[derive(Debug)]
pub enum Event {
    /// Current Nmap task ("Connect Scan", "Service scan", "NSE") and percent.
    Progress(String, f32),
    Host(Box<NmapHost>),
}

/// `22,80,443,8000-8100` — compact, sorted, from validated numbers only.
pub fn ports_arg(ports: &[u16]) -> String {
    let mut p: Vec<u16> = ports.iter().copied().filter(|&p| p > 0).collect();
    p.sort_unstable();
    p.dedup();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < p.len() {
        let start = p[i];
        let mut end = start;
        while i + 1 < p.len() && p[i + 1] == end + 1 {
            i += 1;
            end = p[i];
        }
        out.push(if start == end { start.to_string() } else { format!("{start}-{end}") });
        i += 1;
    }
    out.join(",")
}

/// The full argument list (without the program name). Pure, unit-tested.
pub fn arguments(req: &Request) -> Vec<String> {
    let mut a: Vec<String> = [
        "-n",  // no DNS lookups (Proton resolves names itself)
        "-Pn", // targets are known to be live (Proton found them)
        "--noninteractive",
        "-oX",
        "-", // XML to standard output, nothing written to disk
        "--stats-every",
        "2s",
        "-iL",
        "-", // targets from standard input
        "-sV",
    ]
    .map(String::from)
    .to_vec();
    if req.deep {
        a.extend(["-sS", "-O", "--osscan-limit"].map(String::from));
        if cfg!(windows) {
            a.push("--privileged".into());
        }
    } else {
        a.push("-sT".into());
    }
    a.push("-p".into());
    a.push(ports_arg(&req.ports));
    match req.speed {
        Speed::Normal => a.extend(["-T4", "--host-timeout", "20m", "--script-timeout", "30s"].map(String::from)),
        Speed::Polite => a.extend(
            [
                "-T3",
                "--max-parallelism",
                "8",
                "--scan-delay",
                "150ms",
                "--max-scan-delay",
                "400ms",
                "--randomize-hosts",
                "--host-timeout",
                "45m",
                "--script-timeout",
                "60s",
            ]
            .map(String::from),
        ),
        Speed::Slow => a.extend(
            [
                "-T2",
                "--max-parallelism",
                "2",
                "--scan-delay",
                "1s",
                "--max-scan-delay",
                "3s",
                "--randomize-hosts",
                "--host-timeout",
                "120m",
                "--script-timeout",
                "120s",
            ]
            .map(String::from),
        ),
    }
    match req.scripts {
        Scripts::None => {}
        Scripts::Identify => {
            a.push("--script".into());
            a.push(SCRIPTS_IDENTIFY.into());
        }
        Scripts::Assess { logins } => {
            a.push("--script".into());
            if logins {
                a.push(SCRIPTS_ASSESS.into());
            } else {
                a.push(format!("({SCRIPTS_ASSESS}) and not ({LOGIN_SCRIPTS})"));
            }
        }
    }
    a
}

/// How the run ended.
#[derive(Debug, Default)]
pub struct Summary {
    pub hosts: usize,
    /// Host blocks that were too large or malformed.
    pub skipped: usize,
    pub cancelled: bool,
}

/// Run Nmap and report results through `on_event` (on the calling thread).
/// Blocks until Nmap finishes, fails, or `cancel` is set.
pub fn run(req: &Request, cancel: &AtomicBool, mut on_event: impl FnMut(Event)) -> Result<Summary, String> {
    if req.targets.is_empty() || req.ports.is_empty() {
        return Ok(Summary::default());
    }
    let info = find().ok_or("Nmap is not installed")?;
    let mut cmd = command(&info, req.deep)?;
    cmd.args(arguments(req)).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Nmap also looks for its scripts in the current directory, so start it
    // in one nobody else can write to: "/" on Linux, Nmap's own folder on Windows.
    #[cfg(unix)]
    cmd.current_dir("/");
    #[cfg(not(unix))]
    if let Some(dir) = info.path.parent() {
        cmd.current_dir(dir);
    }
    hide_window(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| format!("could not start Nmap: {e}"))?;

    // Targets → stdin (in a thread: Nmap reads them while it scans).
    if let Some(mut stdin) = child.stdin.take() {
        let list: String = req.targets.iter().map(|ip| format!("{ip}\n")).collect();
        std::thread::spawn(move || {
            let _ = stdin.write_all(list.as_bytes());
        });
    }
    // Keep the end of stderr for error messages.
    let errors = Arc::new(Mutex::new(String::new()));
    if let Some(mut stderr) = child.stderr.take() {
        let errors = errors.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut e) = errors.lock() {
                    e.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if e.len() > 8192 {
                        let cut = e.len() - 4096;
                        let cut = (cut..e.len()).find(|&i| e.is_char_boundary(i)).unwrap_or(e.len());
                        e.drain(..cut);
                    }
                }
            }
        });
    }
    // stdout is read on its own thread so Stop works even while Nmap is
    // silent (e.g. waiting for the password dialog).
    let stop_reader = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<parse::Item>();
    let stdout = child.stdout.take().ok_or("Nmap has no output")?;
    {
        let stop = stop_reader.clone();
        std::thread::Builder::new()
            .name("nmap-output".into())
            .spawn(move || read_output(stdout, &stop, &tx))
            .map_err(|e| format!("could not start a thread: {e}"))?;
    }

    let mut summary = Summary::default();
    let mut finished_error: Option<String> = None;
    loop {
        if cancel.load(Ordering::Relaxed) {
            summary.cancelled = true;
            break;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(parse::Item::Host(h)) => {
                summary.hosts += 1;
                on_event(Event::Host(h));
            }
            Ok(parse::Item::Progress(task, pct)) => on_event(Event::Progress(task, pct)),
            Ok(parse::Item::Skipped) => summary.skipped += 1,
            Ok(parse::Item::Finished(exit, msg)) => {
                if exit == "error" {
                    finished_error = Some(msg.unwrap_or_else(|| "Nmap reported an error".into()));
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    if summary.cancelled {
        stop_reader.store(true, Ordering::Relaxed);
        // Works for Nmap started as the user. A root Nmap cannot be signalled
        // by us; it ends at its next progress line (≤ 2 s) because the reader
        // closes the pipe and Nmap gets "broken pipe".
        let _ = child.kill();
        reap_later(child);
        return Ok(summary);
    }
    let status = wait_with_timeout(child, Duration::from_secs(10));
    let err_text = errors.lock().map(|e| e.clone()).unwrap_or_default();
    let last_err = err_text
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && !l.starts_with("WARNING") && !l.starts_with("Warning"))
        .map(|l| parse::clean(l, 300));
    if let Some(e) = finished_error {
        return Err(e);
    }
    match status {
        Some(0) => Ok(summary),
        // pkexec: 126 = the dialog was dismissed, 127 = not authorised.
        Some(126) | Some(127) if req.deep && uses_pkexec() => {
            Err("administrator authorisation was cancelled or refused, so the deep scan did not run".into())
        }
        Some(code) => Err(last_err.unwrap_or_else(|| format!("Nmap stopped with exit code {code}"))),
        None if summary.hosts > 0 => Ok(summary),
        None => Err(last_err.unwrap_or_else(|| "Nmap ended unexpectedly".into())),
    }
}

/// Start [`run`] on a background thread; events and the result arrive on the channel.
pub fn spawn(req: Request, cancel: Arc<AtomicBool>) -> mpsc::Receiver<Result<Event, (String, Summary)>> {
    let (tx, rx) = mpsc::channel();
    let t = tx.clone();
    let spawned = std::thread::Builder::new().name("nmap".into()).spawn(move || {
        let result = run(&req, &cancel, |ev| {
            let _ = t.send(Ok(ev));
        });
        let _ = t.send(Err(match result {
            Ok(s) => (String::new(), s),
            Err(e) => (e, Summary::default()),
        }));
    });
    if spawned.is_err() {
        let _ = tx.send(Err(("the system refused a new thread".into(), Summary::default())));
    }
    rx
}

/// Linux: a deep scan goes through pkexec unless we already run as root.
#[cfg(target_os = "linux")]
fn uses_pkexec() -> bool {
    !running_as_root()
}
/// Other systems never use pkexec.
#[cfg(not(target_os = "linux"))]
fn uses_pkexec() -> bool {
    false
}

/// The command that starts Nmap, elevated through pkexec for a deep scan on Linux.
fn command(info: &NmapInfo, deep: bool) -> Result<Command, String> {
    #[cfg(target_os = "linux")]
    if deep && !running_as_root() {
        let pkexec = Path::new("/usr/bin/pkexec");
        if !pkexec.is_file() || !is_trusted(pkexec) {
            return Err("a deep scan needs administrator rights, but pkexec (polkit) is not installed".into());
        }
        // Check and run the *resolved* file: a symlink that points to a
        // trusted Nmap could be changed after the check, the real file cannot.
        let real = std::fs::canonicalize(&info.path).unwrap_or_default();
        if !info.trusted || !is_trusted(&real) {
            return Err(format!(
                "a deep scan runs Nmap with administrator rights, which is only done for an Nmap installed by the \
                 system's package manager (owned by root, e.g. /usr/bin/nmap). The Nmap at {} is not, so only \
                 normal scans can use it",
                info.path.display()
            ));
        }
        // Absolute, resolved path, verified above; pkexec gives Nmap a clean
        // environment and shows this path in its password dialog.
        let mut c = Command::new(pkexec);
        c.arg(real);
        return Ok(c);
    }
    let _ = deep;
    Ok(Command::new(&info.path))
}

/// Read Nmap's stdout line by line (each line capped at the host-block
/// limit) and pass complete items on.
fn read_output(stdout: impl Read, stop: &AtomicBool, tx: &mpsc::Sender<parse::Item>) {
    let mut reader = BufReader::with_capacity(64 * 1024, stdout);
    let mut stream = parse::Stream::default();
    let mut line = Vec::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return; // dropping the pipe ends a root Nmap ("broken pipe")
        }
        line.clear();
        match read_line_capped(&mut reader, &mut line, parse::MAX_HOST_XML + 1) {
            Ok(0) => return,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                if let Some(item) = stream.push_line(text.trim_end_matches(['\r', '\n']))
                    && tx.send(item).is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// `read_until('\n')`, but never keeps more than `max` bytes of one line
/// (the rest of an over-long line is read and discarded).
fn read_line_capped(r: &mut impl BufRead, out: &mut Vec<u8>, max: usize) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return Ok(total);
        }
        let (chunk, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..=i], true),
            None => (buf, false),
        };
        let keep = chunk.len().min(max.saturating_sub(out.len()));
        out.extend_from_slice(&chunk[..keep]);
        let n = chunk.len();
        total += n;
        r.consume(n);
        if done {
            return Ok(total);
        }
    }
}

/// Wait up to `limit` for the process to exit; kill it (and reap it later) if it does not.
fn wait_with_timeout(mut child: Child, limit: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                reap_later(child);
                return None;
            }
        }
    }
}

/// Collect the exit status in the background so no zombie process remains.
fn reap_later(mut child: Child) {
    let _ = std::thread::Builder::new().name("nmap-reaper".into()).stack_size(64 * 1024).spawn(move || {
        let _ = child.wait();
    });
}

/// Copy what Nmap found about a device into the Network Scanner's [`Host`](crate::scanner::Host):
/// operating system, service versions (shown as the port's banner), MAC
/// address and name when Proton had none, and identification script output.
pub fn apply_to_host(host: &mut crate::scanner::Host, n: &NmapHost) {
    use crate::scanner::ports::{OpenPort, service_name};
    // Operating system: OS detection (deep), else what services reported.
    let os = n.os.as_ref().map(|o| o.label()).or_else(|| {
        n.scripts
            .iter()
            .chain(n.ports.iter().flat_map(|p| p.scripts.iter()))
            .find(|s| s.id == "smb-os-discovery")
            .and_then(|s| s.output.lines().find_map(|l| l.trim().strip_prefix("OS: ").map(|o| parse::clean(o, 100))))
            // Services' own OS hints; a specific one ("Linux") beats "Unix".
            .or_else(|| {
                let hints = || n.ports.iter().filter_map(|p| p.ostype.clone());
                hints().find(|o| o != "Unix").or_else(|| hints().next())
            })
    });
    if os.is_some() {
        host.os = os;
    }
    if host.mac.is_none()
        && let Some(mac) = n.mac.as_deref().and_then(crate::scanner::mac::Mac::parse)
    {
        host.vendor = crate::scanner::vendor::lookup(&mac);
        host.mac = Some(mac);
    }
    if host.dns_name.is_none() {
        host.dns_name = n.hostname.clone();
    }
    let list = host.ports.get_or_insert_with(Vec::new);
    for p in &n.ports {
        let banner = p.description();
        match list.iter_mut().find(|o| o.port == p.port) {
            Some(o) => {
                if banner.is_some() {
                    o.banner = banner;
                }
            }
            None => list.push(OpenPort { port: p.port, service: service_name(p.port), banner }),
        }
    }
    list.sort_by_key(|p| p.port);
    host.nmap_scripts.clear();
    let scripts = n
        .scripts
        .iter()
        .map(|s| (String::new(), s))
        .chain(n.ports.iter().flat_map(|p| p.scripts.iter().map(move |s| (format!("{} ", p.port), s))));
    for (prefix, s) in scripts.filter(|(_, s)| !s.failed() && !s.output.is_empty()).take(48) {
        host.nmap_scripts.push((format!("{prefix}{}", s.id), s.output.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges() {
        assert_eq!(ports_arg(&[443, 22, 80, 81, 82, 22, 0, 65535]), "22,80-82,443,65535");
        assert_eq!(ports_arg(&(1..=1024).collect::<Vec<_>>()), "1-1024");
        assert_eq!(ports_arg(&[]), "");
    }

    #[test]
    fn arguments_are_fixed_and_safe() {
        let req = Request {
            targets: vec![Ipv4Addr::new(10, 0, 0, 1)],
            ports: vec![22, 80],
            speed: Speed::Slow,
            deep: false,
            scripts: Scripts::Assess { logins: false },
        };
        let a = arguments(&req);
        assert!(a.contains(&"-sT".to_string()));
        assert!(!a.iter().any(|x| x == "-sS" || x == "-O"));
        assert!(a.windows(2).any(|w| w[0] == "-p" && w[1] == "22,80"));
        assert!(a.windows(2).any(|w| w[0] == "-iL" && w[1] == "-"));
        let script = a.iter().skip_while(|x| *x != "--script").nth(1).unwrap();
        for bad in ["intrusive", "dos", "exploit", "brute", "external", "broadcast", "ftp-anon"] {
            assert!(script.contains(bad), "{bad} must be excluded explicitly");
        }
        assert!(script.starts_with("((default or vuln) and safe"));
        // No target address on the command line.
        assert!(!a.iter().any(|x| x.contains("10.0.0.1")));
        let deep = arguments(&Request { deep: true, ..req });
        assert!(deep.contains(&"-sS".to_string()) && deep.contains(&"-O".to_string()));
    }

    #[test]
    fn capped_line_reader() {
        let data = format!("short\n{}\nend", "x".repeat(100));
        let mut r = BufReader::with_capacity(16, data.as_bytes());
        let mut line = Vec::new();
        assert_eq!(read_line_capped(&mut r, &mut line, 50).unwrap(), 6);
        assert_eq!(line, b"short\n");
        line.clear();
        assert_eq!(read_line_capped(&mut r, &mut line, 50).unwrap(), 101);
        assert_eq!(line.len(), 50);
        line.clear();
        assert_eq!(read_line_capped(&mut r, &mut line, 50).unwrap(), 3);
        line.clear();
        assert_eq!(read_line_capped(&mut r, &mut line, 50).unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn trust_rules() {
        // A file in a temporary (user-writable) directory is never trusted.
        let p = std::env::temp_dir().join(format!("nmap-trust-{}", std::process::id()));
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        assert!(!is_trusted(&p));
        let _ = std::fs::remove_file(&p);
        if Path::new("/usr/bin/nmap").exists() {
            assert!(is_trusted(Path::new("/usr/bin/nmap")));
        }
    }

    #[test]
    fn host_gets_os_versions_and_mac() {
        let xml = include_str!("testdata/vulns.xml");
        let n =
            parse::parse_host(&xml[xml.find("<host ").unwrap()..xml.find("</host>").unwrap() + 7]).unwrap().unwrap();
        let mut h = crate::scanner::Host {
            ip: Ipv4Addr::new(192, 168, 1, 20),
            role: crate::scanner::Role::Device,
            method: crate::scanner::Method::Ping,
            rtt: None,
            mac: None,
            vendor: None,
            dns_name: None,
            netbios_name: None,
            local_name: None,
            upnp_name: None,
            workgroup: None,
            ports: None,
            os: None,
            nmap_scripts: vec![],
        };
        apply_to_host(&mut h, &n);
        assert_eq!(h.os.as_deref(), Some("Linux 4.15 - 5.8 (96%, general purpose)"));
        assert_eq!(h.mac.map(|m| m.to_string()).as_deref(), Some("00:11:32:AA:BB:CC"));
        assert!(h.vendor.is_some_and(|v| v.contains("Synology")));
        assert_eq!(h.dns_name.as_deref(), Some("nas.lan"));
        let ports = h.ports.as_ref().unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].banner.as_deref(), Some("nginx 1.18.0"));
        assert!(h.nmap_scripts.iter().any(|(k, _)| k == "smb2-security-mode"));
        assert!(h.nmap_scripts.iter().any(|(k, _)| k == "443 ssl-heartbleed"));
    }

    /// Real Nmap against local fake services (skipped when Nmap is missing).
    #[test]
    fn real_nmap_run() {
        let Some(info) = find() else { return };
        assert!(info.version.starts_with('7') || info.version.starts_with('8'));
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let _ = s.write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n");
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let req = Request {
            targets: vec![Ipv4Addr::LOCALHOST],
            ports: vec![port],
            speed: Speed::Normal,
            deep: false,
            scripts: Scripts::None,
        };
        let mut hosts = Vec::new();
        let cancel = AtomicBool::new(false);
        let summary = run(&req, &cancel, |ev| {
            if let Event::Host(h) = ev {
                hosts.push(*h);
            }
        })
        .unwrap();
        assert_eq!(summary.hosts, 1);
        let p = &hosts[0].ports[0];
        assert_eq!(p.port, port);
        assert_eq!(p.product.as_deref(), Some("OpenSSH"));
        assert!(p.cpes.iter().any(|c| c.starts_with("cpe:/a:openbsd:openssh:8.9p1")));
    }

    /// Stop ends a long Nmap run quickly.
    #[test]
    fn cancel_is_quick() {
        if find().is_none() {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let req = Request {
            // TEST-NET addresses: nothing answers, so Nmap would wait a long time.
            targets: (1..=50).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect(),
            ports: (1..=2000).collect(),
            speed: Speed::Slow,
            deep: false,
            scripts: Scripts::None,
        };
        let rx = spawn(req, cancel.clone());
        std::thread::sleep(Duration::from_millis(1500));
        let t = Instant::now();
        cancel.store(true, Ordering::Relaxed);
        loop {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Err((e, s))) => {
                    assert!(e.is_empty() && s.cancelled, "{e}");
                    break;
                }
                Ok(Ok(_)) => {}
                Err(e) => panic!("no result after Stop: {e}"),
            }
        }
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
