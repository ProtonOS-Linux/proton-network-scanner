//! Saving scan results as CSV (for spreadsheets) or HTML (a readable report).
//!
//! Security:
//! * Every CSV cell is quoted, and cells that start with `= + - @` or a tab
//!   get a leading `'` so spreadsheet apps never run them as formulas
//!   ("CSV injection").
//! * Every HTML value is escaped; the report contains no scripts or links to
//!   the internet.
//! * Files are created with `create_new`, so an existing file — or a symbolic
//!   link planted at that name — is never overwritten.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::scanner::Host;

/// File format for [`save`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Csv,
    Html,
}

/// Write `hosts` to a new, time-stamped file in the user's Documents folder
/// (or home folder) and return its path.
pub fn save(hosts: &[Host], format: Format) -> std::io::Result<PathBuf> {
    let (ext, body) = match format {
        Format::Csv => ("csv", to_csv(hosts)),
        Format::Html => ("html", to_html(hosts)),
    };
    save_bytes("proton-ip-scan", ext, body.as_bytes())
}

/// Save `bytes` as `<prefix>-<YYYYMMDD-HHMMSS>.<ext>` in the Documents (or
/// home) folder. Never overwrites: an existing name gets `-2`, `-3`… and the
/// file is created with `create_new`, so a planted symlink is not followed.
pub fn save_bytes(prefix: &str, ext: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let dir = dirs::document_dir().or_else(dirs::home_dir).unwrap_or_else(std::env::temp_dir);
    let stamp = timestamp_for_filename(SystemTime::now());
    let mut path = dir.join(format!("{prefix}-{stamp}.{ext}"));
    let mut n = 2;
    let mut file = loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 100 => {
                path = dir.join(format!("{prefix}-{stamp}-{n}.{ext}"));
                n += 1;
            }
            Err(e) => return Err(e),
        }
    };
    file.write_all(bytes)?;
    Ok(path)
}

/// Open the system file manager at `path`: a folder is opened, a file is
/// shown selected in its folder where the file manager supports it.
///
/// * Linux: asks the desktop's file manager over D-Bus
///   (`org.freedesktop.FileManager1.ShowItems`, supported by Dolphin and
///   Nautilus) to show the file selected; if that is not available,
///   `xdg-open` opens the folder.
/// * Windows: `explorer.exe /select,"file"` (or the folder).
///
/// Programs are started directly with an argument list (no shell); the path
/// is one the app created itself. Runs in the background, so a slow file
/// manager never freezes the window; the child processes are waited for, so
/// none is left behind.
pub fn show_in_folder(path: &Path) {
    let path = path.to_path_buf();
    let _ = std::thread::Builder::new().name("show-in-folder".into()).stack_size(128 * 1024).spawn(move || {
        reveal(&path);
    });
}

/// Linux: file manager over D-Bus (file selected), else `xdg-open` on the folder.
#[cfg(target_os = "linux")]
fn reveal(path: &Path) {
    use std::process::{Command, Stdio};
    let quiet = |c: &mut Command| {
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    };
    if path.is_file() {
        let mut c = Command::new("dbus-send");
        c.args([
            "--session",
            "--print-reply",
            "--reply-timeout=3000",
            "--dest=org.freedesktop.FileManager1",
            "--type=method_call",
            "/org/freedesktop/FileManager1",
            "org.freedesktop.FileManager1.ShowItems",
        ])
        .arg(format!("array:string:{}", file_uri(path)))
        .arg("string:");
        quiet(&mut c);
        if c.status().is_ok_and(|s| s.success()) {
            return;
        }
    }
    let dir = if path.is_dir() { path } else { path.parent().unwrap_or(path) };
    let mut c = Command::new("xdg-open");
    c.arg(dir);
    quiet(&mut c);
    let _ = c.status();
}

/// Windows: Explorer with the file selected (or the folder opened).
#[cfg(windows)]
fn reveal(path: &Path) {
    use std::os::windows::process::CommandExt;
    let mut c = std::process::Command::new("explorer.exe");
    if path.is_file() {
        // Explorer needs exactly `/select,"C:\path\file"` (one argument with
        // the quotes inside), so it is passed raw. Windows paths cannot
        // contain `"`, so the quoting cannot be broken.
        c.raw_arg(format!("/select,\"{}\"", path.display()));
    } else {
        c.arg(path);
    }
    let _ = c.status();
}

/// Other systems (macOS): `open` on the folder.
#[cfg(not(any(target_os = "linux", windows)))]
fn reveal(path: &Path) {
    let dir = if path.is_dir() { path } else { path.parent().unwrap_or(path) };
    let _ = std::process::Command::new("open").arg(dir).status();
}

/// `file://` URI for a path: every byte except unreserved characters and `/`
/// is percent-encoded (so commas and spaces cannot split the D-Bus argument).
#[cfg(any(target_os = "linux", test))]
fn file_uri(path: &Path) -> String {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = path.to_string_lossy().as_bytes().to_vec();
    let mut out = String::from("file://");
    for b in bytes {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Current time as "2026-11-02 21:40 UTC" (for report headers).
pub fn now_readable() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs % 86_400 / 3600, secs % 3600 / 60)
}

/// Comma-separated values, one row per host.
pub fn to_csv(hosts: &[Host]) -> String {
    let mut out = String::from(
        "IP,Name,DNS name,NetBIOS name,mDNS/LLMNR name,UPnP name,Workgroup,MAC,Manufacturer,Response ms,Detected by,Open ports,Operating system\r\n",
    );
    for h in hosts {
        let cells = [
            h.ip.to_string(),
            h.display_name().to_string(),
            h.dns_name.clone().unwrap_or_default(),
            h.netbios_name.clone().unwrap_or_default(),
            h.local_name.clone().unwrap_or_default(),
            h.upnp_name.clone().unwrap_or_default(),
            h.workgroup.clone().unwrap_or_default(),
            h.mac.map(|m| m.to_string()).unwrap_or_default(),
            h.vendor.unwrap_or_default().to_string(),
            h.rtt.map(|d| format!("{:.1}", d.as_secs_f64() * 1000.0)).unwrap_or_default(),
            h.method.label().to_string(),
            ports_text(h),
            h.os.clone().unwrap_or_default(),
        ];
        let row: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

/// Quote a CSV cell and neutralise spreadsheet formulas.
fn csv_cell(s: &str) -> String {
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

/// `22 (SSH); 80 (HTTP)` or empty.
fn ports_text(h: &Host) -> String {
    match &h.ports {
        None => String::new(),
        Some(p) if p.is_empty() => "none found".into(),
        Some(p) => p
            .iter()
            .map(|o| if o.service.is_empty() { o.port.to_string() } else { format!("{} ({})", o.port, o.service) })
            .collect::<Vec<_>>()
            .join("; "),
    }
}

/// A standalone HTML report with inline styling.
pub fn to_html(hosts: &[Host]) -> String {
    let mut rows = String::new();
    for h in hosts {
        let _ = writeln!(
            rows,
            "<tr><td>{}</td><td>{}</td><td class=m>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&h.ip.to_string()),
            esc(h.display_name()),
            esc(&h.mac.map(|m| m.to_string()).unwrap_or_default()),
            esc(h.vendor.unwrap_or_default()),
            esc(&h.rtt.map(|d| format!("{:.1} ms", d.as_secs_f64() * 1000.0)).unwrap_or_default()),
            esc(&ports_text(h)),
        );
    }
    format!(
        "<!doctype html>\n<html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
<title>Proton IP Scanner report</title><style>\
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1d2433;background:#f6f8fb}}\
h1{{font-size:1.4rem;margin:0 0 .25rem}}p{{color:#5a6478;margin:0 0 1rem}}\
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px #0002}}\
th,td{{padding:.45rem .7rem;text-align:left;border-bottom:1px solid #e3e7ee;font-size:.9rem}}\
th{{background:#1f6feb;color:#fff;font-weight:600}}td.m{{font-family:ui-monospace,monospace}}\
</style></head><body><h1>Proton IP Scanner report</h1><p>{} live device(s) · generated {}</p>\
<table><thead><tr><th>IP</th><th>Name</th><th>MAC</th><th>Manufacturer</th><th>Response</th><th>Open ports</th></tr></thead>\
<tbody>\n{rows}</tbody></table></body></html>\n",
        hosts.len(),
        esc(&timestamp_for_filename(SystemTime::now()).replace('-', " ")),
    )
}

/// Escape text for HTML element content and attribute values.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// `YYYYMMDD-HHMMSS` in UTC, without pulling in a date library.
fn timestamp_for_filename(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uris_are_encoded() {
        assert_eq!(file_uri(Path::new("/home/a b/Report, v1.pdf")), "file:///home/a%20b/Report%2C%20v1.pdf");
    }
    use std::time::Duration;

    #[test]
    fn csv_injection_is_neutralised() {
        assert_eq!(csv_cell("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_cell("-cmd"), "\"'-cmd\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("192.168.1.1"), "\"192.168.1.1\"");
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(esc("<img src=x onerror='a'>&"), "&lt;img src=x onerror=&#39;a&#39;&gt;&amp;");
    }

    #[test]
    fn dates() {
        assert_eq!(timestamp_for_filename(UNIX_EPOCH), "19700101-000000");
        // 2026-10-31 04:05:06 UTC
        assert_eq!(timestamp_for_filename(UNIX_EPOCH + Duration::from_secs(1_793_419_506)), "20261031-040506");
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }
}
