# Changelog

## 1.3.0 — 2026-11-03

### New
- **Windows installer** (`ProtonIPScanner-1.3.0-Setup.exe`): Program Files, Start menu + desktop shortcuts,
  uninstaller in Settings → Apps, and a firewall rule for private networks. The .exe now carries an icon,
  version information and a manifest (runs as a normal user, sharp on high-DPI screens).
- **⟳ Update CVE database** button, and **automatic update of the local CVE database when the app opens**
  (background, at most about once a day, quiet without internet). Setting remembered in settings.json.
- Releases are built and published automatically from version tags; the .deb reaches Proton OS through the
  Proton OS APT repository (Discover / apt updates).

### Changed
- The Linux build targets glibc 2.30, so the .deb installs on Debian 11+ and Ubuntu 20.04+ (was 24.04+ only).
- Package dependencies list the window libraries explicitly; the desktop entry passes validation.
- Project moved to github.com/ProtonOS-Linux/proton-network-scanner.

## 1.2.0 — 2026-11-03

### New
- **Offline vulnerability database** for networks without internet: download once (Database → Download),
  export to a file, import on the offline computer. Versions are matched locally against each CVE's
  version ranges. *Online* mode falls back to it automatically when NVD can't be reached.
- **Port lists for assessments**: Standard (52), **Comprehensive (1,298)** and **Full scan (65,535)**.
- Vulnerability targets can be the **selected device** from the Network Scanner tab.
- **More names**: router DNS asked directly, **UPnP friendly names** (TVs, NAS, printers, media players),
  and a multicast mDNS/UPnP sweep for devices that only answer multicast.
- Right-click **Copy manufacturer** and **Copy all details**; right-click → Copy on every detail value.
- Command line: `--cve online|offline|off`, `--update-db`, `--export-db`, `--import-db`.

### Changed
- **Every assessment starts fresh**: no CVE lookup cache between scans (the 1.1.0 cache is deleted on
  start); results, notes and filters are cleared. New **✖ Clear** button.
- Network toolbar order is now **My network → IP range → Scan**.
- No text-selection cursor anywhere: clicking a name, IP or MAC selects the row.

## 1.1.0 — 2026-11-02

### New
- **Vulnerability Scanner tab**: service detection, 14 safe configuration checks, known CVEs from
  NIST NVD with **CVSS v4.0**, **EPSS** (FIRST), **CISA KEV** and a VPR-style **priority rating (PPR)**;
  Top 10 view, severity filter, finding details.
- **Excel (.xlsx) and PDF reports** of vulnerability findings.
- **Slow probing**: Normal / Polite / Slow-stealthy speeds (fewer probes, random pauses, shuffled order).
- **Ping test** window: live latency chart, packet loss, min/avg/max, jitter, verdict.
- Command line: `--vuln`, `--report pdf|xlsx`, `--offline`, `--stealth`, `--slow`, `--no-ports`.

### Improved
- A normal scan now also checks the **28 common ports** on every device found (can be turned off).
- **More names**: mDNS (Bonjour/Avahi) and LLMNR, asked in parallel with NetBIOS.
- **More manufacturers**: 54 000 IEEE prefixes including MA-M and MA-S blocks (was 32 500).
- Toolbars: equal control heights, centred labels and proper spacing between rows; they wrap
  cleanly on narrow windows.
- Logo and icon are now **magenta**.

## 1.0.0 — 2026-10-31
- First release: device discovery, MAC/manufacturer, DNS/NetBIOS names, port scan, CSV/HTML export.
