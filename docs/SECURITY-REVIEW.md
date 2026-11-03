# Security & resource review — Proton IP Scanner 1.3.0

Reviewed: 2026-11-03 · Scope: all code in `src/`, the dependency tree (408 crates), packaging.
Covers 1.0, the 1.1 additions (vulnerability scanner, reports, ping test, mDNS/LLMNR names) and the
1.2 additions (offline CVE database, UPnP names, router DNS, multicast name sweep, no cross-scan cache).

## Result

| Check | Result |
|---|---|
| `cargo audit` (RustSec database, 1 403 advisories) | **0 vulnerabilities, 0 warnings** |
| `cargo clippy --all-targets -D warnings` | **clean** |
| Unit + integration tests | **72 passed** (2 ignored: need a real network / internet) |
| Fuzz tests (random + mutated input) | 20 000 random inputs × 10 parsers (incl. SSDP, UPnP XML, mDNS records), 30 000 mutated mDNS/NetBIOS replies, 5 000 random JSON documents, 6 000 random/garbage offline-database files — **no panics** |
| Runs as root / admin | **Never.** No `sudo`, `pkexec`, `setcap` or UAC elevation |
| Shell / external commands | **None.** Only the desktop browser is opened, for URLs built from a parsed IP + port, or `http(s)://` links from NVD |
| `unsafe` code | Only 3 small Windows API calls (`IcmpSendEcho`, `SendARP`, `AttachConsole`), each with a `SAFETY` comment |

## Threat model

The scanner reads data **from devices on the network** (which may be hostile: a compromised IoT
device, a rogue machine on shared Wi-Fi) and, new in 1.1, **from the internet** (NVD and FIRST
APIs). It also takes input from the user. The review asked: can any of these crash the app, run
code, corrupt files, leak private data, or make the app harm the computer or the network?

## Findings and how they are handled

### 1. Untrusted text from devices — handled
DNS/mDNS/LLMNR/NetBIOS names, service banners, HTTP headers and page content are attacker-controlled.
* Names: `names::sanitize` keeps only `A–Z a–z 0–9 . - _ space`, max 64 chars.
* Banners and headers: `detect::clean` strips control characters (ANSI escapes, `\r\n` injection) and
  caps length (80–200 chars).
* At most 64 KiB is read from any response, always with timeouts.

### 2. Binary packet parsers — handled
NetBIOS NBSTAT and DNS PTR (mDNS/LLMNR) replies are parsed by hand. Every read uses
`slice.get(..)`; DNS compression pointers may only point backwards and are followed at most
16 times (no loops); label count is capped. Covered by truncation tests, a self-referencing
pointer test and mutation fuzzing (`names::tests::mutated_replies_never_panic`).

### 3. Data from the internet (NVD, FIRST EPSS) — handled
* TLS is always verified against the operating system trust store (`rustls-platform-verifier`).
* JSON is parsed with `serde_json` (memory-safe); response size is capped (NVD 64 MiB, EPSS 4 MiB).
* CVE ids must match `CVE-YYYY-NNNN…`; scores are clamped to 0–10 / 0–1; descriptions are cleaned
  and capped at 2 000 chars; at most 400 CVEs per product are kept.
* Reference links are kept only if they start with `http://` or `https://` (no `javascript:`,
  `file:` …), so clicking one in the app cannot run anything.
* The NVD API key (optional) is checked to contain only letters, digits and `-`, is sent only to
  NVD, and is **never written to disk** (memory only, or the `NVD_API_KEY` environment variable).

### 4. Privacy of online lookups — by design
Only product names and versions (as CPE names, e.g. `cpe:2.3:a:openbsd:openssh:9.6:p1`) and CVE
numbers are sent to NVD and FIRST. **No IP addresses, host names, MAC addresses or results leave the
computer.** Online lookups can be switched off (checkbox / `--offline`).

### 5. Probing scanned devices — non-destructive by design
* Configuration checks only read what services send, or send fixed read-only requests (`INFO server`
  to Redis, `version` to memcached, `GET /` to web servers, VNC version handshake).
* "Safe login checks" (on by default, can be switched off) try only *documented anonymous access*:
  FTP user `anonymous`, MQTT connect without credentials. No password guessing, no writes, immediate
  logout. Nothing is exploited.
* The HTTP client used for scanned devices **does not verify TLS certificates** (home devices use
  self-signed ones), never uses a proxy and never follows redirects. It is a separate client from
  the vulnerability-database client, which always verifies TLS.

### 6. Disk cache — handled
NVD/EPSS answers are cached for 24 h in the user's cache folder. File names are derived from CPE
names with every character except letters, digits and `.` replaced by `_` (no path separators, so
no path traversal). Writes go to a new temporary file (`create_new`) and are renamed into place;
cache files over 32 MiB are ignored. The cache holds only public data.

### 7. Reports (PDF, Excel, CSV, HTML) — handled
* **PDF** is written by our own small writer. Every string is escaped (`(`, `)`, `\` and non-ASCII
  as octal), so text such as `) Tj ET` from a banner cannot break out of a text object. Structure is
  verified by `qpdf --check` and a test that checks every cross-reference offset.
* **Excel**: all text is written with `write_string`, which stores it as text; a value such as
  `=HYPERLINK(…)` is shown literally, never evaluated.
* CSV: cells quoted and formula characters neutralised. HTML: every value escaped.
* All files are created with `create_new` in the Documents (or home) folder: an existing file or a
  planted symlink is never overwritten.

### 8. Resource exhaustion — handled
* IP ranges capped at 65 536 addresses; port scans at 17 M checks, generated lazily (no big lists).
* Thread counts are bounded: discovery/port workers ≤ 256 (≤ 8 in Polite, ≤ 2 in Slow mode),
  service-detection workers ≤ 16, ping test 1 thread. Worker stacks 256–512 KiB.
* The ping test keeps at most 3 600 samples (one hour) and running statistics.
* The UI handles at most 4 000 events per frame.
* If the OS refuses new threads, the scan ends cleanly instead of crashing.

### 9. UPnP device descriptions (new in 1.2) — handled
A device answering SSDP tells us a URL for its description. To prevent being steered to other hosts
(SSRF), the URL is used **only if it is plain `http://` on the IP address of the device that sent it**,
with a printable path ≤ 200 chars. At most 64 KiB is read with timeouts; the friendly name is found by a
simple text search (no XML parser, so no entity-expansion attacks), entities are decoded once and the
result is reduced to a safe character set. At most 64 descriptions are fetched per scan, 8 at a time.

### 10. Multicast name sweep (new in 1.2) — bounded
At the start of a network scan: one SSDP search and ⌈targets/40⌉ mDNS packets per interface (7 packets
for a /24), then 2.5 s of listening. Only answers from addresses inside the scanned range are used.
Skipped for ranges over 4 096 addresses and for vulnerability scans.

### 11. Offline vulnerability database (new in 1.2) — handled
* An imported file is **untrusted**: max 32 MB compressed / 256 MB unpacked (gzip bomb protection),
  must carry the `proton-vulndb` format marker, and every record is validated like live NVD data (CVE id
  format, scores clamped, text cleaned, only http(s) links, ≤ 2 000 version rules per CVE).
* It is installed into the user's own data folder by writing a new file and renaming it (atomic).
* Downloading it sends only product names (no versions, no addresses) to NVD and CVE ids to FIRST.

### 12. No data carried between scans (changed in 1.2)
Version 1.1.0 cached NVD/EPSS answers on disk for 24 h. This could make a re-scan show results based on
old data. Now nothing is cached between assessments: each one asks NVD again (or uses the offline database
you chose), the result list, notes and filters are cleared at start, and the old cache files
(`nvd-*.json`, `epss.json` in the user's cache folder) are deleted when the app starts. Only files with
those exact name patterns, in that one folder, are removed.

### 13. Text selection removed from the UI
Label text selection is disabled; values are copied through right-click menus. (Usability, but it also
means no partially-selected, mis-copied IP addresses.)

### 14. Installers and updates (new in 1.3)
* **Windows installer** (NSIS): needs administrator rights once, to write to Program Files and add the
  uninstall entry. It adds one firewall rule, scoped to the scanner's own .exe and to **private/domain**
  networks only — public Wi-Fi stays fully protected. The uninstaller removes the files, shortcuts, registry
  entry and the firewall rule. The app's manifest requests `asInvoker`: it never runs elevated.
* **Unsigned builds** trigger SmartScreen's "unknown publisher" dialog. That is a reputation check, not a
  detection. The release workflow can sign with a code-signing certificate stored as a repository secret;
  SHA256SUMS.txt is published with every release.
* **Linux updates** come through the signed Proton OS APT repository (apt verifies the repository's GPG
  signature). The .deb only *recommends* the keyring package; installing the .deb alone adds no repository.
* **Automatic CVE-database update** at start-up uses the same verified-TLS client and sends only product
  names to NVD and CVE ids to FIRST; it runs in the background, at most about once a day, and failures are
  harmless (the previous database stays installed — a new one replaces it only after it downloaded and
  validated completely).
* **settings.json** stores one boolean; the NVD API key is never written to disk.

### 15. Politeness towards services we depend on — by design
NVD rate limits are respected (6.5 s between requests without a key, 0.7 s with one; 30 s back-off on
403/429/503). If NVD cannot be reached at all, lookups stop at the first failure instead of retrying
every product.

### 16. Privileges — by design
Unchanged from 1.0: ICMP uses unprivileged "ping sockets" on Linux and `IcmpSendEcho` on Windows;
when ping is not allowed the scanner falls back to TCP + ARP. ARP data comes from world-readable
`/proc/net/arp` or `SendARP`.

## Known limitations (accepted)

* **Version-based CVE matching**: like remote version checks in other scanners, CVEs are matched from
  the version a service announces. Linux distributions back-port fixes without changing the version;
  findings from such builds are flagged ("confirm with the installed package version").
* **PPR is not VPR.** Tenable's VPR is proprietary. PPR (Proton Priority Rating) uses the same idea
  with public data (CVSS + EPSS + KEV); the formula is documented in the app, the reports and
  `src/vuln/score.rs`.
* **CVSS v4.0 coverage**: NVD publishes v4.0 scores for newer CVEs; older CVEs show v3.1/v3.0/v2.0,
  labelled as such.
* **Online lookups were tested with recorded NVD/FIRST-format responses**, not live, because the build
  machine had no internet access. The no-internet paths (automatic fallback to the offline database, or a
  clear warning) and the offline database (import, version matching, scan) were tested end to end.
* **Offline matching ignores "running on" conditions** in NVD configurations (e.g. "only on Windows"),
  which can over-match slightly. Version-range matching follows NVD's own bounds.
* **Host firewalls** (e.g. ufw on the scanning computer) may drop the replies to multicast name queries;
  the per-device unicast queries still work.
* Stale ARP entries, reverse DNS revealing scanned addresses to your DNS server, and port scans
  triggering intrusion-detection alarms are unchanged from 1.0. "Slow / stealthy" mode reduces the
  last one.

## Resource measurements

Measured on a 2-core VM with no GPU, release build.

| Situation | CPU | Memory (RSS) |
|---|---|---|
| Window open, idle (either tab) | **0 CPU ticks in 8 s** | ~40 MB own + renderer* |
| Ping test running (1 ping/s) | ~3 redraws/s, only when a reply arrives | +a few KB |
| CLI: /24 discovery + 28 common ports | 0.15 s CPU total | 9 MB peak |
| CLI: vulnerability assessment of 4 services, PDF report | **0.01 s CPU total** | **8.8 MB peak** |
| CLI: /24 discovery + name sweep + common ports (1.2) | 0.31 s CPU total | 9.1 MB peak |
| GUI after an assessment | — | 132 MB total in the VM* |

\* Most of the window's memory in the VM is Mesa's *software* OpenGL renderer (`libLLVM`,
`libgallium`, ~66 MB), used because the VM has no GPU. On real hardware the GPU driver replaces it.
The same applies to redraw CPU: about 30 ms per frame in software, ~1 ms on a GPU.

Why it is light:
* No async runtime and no external processes; blocking sockets with timeouts mean waiting threads
  use no CPU.
* Only live hosts, open services and findings are stored.
* The 54 000-entry vendor list stays in the binary's read-only data; a ~1 MB index is built on first use.
* egui redraws only on input, every 150 ms during a scan, or when a ping reply arrives.
