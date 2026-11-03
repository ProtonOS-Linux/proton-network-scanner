//! The graphical window.
//!
//! Two tabs share one window:
//! * **Network Scanner** (this file): find devices, names, MAC/manufacturer,
//!   open ports, and a ping test for the selected device.
//! * **Vulnerability Scanner** ([`vuln_tab`]): service detection, safe
//!   configuration checks and known CVEs with CVSS v4 / EPSS / priority.
//!
//! ```text
//! ┌ header: logo · Proton IP Scanner · [Network Scanner][Vulnerability Scanner]   [Settings][About] ┐
//! ├ toolbar (per tab, two rows, equal control heights) ─────────────────────────────────────────────┤
//! │ results table                                              │ details of the selected item      │
//! ├ status bar: progress · counts · messages ──────────────────┴───────────────────────────────────┤
//! ```
//!
//! CPU use: egui only redraws on input. While a scan or ping test runs we ask
//! for a redraw every 150 ms to show progress; when nothing is happening the
//! window does no work at all.

mod ping_window;
mod vuln_tab;
mod widgets;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, RichText, Sense, Stroke, Vec2};
use egui_extras::{Column, TableBuilder};

use crate::export::{self, Format};
use crate::scanner::ports::{self, OpenPort};
use crate::scanner::{self, Event, Host, Job, LocalNet, Role, Settings, Speed, range};
use ping_window::PingWindow;
use vuln_tab::{NetworkInfo, VulnTab};
use widgets::*;

/// How often to redraw while a scan is running.
const SCAN_REDRAW: Duration = Duration::from_millis(150);
/// Max events handled per frame, so a burst can never freeze the window.
const MAX_EVENTS_PER_FRAME: usize = 4_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Network,
    Vulnerability,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobKind {
    Discovery,
    Ports,
    /// The automatic common-port check that follows a discovery scan.
    AutoPorts,
}

/// Table columns that can be sorted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Ip,
    Name,
    Mac,
    Vendor,
    Ping,
    Ports,
}

/// A short message shown in the status bar for a few seconds.
struct Toast {
    text: String,
    error: bool,
    until: Instant,
}

pub struct App {
    tab: Tab,
    vuln: VulnTab,
    ping: Option<PingWindow>,
    /// Optional NVD API key (faster lookups); from Settings or $NVD_API_KEY.
    nvd_api_key: String,
    /// Remembered preferences (auto-update of the CVE database).
    config: crate::config::Config,
    nets: Vec<LocalNet>,
    range_text: String,
    ports_text: String,
    settings: Settings,

    /// Live hosts found by the last discovery scan.
    hosts: Vec<Host>,
    /// Names from the multicast sweep, applied to hosts as they arrive.
    swept: HashMap<Ipv4Addr, Vec<(scanner::names::SweepKind, String)>>,
    /// IP → position in `hosts`, for fast updates from scan events.
    index: HashMap<Ipv4Addr, usize>,

    job: Option<(Job, JobKind)>,
    /// Summary of the last finished scan, shown in the status bar.
    last_summary: Option<String>,

    selected: Option<Ipv4Addr>,
    filter: String,
    sort: (SortCol, bool),

    show_settings: bool,
    show_about: bool,
    toast: Option<Toast>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_style(&cc.egui_ctx);
        // Follows the desktop's light/dark setting; PROTON_IP_SCANNER_THEME
        // = light | dark forces one (same convention as Proton Security).
        match std::env::var("PROTON_IP_SCANNER_THEME").as_deref() {
            Ok("light") => cc.egui_ctx.set_theme(egui::Theme::Light),
            Ok("dark") => cc.egui_ctx.set_theme(egui::Theme::Dark),
            _ => {}
        }
        let nets = scanner::local_networks();
        let range_text = nets
            .first()
            .map(|n| range::network_range_text(n.addr, n.prefix_len))
            .unwrap_or_else(|| "192.168.1.1-254".into());
        let mut app = App {
            tab: Tab::Network,
            vuln: VulnTab::new(range_text.clone()),
            ping: None,
            nvd_api_key: std::env::var("NVD_API_KEY").unwrap_or_default(),
            config: crate::config::Config::load(),
            nets,
            range_text,
            ports_text: ports::PRESET_COMMON.into(),
            settings: Settings::default(),
            hosts: Vec::new(),
            swept: HashMap::new(),
            index: HashMap::new(),
            job: None,
            last_summary: None,
            selected: None,
            filter: String::new(),
            sort: (SortCol::Ip, true),
            show_settings: false,
            show_about: false,
            toast: None,
        };
        // Screenshot/demo mode for documentation and UI testing: fills the
        // table with made-up devices. Never touches the network.
        if let Ok(v) = std::env::var("PROTON_IP_SCANNER_DEMO") {
            app.load_demo();
            app.vuln.load_demo();
            if v == "vuln" {
                app.tab = Tab::Vulnerability;
            }
            if v == "ping" {
                // Ping this computer so the window shows real measurements.
                app.ping =
                    Some(PingWindow::new(&cc.egui_ctx, Ipv4Addr::LOCALHOST, "this computer (demo)".into(), vec![]));
            }
        } else if app.config.auto_update_db {
            // Keep the local CVE database current: refresh it in the background
            // (at most about once a day; quietly skipped without internet).
            let key = app.nvd_api_key.trim().to_string();
            app.vuln.auto_update((!key.is_empty()).then_some(key));
        }
        app
    }

    /// Fill the table with example devices (see `PROTON_IP_SCANNER_DEMO`).
    fn load_demo(&mut self) {
        use crate::scanner::mac::Mac;
        use crate::scanner::{Method, vendor};
        let mk = |last: u8, mac: [u8; 6], name: &str, role: Role, ms: Option<u64>, ports: Option<&[u16]>| {
            let mac = Mac(mac);
            Host {
                ip: Ipv4Addr::new(192, 168, 1, last),
                role,
                method: if role == Role::ThisComputer {
                    Method::Local
                } else if ms.is_some() {
                    Method::Ping
                } else {
                    Method::Arp
                },
                rtt: ms.map(Duration::from_millis),
                vendor: vendor::lookup(&mac),
                mac: Some(mac),
                dns_name: (!name.is_empty()).then(|| format!("{}.lan", name.to_ascii_lowercase())),
                netbios_name: (!name.is_empty() && !name.contains("iPhone")).then(|| name.to_string()),
                local_name: (!name.is_empty()).then(|| name.to_string()),
                upnp_name: (name == "PRINTER").then(|| "HP LaserJet Pro M404".to_string()),
                workgroup: None,
                ports: ports.map(|ps| {
                    ps.iter().map(|&p| OpenPort { port: p, service: ports::service_name(p), banner: None }).collect()
                }),
            }
        };
        let demo = [
            mk(1, [0x00, 0x1D, 0x7E, 0x10, 0x20, 0x30], "", Role::Router, Some(2), Some(&[53, 80, 443])),
            mk(
                10,
                [0xB8, 0x27, 0xEB, 0x44, 0x55, 0x66],
                "HOMESERVER",
                Role::Device,
                Some(1),
                Some(&[22, 80, 445, 32400]),
            ),
            mk(23, [0x00, 0x15, 0x5D, 0x01, 0x02, 0x03], "OFFICE-PC", Role::Device, None, None),
            mk(37, [0x08, 0x00, 0x27, 0xAA, 0xBB, 0xCC], "PROTON-LAPTOP", Role::ThisComputer, None, None),
            mk(41, [0xDA, 0xA1, 0x19, 0x22, 0x33, 0x44], "Johns-iPhone", Role::Device, Some(38), Some(&[62078])),
            mk(52, [0x00, 0x00, 0x48, 0x77, 0x88, 0x99], "PRINTER", Role::Device, Some(4), Some(&[80, 631, 9100])),
            mk(60, [0xDC, 0xA6, 0x32, 0x12, 0x34, 0x56], "PIHOLE", Role::Device, Some(1), Some(&[22, 53, 80])),
        ];
        for h in demo {
            self.index.insert(h.ip, self.hosts.len());
            self.hosts.push(h);
        }
        self.range_text = "192.168.1.1-192.168.1.254".into();
        self.selected = Some(Ipv4Addr::new(192, 168, 1, 10));
        self.last_summary = Some("Demo data: 7 live device(s) out of 254 address(es) in 4.2 s".into());
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Open the ping test window for `ip`.
    fn open_ping(&mut self, ctx: &egui::Context, ip: Ipv4Addr) {
        let Some(h) = self.index.get(&ip).map(|&i| &self.hosts[i]) else { return };
        let ports: Vec<u16> = h.ports.iter().flatten().map(|p| p.port).collect();
        self.ping = Some(PingWindow::new(ctx, ip, h.display_name().to_string(), ports));
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.toast = Some(Toast { text: text.into(), error, until: Instant::now() + Duration::from_secs(6) });
    }

    // -----------------------------------------------------------------
    // Starting / stopping scans
    // -----------------------------------------------------------------

    fn start_discovery(&mut self) {
        match range::parse_ip_ranges(&self.range_text) {
            Ok(ips) => {
                self.hosts.clear();
                self.index.clear();
                self.swept.clear();
                self.selected = None;
                let job = scanner::start_discovery(ips, &self.settings, self.nets.clone());
                if !job.icmp {
                    self.notify(
                        "Ping isn't allowed for this user, so devices are detected with TCP and ARP instead.",
                        false,
                    );
                }
                self.job = Some((job, JobKind::Discovery));
            }
            Err(e) => self.notify(e, true),
        }
    }

    /// Scan ports on `targets` (one device, or all live devices).
    fn start_port_scan(&mut self, targets: Vec<Ipv4Addr>) {
        self.start_port_scan_as(targets, JobKind::Ports);
    }

    fn start_port_scan_as(&mut self, targets: Vec<Ipv4Addr>, kind: JobKind) {
        if targets.is_empty() {
            self.notify("Find some devices first, then scan their ports.", true);
            return;
        }
        let port_list = match range::parse_ports(&self.ports_text) {
            Ok(p) => p,
            Err(e) => return self.notify(e, true),
        };
        match scanner::start_port_scan(targets.clone(), port_list, &self.settings) {
            Ok(job) => {
                for ip in &targets {
                    if let Some(&i) = self.index.get(ip) {
                        self.hosts[i].ports = Some(Vec::new());
                    }
                }
                self.job = Some((job, kind));
            }
            Err(e) => self.notify(e, true),
        }
    }

    fn stop(&mut self) {
        if let Some((job, _)) = &self.job {
            job.cancel();
        }
    }

    /// Apply all pending scan events (called every frame).
    fn poll_job(&mut self) {
        let Some((job, kind)) = &mut self.job else { return };
        let mut finished = false;
        for _ in 0..MAX_EVENTS_PER_FRAME {
            match job.rx.try_recv() {
                Ok(Event::Host(h)) => {
                    let mut h = *h;
                    for (kind, name) in self.swept.get(&h.ip).into_iter().flatten() {
                        h.apply_swept(*kind, name);
                    }
                    self.index.insert(h.ip, self.hosts.len());
                    self.hosts.push(h);
                }
                Ok(Event::Names(list)) => {
                    for (ip, kind, name) in list {
                        if let Some(&i) = self.index.get(&ip) {
                            self.hosts[i].apply_swept(kind, &name);
                        }
                        self.swept.entry(ip).or_default().push((kind, name));
                    }
                }
                Ok(Event::OpenPort(ip, p)) => {
                    if let Some(list) = self.index.get(&ip).and_then(|&i| self.hosts[i].ports.as_mut()) {
                        let pos = list.partition_point(|o| o.port < p.port);
                        list.insert(pos, p);
                    }
                }
                Ok(Event::Finished) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }
        if finished {
            job.finished_at = Some(Instant::now());
            let secs = job.elapsed().as_secs_f64();
            let stopped = if job.is_cancelled() { " (stopped)" } else { "" };
            let kind = *kind;
            let cancelled = job.is_cancelled();
            let summary = match kind {
                JobKind::Discovery => format!(
                    "{} live device(s) out of {} address(es) in {secs:.1} s{stopped}",
                    self.hosts.len(),
                    job.total
                ),
                JobKind::Ports | JobKind::AutoPorts => {
                    let open: usize = self.hosts.iter().filter_map(|h| h.ports.as_ref()).map(Vec::len).sum();
                    let devices = self.hosts.len();
                    format!("{devices} device(s) · {open} open port(s) · port check took {secs:.1} s{stopped}")
                }
            };
            self.last_summary = Some(summary);
            self.job = None;
            // A normal scan continues with the common ports on every device found.
            if kind == JobKind::Discovery && !cancelled && self.settings.auto_ports && !self.hosts.is_empty() {
                let targets = self.hosts.iter().map(|h| h.ip).collect();
                let saved = std::mem::replace(&mut self.ports_text, ports::PRESET_COMMON.into());
                self.start_port_scan_as(targets, JobKind::AutoPorts);
                self.ports_text = saved;
            }
        }
    }

    fn export(&mut self, format: Format) {
        if self.hosts.is_empty() {
            return self.notify("Nothing to export yet — run a scan first.", true);
        }
        let mut hosts = self.hosts.clone();
        hosts.sort_by_key(|h| h.ip);
        match export::save(&hosts, format) {
            Ok(path) => self.notify(format!("Saved {}", path.display()), false),
            Err(e) => self.notify(format!("Could not save the file: {e}"), true),
        }
    }

    /// Indices into `self.hosts` matching the search box, in table order.
    fn visible_rows(&self) -> Vec<usize> {
        let needle = self.filter.trim().to_ascii_lowercase();
        let mut rows: Vec<usize> =
            (0..self.hosts.len()).filter(|&i| needle.is_empty() || matches_filter(&self.hosts[i], &needle)).collect();
        let (col, asc) = self.sort;
        let h = &self.hosts;
        rows.sort_by(|&a, &b| {
            let (x, y) = (&h[a], &h[b]);
            let ord = match col {
                SortCol::Ip => x.ip.cmp(&y.ip),
                SortCol::Name => x.display_name().to_lowercase().cmp(&y.display_name().to_lowercase()),
                SortCol::Mac => x.mac.cmp(&y.mac),
                SortCol::Vendor => x.vendor.cmp(&y.vendor),
                SortCol::Ping => x.rtt.unwrap_or(Duration::MAX).cmp(&y.rtt.unwrap_or(Duration::MAX)),
                SortCol::Ports => port_count(x).cmp(&port_count(y)),
            };
            // Empty values always last; ties broken by IP.
            let ord = if asc { ord } else { ord.reverse() };
            ord.then(x.ip.cmp(&y.ip))
        });
        rows
    }

    // -----------------------------------------------------------------
    // UI pieces
    // -----------------------------------------------------------------

    /// Title row with the tab switcher.
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            logo(ui, 38.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Proton IP Scanner").size(18.0).strong());
                ui.label(RichText::new("Network & vulnerability scanner").small().weak());
            });
            ui.add_space(24.0);
            for (tab, label) in [(Tab::Network, "🖧  Network Scanner"), (Tab::Vulnerability, "🛡  Vulnerability Scanner")]
            {
                let active = self.tab == tab;
                let text = RichText::new(label).size(14.0).strong();
                let btn = egui::Button::new(if active { text.color(Color32::WHITE) } else { text })
                    .fill(if active { MAGENTA } else { ui.visuals().widgets.inactive.weak_bg_fill })
                    .corner_radius(CornerRadius::same(16))
                    .min_size(Vec2::new(0.0, CONTROL_H));
                if ui.add(btn).clicked() {
                    self.tab = tab;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(tool_button("About")).clicked() {
                    self.show_about = true;
                }
                if ui.add(tool_button("⚙ Settings")).clicked() {
                    self.show_settings = !self.show_settings;
                }
            });
        });
        ui.add_space(10.0);
    }

    /// Network tab toolbar: row 1 = what to scan, row 2 = ports and tools.
    fn network_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            toolbar_spacing(ui);
            let busy = self.busy();
            // Order: pick a network → check/edit the range → Scan.
            ui.add_enabled_ui(!busy, |ui| {
                ui.menu_button("🖧 My network ⏷", |ui| {
                    if self.nets.is_empty() {
                        ui.label("No active network connection found.");
                    }
                    for n in self.nets.clone() {
                        let text = format!("{}  —  {}/{}", n.interface, n.addr, n.prefix_len);
                        if ui.button(text).clicked() {
                            self.range_text = range::network_range_text(n.addr, n.prefix_len);
                            ui.close();
                        }
                    }
                    ui.separator();
                    if ui.button("⟳ Refresh list").clicked() {
                        self.nets = scanner::local_networks();
                    }
                });
            });
            toolbar_label(ui, "IP range");
            let resp = ui
                .add_enabled(
                    !busy,
                    text_box(&mut self.range_text, 260.0, "e.g. 192.168.1.1-254 or 192.168.1.0/24", 512),
                )
                .on_hover_text("Single addresses, ranges (a-b) or CIDR (/24), separated by commas");
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !busy {
                self.start_discovery();
            }
            let (label, fill) = if busy { ("■  Stop", RED) } else { ("▶  Scan", ACCENT) };
            if ui.add(action_button(label, fill)).on_hover_text("Find live devices in the IP range (Enter)").clicked() {
                if busy { self.stop() } else { self.start_discovery() }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button("💾 Export ⏷", |ui| {
                    if ui.button("CSV file (spreadsheet)").clicked() {
                        self.export(Format::Csv);
                        ui.close();
                    }
                    if ui.button("HTML report").clicked() {
                        self.export(Format::Html);
                        ui.close();
                    }
                    if ui.button("Copy table to clipboard").clicked() {
                        let mut hosts = self.hosts.clone();
                        hosts.sort_by_key(|h| h.ip);
                        ui.ctx().copy_text(export::to_csv(&hosts));
                        self.notify("Copied to the clipboard as CSV.", false);
                        ui.close();
                    }
                });
            });
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            toolbar_spacing(ui);
            let busy = self.busy();
            toolbar_label(ui, "Ports");
            ui.add_enabled(!busy, text_box(&mut self.ports_text, 300.0, "e.g. 22,80,443 or 1-1024", 2048))
                .on_hover_text("TCP ports to check: numbers and ranges separated by commas");
            ui.add_enabled_ui(!busy, |ui| {
                ui.menu_button("Presets ⏷", |ui| {
                    for (name, list) in [
                        ("Common services (28 ports)", ports::PRESET_COMMON),
                        ("Standard vulnerability set (52 ports)", ports::PRESET_VULN),
                        ("Comprehensive (1,298 ports)", ports::PRESET_COMPREHENSIVE),
                        ("Web servers", ports::PRESET_WEB),
                        ("Well-known 1-1024", ports::PRESET_WELL_KNOWN),
                        ("Full scan: all 65,535 ports (slow)", ports::PRESET_FULL),
                    ] {
                        if ui.button(name).clicked() {
                            self.ports_text = list.into();
                            ui.close();
                        }
                    }
                });
            });
            ui.separator();
            let has_sel = self.selected.is_some();
            let has_hosts = !self.hosts.is_empty();
            if ui
                .add_enabled(!busy && has_sel, tool_button("🔍 Scan ports: selected device"))
                .on_disabled_hover_text("Select a device in the list first")
                .clicked()
            {
                let t = self.selected.into_iter().collect();
                self.start_port_scan(t);
            }
            if ui
                .add_enabled(!busy && has_hosts, tool_button("🔍 Scan ports: all live devices"))
                .on_disabled_hover_text("Run a scan first")
                .clicked()
            {
                let t = self.hosts.iter().map(|h| h.ip).collect();
                self.start_port_scan(t);
            }
            ui.separator();
            if ui
                .add_enabled(has_sel, tool_button("📶 Ping test"))
                .on_hover_text("Measure latency, jitter and packet loss to the selected device")
                .on_disabled_hover_text("Select a device in the list first")
                .clicked()
                && let Some(ip) = self.selected
            {
                self.open_ping(&ui.ctx().clone(), ip);
            }
        });
        ui.add_space(10.0);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            if self.tab == Tab::Vulnerability {
                self.vuln.status(ui);
            } else if let Some((job, kind)) = &self.job {
                let done = job.done();
                let frac = if job.total == 0 { 1.0 } else { done as f32 / job.total as f32 };
                let what = match kind {
                    JobKind::Discovery => "addresses",
                    JobKind::Ports => "port checks",
                    JobKind::AutoPorts => "common-port checks",
                };
                ui.add(egui::ProgressBar::new(frac).desired_width(220.0).fill(ACCENT).show_percentage());
                ui.label(format!(
                    "{done} / {} {what} · {} live · {:.1} s{}",
                    job.total,
                    self.hosts.len(),
                    job.elapsed().as_secs_f64(),
                    if job.is_cancelled() { " · stopping…" } else { "" }
                ));
            } else if let Some(s) = &self.last_summary {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.5, GREEN);
                ui.label(s);
            } else {
                ui.label(RichText::new("Ready. Press Scan to find the devices on your network.").weak());
            }

            if let Some(t) = &self.toast {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let color = if t.error { RED } else { ui.visuals().text_color() };
                    ui.label(RichText::new(&t.text).color(color));
                });
            }
        });
        ui.add_space(5.0);
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        // Search row.
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("🔍 Filter by IP, name, MAC, manufacturer or port")
                    .desired_width(340.0)
                    .char_limit(128),
            );
            if !self.filter.is_empty() && ui.small_button("✖").clicked() {
                self.filter.clear();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let open: usize = self.hosts.iter().filter_map(|h| h.ports.as_ref()).map(Vec::len).sum();
                ui.label(RichText::new(format!("{} devices · {} open ports", self.hosts.len(), open)).weak());
            });
        });
        ui.add_space(4.0);

        if self.hosts.is_empty() {
            empty_state(
                ui,
                "🖧",
                self.busy(),
                "Looking for devices…",
                "No devices yet",
                "Press Scan to find computers, phones, printers and everything else on your network.",
            );
            return;
        }

        let rows = self.visible_rows();
        let mut clicked: Option<Ipv4Addr> = None;
        let mut action: Option<RowAction> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(26.0))
            .column(Column::initial(120.0).at_least(90.0))
            .column(Column::initial(160.0).at_least(80.0).clip(true))
            .column(Column::initial(140.0).at_least(110.0))
            .column(Column::initial(165.0).at_least(80.0).clip(true))
            .column(Column::initial(70.0).at_least(55.0))
            .column(Column::remainder().at_least(80.0).clip(true))
            .header(26.0, |mut header| {
                header.col(|_| {});
                for (col, title) in [
                    (SortCol::Ip, "IP address"),
                    (SortCol::Name, "Name"),
                    (SortCol::Mac, "MAC address"),
                    (SortCol::Vendor, "Manufacturer"),
                    (SortCol::Ping, "Ping"),
                    (SortCol::Ports, "Open ports"),
                ] {
                    header.col(|ui| {
                        let arrow = if self.sort.0 == col { if self.sort.1 { " ⏶" } else { " ⏷" } } else { "" };
                        let r = ui.add(
                            egui::Label::new(RichText::new(format!("{title}{arrow}")).strong()).sense(Sense::click()),
                        );
                        if r.clicked() {
                            self.sort = if self.sort.0 == col { (col, !self.sort.1) } else { (col, true) };
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(24.0, rows.len(), |mut row| {
                    let h = &self.hosts[rows[row.index()]];
                    row.set_selected(self.selected == Some(h.ip));
                    row.col(|ui| status_dot(ui, h));
                    row.col(|ui| {
                        ui.monospace(h.ip.to_string());
                    });
                    row.col(|ui| {
                        let name = h.display_name();
                        match h.role {
                            Role::ThisComputer => {
                                ui.label(RichText::new(if name.is_empty() { "This computer" } else { name }).strong())
                            }
                            Role::Router => {
                                ui.label(format!("{}  (router)", if name.is_empty() { "Router" } else { name }))
                            }
                            Role::Device => ui.label(name),
                        };
                    });
                    row.col(|ui| {
                        ui.monospace(h.mac.map(|m| m.to_string()).unwrap_or_default());
                    });
                    row.col(|ui| {
                        ui.label(h.vendor.unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(rtt_text(h));
                    });
                    row.col(|ui| {
                        ui.label(ports_summary(h));
                    });
                    let resp = row.response();
                    if resp.clicked() {
                        clicked = Some(h.ip);
                    }
                    let ip = h.ip;
                    resp.context_menu(|ui| {
                        if let Some(a) = row_menu(ui, ip) {
                            action = Some(a);
                        }
                    });
                });
            });

        if let Some(ip) = clicked {
            self.selected = if self.selected == Some(ip) { None } else { Some(ip) };
        }
        if let Some(a) = action {
            self.do_row_action(ui.ctx(), a);
        }
    }

    fn do_row_action(&mut self, ctx: &egui::Context, a: RowAction) {
        let Some(h) = self.index.get(&a.ip()).map(|&i| self.hosts[i].clone()) else { return };
        match a {
            RowAction::CopyIp(_) => ctx.copy_text(h.ip.to_string()),
            RowAction::CopyMac(_) => ctx.copy_text(h.mac.map(|m| m.to_string()).unwrap_or_default()),
            RowAction::CopyName(_) => ctx.copy_text(h.display_name().to_string()),
            RowAction::CopyVendor(_) => ctx.copy_text(h.vendor.unwrap_or("").to_string()),
            RowAction::CopyRow(_) => ctx.copy_text(format!(
                "{}\t{}\t{}\t{}\t{}",
                h.ip,
                h.display_name(),
                h.mac.map(|m| m.to_string()).unwrap_or_default(),
                h.vendor.unwrap_or(""),
                ports_summary(&h)
            )),
            RowAction::ScanPorts(ip) => {
                self.selected = Some(ip);
                if !self.busy() {
                    self.start_port_scan(vec![ip]);
                }
            }
            RowAction::Ping(ip) => {
                self.selected = Some(ip);
                self.open_ping(ctx, ip);
            }
            RowAction::Open(ip, scheme, port) => open_url(ctx, ip, scheme, port),
        }
    }

    fn details(&mut self, ui: &mut egui::Ui) {
        let Some(h) = self.selected.and_then(|ip| self.index.get(&ip)).map(|&i| self.hosts[i].clone()) else {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.label(RichText::new("Select a device to see its details.").weak()));
            return;
        };

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(device_glyph(&h)).size(28.0));
            ui.vertical(|ui| {
                let title = if h.display_name().is_empty() { h.ip.to_string() } else { h.display_name().to_string() };
                ui.label(RichText::new(title).size(17.0).strong());
                ui.label(RichText::new(h.vendor.unwrap_or("Unknown manufacturer")).weak());
            });
        });
        ui.add_space(8.0);

        egui::Grid::new("details").num_columns(2).spacing([12.0, 6.0]).striped(true).show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.label(RichText::new(k).weak());
                copy_value(ui, v.clone(), &v).on_hover_text("Right-click to copy");
                ui.end_row();
            };
            row("IP address", h.ip.to_string());
            row("MAC address", h.mac.map(|m| m.to_string()).unwrap_or_else(|| "—".into()));
            row("Manufacturer", h.vendor.unwrap_or("—").into());
            row("NetBIOS name", h.netbios_name.clone().unwrap_or_else(|| "—".into()));
            row("mDNS / LLMNR name", h.local_name.clone().unwrap_or_else(|| "—".into()));
            row("UPnP name", h.upnp_name.clone().unwrap_or_else(|| "—".into()));
            row("DNS name", h.dns_name.clone().unwrap_or_else(|| "—".into()));
            row("Workgroup", h.workgroup.clone().unwrap_or_else(|| "—".into()));
            row("Response", rtt_text(&h));
            row("Detected by", h.method.label().into());
            row(
                "Type",
                match h.role {
                    Role::ThisComputer => "This computer".into(),
                    Role::Router => "Router (default gateway)".into(),
                    Role::Device => "Device".into(),
                },
            );
        });

        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(!self.busy(), egui::Button::new("🔍 Scan ports")).clicked() {
                self.start_port_scan(vec![h.ip]);
            }
            if ui.button("📶 Ping test").clicked() {
                self.open_ping(&ui.ctx().clone(), h.ip);
            }
            if ui.button("Copy IP").clicked() {
                ui.ctx().copy_text(h.ip.to_string());
            }
            if ui.button("Open in browser").on_hover_text(format!("http://{}", h.ip)).clicked() {
                open_url(ui.ctx(), h.ip, "http", 80);
            }
        });

        ui.add_space(12.0);
        ui.label(RichText::new("Open ports").strong());
        ui.separator();
        match &h.ports {
            None => {
                ui.label(RichText::new("Not scanned yet. Press \"Scan ports\" to check this device.").weak());
            }
            Some(list) if list.is_empty() => {
                let scanning = self.job.as_ref().is_some_and(|(_, k)| *k != JobKind::Discovery);
                ui.label(
                    RichText::new(if scanning {
                        "Scanning…"
                    } else {
                        "No open ports found in the list you scanned."
                    })
                    .weak(),
                );
            }
            Some(list) => {
                egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
                    for p in list {
                        port_row(ui, h.ip, p);
                    }
                });
            }
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_settings;
        egui::Window::new("⚙ Settings").open(&mut open).resizable(false).collapsible(false).show(ctx, |ui| {
            let s = &mut self.settings;
            egui::Grid::new("settings").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Parallel workers");
                ui.add(egui::Slider::new(&mut s.threads, 1..=scanner::MAX_THREADS))
                    .on_hover_text("More is faster but uses more of the network. 64 suits most home networks.");
                ui.end_row();
                ui.label("Ping timeout");
                ui.add(egui::Slider::new(&mut s.ping_timeout_ms, 100..=5000).suffix(" ms"));
                ui.end_row();
                ui.label("Ping attempts");
                ui.add(egui::Slider::new(&mut s.ping_attempts, 1..=5));
                ui.end_row();
                ui.label("Port timeout");
                ui.add(egui::Slider::new(&mut s.port_timeout_ms, 100..=5000).suffix(" ms"));
                ui.end_row();
                ui.label("Probe speed");
                egui::ComboBox::from_id_salt("net-speed").selected_text(s.speed.label()).show_ui(ui, |ui| {
                    for sp in Speed::ALL {
                        ui.selectable_value(&mut s.speed, sp, sp.label());
                    }
                });
                ui.end_row();
                ui.label("Names");
                ui.vertical(|ui| {
                    ui.checkbox(&mut s.resolve_dns, "Look up DNS names (router / DNS server)");
                    ui.checkbox(&mut s.netbios, "Ask for Windows (NetBIOS) names");
                    ui.checkbox(&mut s.multicast_names, "Ask for mDNS / LLMNR names (phones, Macs, printers, Linux)");
                });
                ui.end_row();
                ui.label("After a scan");
                ui.checkbox(&mut s.auto_ports, "Check the common ports on every device found");
                ui.end_row();
                ui.label("Services");
                ui.checkbox(&mut s.grab_banners, "Show service greeting (version) of open ports");
                ui.end_row();
                ui.label("CVE database");
                if ui
                    .checkbox(&mut self.config.auto_update_db, "Update the local CVE database automatically when the app opens")
                    .on_hover_text("At most about once a day, in the background. Skipped quietly without internet.")
                    .changed()
                {
                    self.config.save();
                }
                ui.end_row();
                ui.label("NVD API key");
                ui.vertical(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.nvd_api_key).password(true).desired_width(260.0).char_limit(64).hint_text("optional"));
                    ui.label(RichText::new("Free key from nvd.nist.gov makes CVE lookups ~10× faster.\nKept in memory only (or set NVD_API_KEY).").small().weak());
                });
                ui.end_row();
            });
            ui.add_space(6.0);
            if ui.button("Restore defaults").clicked() {
                self.settings = Settings::default();
            }
        });
        self.show_settings = open;
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_about;
        egui::Window::new("About Proton IP Scanner").open(&mut open).resizable(false).collapsible(false).show(
            ctx,
            |ui| {
                ui.horizontal(|ui| {
                    logo(ui, 36.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Proton IP Scanner").size(16.0).strong());
                        ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                    });
                });
                ui.add_space(6.0);
                ui.label("Part of the Proton OS family. Free software under the GNU GPL v3 or later.");
                ui.label("Runs without administrator rights on Linux and Windows.");
                ui.label("Manufacturer names come from the public IEEE registries (MA-L, MA-M, MA-S).");
                ui.label("Vulnerability data: NIST NVD (CVSS, CISA KEV) and FIRST EPSS.");
                ui.label(
                    RichText::new("This product uses the NVD API but is not endorsed or certified by the NVD.")
                        .small()
                        .weak(),
                );
                ui.add_space(6.0);
                ui.label(RichText::new("Only scan networks you own or have permission to scan.").strong());
                ui.add_space(4.0);
                ui.hyperlink_to("www.protonos.org", "https://www.protonos.org");
            },
        );
        self.show_about = open;
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_job();
        let ctx = ui.ctx().clone();

        // Drop an expired message; otherwise wake up when it expires.
        if let Some(t) = &self.toast {
            let left = t.until.saturating_duration_since(Instant::now());
            if left.is_zero() { self.toast = None } else { ctx.request_repaint_after(left) }
        }
        if self.busy() {
            ctx.request_repaint_after(SCAN_REDRAW);
        }

        self.vuln.poll();
        if let Some((msg, err)) = self.vuln.toast.take() {
            self.notify(msg, err);
        }
        if self.vuln.busy() || self.vuln.poll_db() {
            ctx.request_repaint_after(SCAN_REDRAW);
        }

        let bar = egui::Frame::side_top_panel(ui.style()).inner_margin(egui::Margin::symmetric(14, 0));
        egui::Panel::top("header").frame(bar).show(ui, |ui| self.header(ui));
        match self.tab {
            Tab::Network => {
                egui::Panel::top("net-tools").frame(bar).show(ui, |ui| self.network_toolbar(ui));
            }
            Tab::Vulnerability => {
                let live: Vec<Ipv4Addr> = self.hosts.iter().map(|h| h.ip).collect();
                let key = self.nvd_api_key.trim();
                let info = NetworkInfo {
                    live,
                    nets: &self.nets,
                    port_timeout_ms: self.settings.port_timeout_ms,
                    nvd_api_key: (!key.is_empty()).then(|| key.to_string()),
                    selected: self.selected,
                };
                egui::Panel::top("vuln-tools").frame(bar).show(ui, |ui| self.vuln.toolbar(ui, &info));
            }
        }
        egui::Panel::bottom("status").frame(bar).show(ui, |ui| self.status_bar(ui));
        match self.tab {
            Tab::Network => {
                egui::Panel::right("details")
                    .resizable(true)
                    .default_size(330.0)
                    .size_range(260.0..=520.0)
                    .show(ui, |ui| self.details(ui));
                egui::CentralPanel::default().show(ui, |ui| self.results(ui));
            }
            Tab::Vulnerability => {
                egui::Panel::right("vuln-details")
                    .resizable(true)
                    .default_size(380.0)
                    .size_range(280.0..=620.0)
                    .show(ui, |ui| self.vuln.details(ui));
                egui::CentralPanel::default().show(ui, |ui| self.vuln.central(ui));
            }
        }

        if let Some(p) = &mut self.ping
            && !p.show(&ctx)
        {
            self.ping = None;
        }
        if self.show_settings {
            self.settings_window(&ctx);
        }
        if self.show_about {
            self.about_window(&ctx);
        }
    }
}

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------

/// Things the right-click menu can do.
enum RowAction {
    CopyIp(Ipv4Addr),
    CopyMac(Ipv4Addr),
    CopyName(Ipv4Addr),
    CopyVendor(Ipv4Addr),
    /// IP, name, MAC, manufacturer and open ports as one line of text.
    CopyRow(Ipv4Addr),
    ScanPorts(Ipv4Addr),
    Ping(Ipv4Addr),
    Open(Ipv4Addr, &'static str, u16),
}

impl RowAction {
    fn ip(&self) -> Ipv4Addr {
        match *self {
            RowAction::CopyIp(ip)
            | RowAction::CopyMac(ip)
            | RowAction::CopyName(ip)
            | RowAction::CopyVendor(ip)
            | RowAction::CopyRow(ip)
            | RowAction::ScanPorts(ip)
            | RowAction::Ping(ip)
            | RowAction::Open(ip, ..) => ip,
        }
    }
}

fn row_menu(ui: &mut egui::Ui, ip: Ipv4Addr) -> Option<RowAction> {
    let mut a = None;
    if ui.button("🔍 Scan ports of this device").clicked() {
        a = Some(RowAction::ScanPorts(ip));
    }
    if ui.button("📶 Ping test…").clicked() {
        a = Some(RowAction::Ping(ip));
    }
    ui.separator();
    if ui.button("Open http://…").clicked() {
        a = Some(RowAction::Open(ip, "http", 80));
    }
    if ui.button("Open https://…").clicked() {
        a = Some(RowAction::Open(ip, "https", 443));
    }
    ui.separator();
    if ui.button("Copy IP address").clicked() {
        a = Some(RowAction::CopyIp(ip));
    }
    if ui.button("Copy MAC address").clicked() {
        a = Some(RowAction::CopyMac(ip));
    }
    if ui.button("Copy name").clicked() {
        a = Some(RowAction::CopyName(ip));
    }
    if ui.button("Copy manufacturer").clicked() {
        a = Some(RowAction::CopyVendor(ip));
    }
    if ui.button("Copy all details").clicked() {
        a = Some(RowAction::CopyRow(ip));
    }
    if a.is_some() {
        ui.close();
    }
    a
}

/// Open a device's web page. The URL is built only from a parsed IPv4
/// address, a fixed scheme and a port number, so it cannot contain anything
/// the user (or a device on the network) typed.
fn open_url(ctx: &egui::Context, ip: Ipv4Addr, scheme: &'static str, port: u16) {
    let default = matches!((scheme, port), ("http", 80) | ("https", 443));
    let url = if default { format!("{scheme}://{ip}/") } else { format!("{scheme}://{ip}:{port}/") };
    ctx.open_url(egui::OpenUrl::new_tab(url));
}

fn port_row(ui: &mut egui::Ui, ip: Ipv4Addr, p: &OpenPort) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{:>5}", p.port)).monospace().strong().color(GREEN));
        ui.label(if p.service.is_empty() { "unknown service" } else { p.service });
        if let Some(scheme) = ports::web_scheme(p.port) {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Open ↗").clicked() {
                    open_url(ui.ctx(), ip, scheme, p.port);
                }
            });
        }
    });
    if let Some(b) = &p.banner {
        ui.label(RichText::new(b).monospace().small().weak());
    }
}

fn matches_filter(h: &Host, needle: &str) -> bool {
    let mac = h.mac.map(|m| m.to_string().to_ascii_lowercase()).unwrap_or_default();
    h.ip.to_string().contains(needle)
        || h.display_name().to_ascii_lowercase().contains(needle)
        || h.dns_name.as_deref().unwrap_or("").to_ascii_lowercase().contains(needle)
        || mac.contains(needle)
        || mac.replace(':', "-").contains(needle)
        || h.vendor.unwrap_or("").to_ascii_lowercase().contains(needle)
        || h.ports.as_ref().is_some_and(|ps| {
            ps.iter().any(|p| p.port.to_string() == needle || p.service.to_ascii_lowercase().contains(needle))
        })
}

fn port_count(h: &Host) -> i64 {
    h.ports.as_ref().map(|p| p.len() as i64).unwrap_or(-1)
}

fn rtt_text(h: &Host) -> String {
    match h.rtt {
        Some(d) if d < Duration::from_millis(1) => "<1 ms".into(),
        Some(d) => format!("{} ms", d.as_millis()),
        None => match h.method {
            scanner::Method::Local => "—".into(),
            m => format!("({})", m.label()),
        },
    }
}

fn ports_summary(h: &Host) -> String {
    match &h.ports {
        None => String::new(),
        Some(p) if p.is_empty() => "—".into(),
        Some(p) => p.iter().map(|o| o.port.to_string()).collect::<Vec<_>>().join(", "),
    }
}

/// A rough device icon from what we know (role, ports, manufacturer).
fn device_glyph(h: &Host) -> &'static str {
    let v = h.vendor.unwrap_or("").to_ascii_lowercase();
    let has = |port| h.ports.as_ref().is_some_and(|p| p.iter().any(|o| o.port == port));
    match h.role {
        Role::ThisComputer => "💻",
        Role::Router => "📶",
        Role::Device if has(9100) || has(631) => "🖶",
        Role::Device if v.contains("apple") || has(62078) => "📱",
        Role::Device if has(3389) || has(445) => "🖥",
        Role::Device => "🖧",
    }
}

/// Green dot = answered ping/TCP, amber = only ARP (ping blocked), blue = us.
fn status_dot(ui: &mut egui::Ui, h: &Host) {
    let color = match h.method {
        scanner::Method::Ping | scanner::Method::Tcp => GREEN,
        scanner::Method::Arp => Color32::from_rgb(210, 153, 34),
        scanner::Method::Local => ACCENT,
    };
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
    resp.on_hover_text(match h.method {
        scanner::Method::Arp => "Online (does not answer ping — firewall)",
        scanner::Method::Local => "This computer",
        _ => "Online",
    });
}

/// Theme tweaks shared by light and dark mode (egui follows the system theme).
fn apply_style(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        // No text-selection cursor: clicks go to rows and buttons; values are
        // copied with right-click menus instead.
        style.interaction.selectable_labels = false;
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.interact_size.y = 26.0;
        let v = &mut style.visuals;
        // Selected rows/text: solid colours with strong contrast in both themes.
        if v.dark_mode {
            v.selection.bg_fill = Color32::from_rgb(28, 78, 158);
            v.selection.stroke = Stroke::new(1.0, Color32::WHITE);
        } else {
            v.selection.bg_fill = Color32::from_rgb(205, 224, 252);
            v.selection.stroke = Stroke::new(1.0, Color32::from_rgb(10, 48, 110));
        }
        v.hyperlink_color = ACCENT;
        v.widgets.inactive.corner_radius = CornerRadius::same(6);
        v.widgets.hovered.corner_radius = CornerRadius::same(6);
        v.widgets.active.corner_radius = CornerRadius::same(6);
        v.widgets.noninteractive.corner_radius = CornerRadius::same(6);
        v.window_corner_radius = CornerRadius::same(10);
    });
}
