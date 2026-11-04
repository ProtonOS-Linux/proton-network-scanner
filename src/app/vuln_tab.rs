//! The "Vulnerability Scanner" tab.
//!
//! ```text
//! ┌ toolbar: [▶ Start assessment] Targets [Live devices ▾ | range……]   [Export report ▾] ┐
//! │          Ports [Vulnerability set ▾]  Speed [Normal ▾]  ☑ Online CVE lookup  ☑ Safe login checks │
//! ├ summary: [Critical n] [High n] [Medium n] [Low n] [Info n]   hosts · services        │
//! ├ view: (Top 10) (All findings) (Services)          filter…  ┬ finding details        │
//! │ table                                                       │ scores, description,   │
//! │                                                             │ solution, references   │
//! └ status: phase · progress ───────────────────────────────────┴────────────────────────┘
//! ```

use std::net::Ipv4Addr;
use std::time::Instant;

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, RichText, Sense, Vec2};
use egui_extras::{Column, TableBuilder};

use super::widgets::*;
use crate::export;
use crate::report::{self, ReportData};
use crate::scanner::{LocalNet, Speed, ports, range};
use crate::vuln::detect::Service;
use crate::vuln::offline::{self, DbInfo, OfflineDb};
use crate::vuln::score::Severity;
use crate::vuln::{self, CveSource, Finding, TopItem, VulnEvent, VulnJob, VulnOptions};

const NMAP_HELP: &str = "Nmap identifies services and versions more precisely and runs its SAFE scripts only\n\
     (no exploits, no password guessing, no denial of service, nothing contacts the internet).\n\
     Proton's own configuration checks run as well. Runs as your user, no admin rights.";

const DEEP_HELP: &str = "Deep scan: SYN port scan + operating-system detection.\n\
     Linux: asks for the administrator password for this one Nmap run (pkexec), and only\n\
     for an Nmap installed by your package manager. Nothing keeps running as admin.\n\
     Windows: uses the Npcap driver, no elevation.";

/// Port lists for the assessment. The last entry is the user's own list.
const PORT_PRESETS: [(&str, &str, &str); 4] = [
    (
        "Standard (52 ports)",
        ports::PRESET_VULN,
        "Common services, databases, remote access, IoT and container ports. Fast: about a minute per device.",
    ),
    (
        "Comprehensive (1,298 ports)",
        ports::PRESET_COMPREHENSIVE,
        "All well-known ports 1-1024 plus ~270 registered ports where admin panels, databases, IoT and \
         industrial services live. A few minutes per device.",
    ),
    (
        "Full scan (all 65,535 ports)",
        ports::PRESET_FULL,
        "Every TCP port. Finds services on unusual ports, but takes much longer \
         (tens of minutes per device, hours in Slow mode).",
    ),
    ("Custom list…", "", "Your own ports, e.g. 22,80,443,8000-8100."),
];

/// A background download of the offline database.
struct DbJob {
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    progress: std::sync::Arc<std::sync::Mutex<(usize, usize, String)>>,
    rx: std::sync::mpsc::Receiver<Result<DbInfo, String>>,
    /// Started automatically when the app opened (failures are reported gently).
    auto: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Top10,
    All,
    Services,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetSource {
    /// The device selected on the Network Scanner tab.
    Selected,
    /// The live devices found on the Network Scanner tab.
    NetworkDevices,
    /// An IP range typed by the user (live hosts are found first).
    Range,
}

/// What the Network tab tells this tab.
pub struct NetworkInfo<'a> {
    pub live: Vec<Ipv4Addr>,
    pub nets: &'a [LocalNet],
    pub port_timeout_ms: u64,
    pub nvd_api_key: Option<String>,
    /// Device selected on the Network Scanner tab.
    pub selected: Option<Ipv4Addr>,
}

pub struct VulnTab {
    source: TargetSource,
    range_text: String,
    preset: usize,
    custom_ports: String,
    speed: Speed,
    cve_source: CveSource,
    safe_logins: bool,
    /// List each CVE that could apply to approximately-known software (Unverified).
    show_unverified: bool,
    /// Scan engine (Nmap only when installed) and its deep-scan option.
    engine: vuln::Engine,
    deep: bool,
    /// Nmap found on this computer (looked up when the tab is created).
    nmap: Option<crate::nmap::NmapInfo>,
    /// Installed offline database (shown in the Database menu).
    db_info: Option<DbInfo>,
    db_job: Option<DbJob>,

    job: Option<VulnJob>,
    /// Description of the last scan's scope, for reports: targets,
    /// speed + engine, CVE source.
    scope: Option<(String, String, CveSource)>,
    services: Vec<Service>,
    findings: Vec<Finding>,
    hosts: usize,
    notes: Vec<String>,
    top: Vec<TopItem>,
    duration_secs: f64,
    demo: bool,

    view: View,
    selected: Option<usize>,
    sev_filter: Option<Severity>,
    search: String,
    /// Message for the status bar (drained by the app).
    pub toast: Option<(String, bool)>,
}

impl VulnTab {
    pub fn new(default_range: String) -> VulnTab {
        VulnTab {
            source: TargetSource::NetworkDevices,
            range_text: default_range,
            preset: 0,
            custom_ports: ports::PRESET_VULN.into(),
            speed: Speed::Normal,
            cve_source: CveSource::Online,
            safe_logins: true,
            show_unverified: false,
            engine: vuln::Engine::Builtin,
            deep: false,
            nmap: crate::nmap::find(),
            db_info: offline::installed_info(),
            db_job: None,
            job: None,
            scope: None,
            services: Vec::new(),
            findings: Vec::new(),
            hosts: 0,
            notes: Vec::new(),
            top: Vec::new(),
            duration_secs: 0.0,
            demo: false,
            view: View::Top10,
            selected: None,
            sev_filter: None,
            search: String::new(),
            toast: None,
        }
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Nmap was installed or removed (Settings → Look again).
    pub fn set_nmap(&mut self, nmap: Option<crate::nmap::NmapInfo>) {
        if nmap.is_none() {
            self.engine = vuln::Engine::Builtin;
        }
        self.nmap = nmap;
    }

    fn ports_text(&self) -> &str {
        if self.preset == PORT_PRESETS.len() - 1 { &self.custom_ports } else { PORT_PRESETS[self.preset].1 }
    }

    /// Forget all results (also done automatically when a new assessment starts).
    fn clear(&mut self) {
        self.services.clear();
        self.findings.clear();
        self.notes.clear();
        self.top.clear();
        self.hosts = 0;
        self.selected = None;
        self.sev_filter = None;
        self.search.clear();
        self.demo = false;
        self.scope = None;
        self.duration_secs = 0.0;
    }

    fn start(&mut self, net: &NetworkInfo<'_>) {
        let ports = match range::parse_ports(self.ports_text()) {
            Ok(p) => p,
            Err(e) => return self.toast = Some((e, true)),
        };
        let (targets, discover_first, desc) = match self.source {
            TargetSource::Selected => match net.selected {
                Some(ip) => (vec![ip], false, ip.to_string()),
                None => {
                    return self.toast = Some((
                        "Select a device on the Network Scanner tab first, or choose another target.".into(),
                        true,
                    ));
                }
            },
            TargetSource::NetworkDevices => {
                if net.live.is_empty() {
                    return self.toast = Some((
                        "No live devices yet. Run a scan on the Network Scanner tab first, or choose \"IP range\" as the target.".into(),
                        true,
                    ));
                }
                let d = format!("{} live device(s) from the network scan", net.live.len());
                (net.live.clone(), false, d)
            }
            TargetSource::Range => match range::parse_ip_ranges(&self.range_text) {
                Ok(ips) => (ips, true, self.range_text.trim().to_string()),
                Err(e) => return self.toast = Some((e, true)),
            },
        };
        // Every assessment starts from a clean slate: no results, notes or
        // filters from an earlier scan, and no cached lookups (see vuln::nvd).
        self.clear();
        if self.engine == vuln::Engine::Nmap && self.nmap.is_none() {
            return self.toast =
                Some(("Nmap is not installed. Install it, or choose the built-in engine.".into(), true));
        }
        let deep = self.engine == vuln::Engine::Nmap && self.deep;
        self.scope = Some((desc, vuln::engine_label(self.speed, self.engine, deep), self.cve_source));
        self.job = Some(vuln::start(VulnOptions {
            targets,
            discover_first,
            ports,
            speed: self.speed,
            port_timeout_ms: net.port_timeout_ms,
            cve_source: self.cve_source,
            safe_logins: self.safe_logins,
            nvd_api_key: net.nvd_api_key.clone(),
            nets: net.nets.to_vec(),
            engine: self.engine,
            show_unverified: self.show_unverified,
            deep,
        }));
    }

    /// Apply events from the running assessment (called every frame).
    pub fn poll(&mut self) {
        let Some(job) = &mut self.job else { return };
        let mut finished = false;
        let mut changed = false;
        for _ in 0..4_000 {
            match job.rx.try_recv() {
                Ok(VulnEvent::Host) => self.hosts += 1,
                Ok(VulnEvent::Service(s)) => self.services.push(*s),
                Ok(VulnEvent::Finding(f)) => {
                    self.findings.push(*f);
                    changed = true;
                }
                Ok(VulnEvent::Note(n)) => self.notes.push(n),
                Ok(VulnEvent::Finished) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }
        if finished {
            job.finished_at = Some(Instant::now());
            self.duration_secs = job.elapsed().as_secs_f64();
            if job.is_cancelled() {
                self.notes.push("The assessment was stopped before it finished; results are partial.".into());
            }
            self.job = None;
        }
        if changed {
            self.resort();
        }
    }

    /// Keep findings in priority order and the Top 10 up to date.
    fn resort(&mut self) {
        let sel_key = self.selected.and_then(|i| self.findings.get(i)).map(|f| (f.id.clone(), f.ip, f.port));
        self.findings.sort_by(|a, b| a.rank_cmp(b));
        self.top = vuln::top10(&self.findings);
        self.selected = sel_key.and_then(|k| self.findings.iter().position(|f| (f.id.clone(), f.ip, f.port) == k));
    }

    fn stop(&self) {
        if let Some(j) = &self.job {
            j.cancel();
        }
    }

    fn report_data(&self) -> Option<ReportData<'_>> {
        if self.findings.is_empty() && self.services.is_empty() {
            return None;
        }
        let (targets, speed, source) =
            self.scope.clone().unwrap_or_else(|| ("—".into(), self.speed.label().into(), self.cve_source));
        Some(ReportData {
            generated: export::now_readable(),
            targets: if self.demo { format!("{targets} (DEMO DATA)") } else { targets },
            speed,
            duration_secs: self.duration_secs,
            hosts: self.hosts,
            cve_data: vuln::cve_data_label(source),
            services: &self.services,
            findings: &self.findings,
            top10: &self.top,
            notes: &self.notes,
        })
    }

    fn export(&mut self, excel: bool) {
        let Some(d) = self.report_data() else {
            return self.toast = Some(("Nothing to report yet — run an assessment first.".into(), true));
        };
        let saved = if excel {
            report::xlsx::build(&d)
                .map_err(|e| e.to_string())
                .and_then(|b| export::save_bytes("proton-vulnerability-report", "xlsx", &b).map_err(|e| e.to_string()))
        } else {
            let b = report::pdf::build(&d);
            export::save_bytes("proton-vulnerability-report", "pdf", &b).map_err(|e| e.to_string())
        };
        self.toast = Some(match saved {
            Ok(p) => (format!("Saved {}", p.display()), false),
            Err(e) => (format!("Could not save the report: {e}"), true),
        });
    }

    // -----------------------------------------------------------------
    // UI
    // -----------------------------------------------------------------

    pub fn toolbar(&mut self, ui: &mut egui::Ui, net: &NetworkInfo<'_>) {
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            toolbar_spacing(ui);
            if self.busy() {
                if ui.add(action_button("■  Stop", RED)).clicked() {
                    self.stop();
                }
            } else if ui
                .add(action_button("▶  Start assessment", MAGENTA))
                .on_hover_text("Find open services and check them for known vulnerabilities")
                .clicked()
            {
                self.start(net);
            }
            ui.add_space(4.0);
            toolbar_label(ui, "Targets");
            let busy = self.busy();
            ui.add_enabled_ui(!busy, |ui| {
                let live_label = format!("Live devices from Network Scanner ({})", net.live.len());
                let sel_label = match net.selected {
                    Some(ip) => format!("Selected device ({ip})"),
                    None => "Selected device (none selected)".into(),
                };
                egui::ComboBox::from_id_salt("vuln-source")
                    .width(260.0)
                    .selected_text(match self.source {
                        TargetSource::Selected => sel_label.clone(),
                        TargetSource::NetworkDevices => live_label.clone(),
                        TargetSource::Range => "IP range".into(),
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.source, TargetSource::Selected, sel_label);
                        ui.selectable_value(&mut self.source, TargetSource::NetworkDevices, live_label);
                        ui.selectable_value(&mut self.source, TargetSource::Range, "IP range");
                    });
                if self.source == TargetSource::Range {
                    ui.add(text_box(&mut self.range_text, 230.0, "e.g. 192.168.1.0/24", 512));
                }
            });
            if ui
                .add_enabled(!busy && !(self.findings.is_empty() && self.services.is_empty()), tool_button("✖ Clear"))
                .on_hover_text("Clear the results (a new assessment always starts fresh)")
                .clicked()
            {
                self.clear();
            }
            ui.separator();
            self.engine_picker(ui);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                self.database_menu(ui, net);
                ui.menu_button("💾 Export report ⏷", |ui| {
                    if ui.button("Excel workbook (.xlsx)").clicked() {
                        self.export(true);
                        ui.close();
                    }
                    if ui.button("PDF report").clicked() {
                        self.export(false);
                        ui.close();
                    }
                });
            });
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            toolbar_spacing(ui);
            ui.add_enabled_ui(!self.busy(), |ui| {
                toolbar_label(ui, "Ports");
                egui::ComboBox::from_id_salt("vuln-ports")
                    .width(230.0)
                    .selected_text(PORT_PRESETS[self.preset].0)
                    .show_ui(ui, |ui| {
                        for (i, (name, _, help)) in PORT_PRESETS.iter().enumerate() {
                            ui.selectable_value(&mut self.preset, i, *name).on_hover_text(*help);
                        }
                    })
                    .response
                    .on_hover_text(PORT_PRESETS[self.preset].2);
                if self.preset == PORT_PRESETS.len() - 1 {
                    ui.add(text_box(&mut self.custom_ports, 200.0, "e.g. 22,80,443,8000-8100", 2048));
                }
                ui.separator();
                toolbar_label(ui, "Speed");
                egui::ComboBox::from_id_salt("vuln-speed")
                    .width(150.0)
                    .selected_text(self.speed.label())
                    .show_ui(ui, |ui| {
                        for s in Speed::ALL {
                            ui.selectable_value(&mut self.speed, s, s.label()).on_hover_text(speed_help(s));
                        }
                    })
                    .response
                    .on_hover_text(speed_help(self.speed));
                ui.separator();
                toolbar_label(ui, "CVE data");
                egui::ComboBox::from_id_salt("vuln-cve")
                    .width(190.0)
                    .selected_text(self.cve_source.label())
                    .show_ui(ui, |ui| {
                        for c in CveSource::ALL {
                            ui.selectable_value(&mut self.cve_source, c, c.label()).on_hover_text(cve_help(c));
                        }
                    })
                    .response
                    .on_hover_text(cve_help(self.cve_source));
                ui.separator();
                self.update_button(ui, net);
                ui.separator();
                ui.checkbox(&mut self.safe_logins, "Safe login checks").on_hover_text(
                    "Try documented anonymous access (FTP 'anonymous', MQTT without password).\n\
                     Nothing is changed on the device.",
                );
                ui.checkbox(&mut self.show_unverified, "Show unverified CVEs").on_hover_text(
                    "When only an approximate version is visible (e.g. Samba \"4\"), list every CVE that could\n\
                     apply as its own finding, marked Unverified. Off: one \"needs manual check\" finding per\n\
                     service (severity Review) lists them instead.",
                );
            });
        });
        ui.add_space(10.0);
    }

    /// "Engine [Built-in ▾] ☐ Deep scan" — Nmap is offered when installed.
    fn engine_picker(&mut self, ui: &mut egui::Ui) {
        let busy = self.busy();
        ui.add_enabled_ui(!busy, |ui| {
            toolbar_label(ui, "Engine");
            let nmap_label = match &self.nmap {
                Some(n) => n.label(),
                None => "Nmap (not installed)".into(),
            };
            egui::ComboBox::from_id_salt("vuln-engine")
                .width(150.0)
                .selected_text(match self.engine {
                    vuln::Engine::Builtin => "Built-in".to_string(),
                    vuln::Engine::Nmap => nmap_label.clone(),
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.engine, vuln::Engine::Builtin, "Built-in")
                        .on_hover_text("Proton's own service detection and configuration checks. Needs nothing else.");
                    ui.add_enabled_ui(self.nmap.is_some(), |ui| {
                        ui.selectable_value(&mut self.engine, vuln::Engine::Nmap, nmap_label)
                            .on_hover_text(NMAP_HELP)
                            .on_disabled_hover_text(crate::nmap::missing_text());
                    });
                })
                .response
                .on_hover_text(if self.engine == vuln::Engine::Nmap {
                    NMAP_HELP
                } else {
                    "How services are identified"
                });
            if self.engine == vuln::Engine::Nmap {
                ui.checkbox(&mut self.deep, "Deep scan").on_hover_text(DEEP_HELP);
            }
            if self.nmap.is_none() {
                ui.hyperlink_to("Get Nmap", crate::nmap::DOWNLOAD_URL)
                    .on_hover_text("Optional. After installing, use Settings → Look again.");
            }
        });
    }

    /// "Database" menu: status of the offline database, download, export, import.
    fn database_menu(&mut self, ui: &mut egui::Ui, net: &NetworkInfo<'_>) {
        ui.menu_button("🗄 Database ⏷", |ui| {
            ui.set_min_width(330.0);
            ui.label(RichText::new("Offline vulnerability database").strong());
            match &self.db_info {
                Some(i) => {
                    ui.label(i.label());
                    if i.age_days() > 30 {
                        ui.label(RichText::new(format!("{} days old — consider updating.", i.age_days())).color(AMBER));
                    }
                }
                None => {
                    ui.label(RichText::new("Not installed. Without it, CVE matching needs internet.").weak());
                }
            }
            ui.separator();
            let downloading = self.db_job.is_some();
            if ui
                .add_enabled(!downloading, egui::Button::new("⬇ Download / update (needs internet)"))
                .on_hover_text("Downloads every CVE for the software this scanner can detect, with EPSS and KEV.\nAbout 3 minutes (much faster with an NVD API key in Settings).")
                .clicked()
            {
                self.start_db_download(net.nvd_api_key.clone(), false);
                ui.close();
            }
            if ui
                .add_enabled(self.db_info.is_some(), egui::Button::new("📤 Export to Documents (for offline PCs)"))
                .clicked()
            {
                self.toast = Some(match offline::export_installed() {
                    Ok(p) => (format!("Exported {} — copy it to the offline computer and use Import.", p.display()), false),
                    Err(e) => (format!("Export failed: {e}"), true),
                });
                ui.close();
            }
            ui.menu_button("📥 Import from Documents / Downloads", |ui| {
                let files = offline::import_candidates();
                if files.is_empty() {
                    ui.label(RichText::new("No proton-vulndb-*.json.gz files found in Documents or Downloads.").weak());
                }
                for f in files {
                    let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    if ui.button(name).clicked() {
                        self.toast = Some(match OfflineDb::load_file(&f).and_then(|db| db.install()) {
                            Ok(info) => {
                                let msg = format!("Imported the offline database: {}.", info.label());
                                self.db_info = Some(info);
                                (msg, false)
                            }
                            Err(e) => (format!("Import failed: {e}"), true),
                        });
                        ui.close();
                    }
                }
            });
            if ui.add_enabled(self.db_info.is_some(), egui::Button::new("🗑 Delete offline database")).clicked() {
                offline::uninstall();
                self.db_info = None;
                ui.close();
            }
        });
    }

    /// "⟳ Update CVE database" button with the database's age next to it.
    fn update_button(&mut self, ui: &mut egui::Ui, net: &NetworkInfo<'_>) {
        if let Some(job) = &self.db_job {
            let (done, total, _) = job.progress.lock().map(|g| g.clone()).unwrap_or_default();
            let pct = (done * 100).checked_div(total).unwrap_or(0);
            ui.add_enabled(false, tool_button(&format!("⟳ Updating CVE database… {pct}%")));
            return;
        }
        if ui
            .add(tool_button("⟳ Update CVE database"))
            .on_hover_text(
                "Download the newest CVEs, EPSS scores and KEV flags for every product the scanner\n\
                 recognises, into the local (offline) database. Needs internet; ~3 minutes,\n\
                 much faster with an NVD API key in Settings.",
            )
            .clicked()
        {
            self.start_db_download(net.nvd_api_key.clone(), false);
        }
        let (text, color) = match &self.db_info {
            Some(i) if i.age_days() > 30 => (format!("{} CVEs · {} days old", i.cves, i.age_days()), AMBER),
            Some(i) => {
                (format!("{} CVEs · updated {}", i.cves, offline::date(i.created)), ui.visuals().weak_text_color())
            }
            None => ("local CVE database: not downloaded yet".into(), ui.visuals().weak_text_color()),
        };
        ui.label(RichText::new(text).color(color));
    }

    /// Called when the app opens: refresh the local CVE database in the
    /// background if it is missing or more than ~a day old.
    pub fn auto_update(&mut self, api_key: Option<String>) {
        let fresh = self.db_info.as_ref().is_some_and(|i| i.age_hours() < 20);
        if self.db_job.is_none() && !fresh {
            self.start_db_download(api_key, true);
        }
    }

    fn start_db_download(&mut self, api_key: Option<String>, auto: bool) {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex};
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Mutex::new((0, offline::PRODUCTS.len() + 1, "starting…".to_string())));
        let (tx, rx) = std::sync::mpsc::channel();
        let (c, p) = (cancel.clone(), progress.clone());
        let spawned = std::thread::Builder::new().name("vulndb-download".into()).spawn(move || {
            let res = offline::build(api_key, &c, &|done, total, label| {
                if let Ok(mut g) = p.lock() {
                    *g = (done, total, label.to_string());
                }
            })
            .and_then(|db| db.install());
            let _ = tx.send(res);
        });
        if spawned.is_ok() {
            self.db_job = Some(DbJob { cancel, progress, rx, auto });
        }
    }

    /// Check on a running database download (called every frame).
    pub fn poll_db(&mut self) -> bool {
        let Some(job) = &self.db_job else { return false };
        let auto = job.auto;
        match job.rx.try_recv() {
            Ok(res) => {
                self.toast = Some(match res {
                    // An automatic update without internet is normal: say so quietly.
                    Err(e) if auto && e.starts_with("could not reach") => (
                        match &self.db_info {
                            Some(i) => format!(
                                "No internet: the CVE database was not updated (using the copy from {}).",
                                offline::date(i.created)
                            ),
                            None => "No internet: the CVE database could not be downloaded yet.".into(),
                        },
                        false,
                    ),
                    Ok(info) => {
                        let msg = format!("Offline vulnerability database updated: {}.", info.label());
                        self.db_info = Some(info);
                        (msg, false)
                    }
                    Err(e) if e.starts_with("could not reach") => {
                        (format!("Download failed — no connection to NVD ({e})."), true)
                    }
                    Err(e) => (format!("Download failed: {e}"), true),
                });
                self.db_job = None;
                false
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => true,
            Err(_) => {
                self.db_job = None;
                false
            }
        }
    }

    pub fn status(&self, ui: &mut egui::Ui) {
        if let Some(db) = &self.db_job {
            let (done, total, label) = db.progress.lock().map(|g| g.clone()).unwrap_or_default();
            let frac = if total == 0 { 0.0 } else { done as f32 / total as f32 };
            ui.add(egui::ProgressBar::new(frac).desired_width(160.0).fill(ACCENT).show_percentage());
            ui.label(format!("Downloading the offline database: {label} ({done}/{total})"));
            if ui.small_button("Cancel").clicked() {
                db.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            ui.separator();
        }
        if let Some(job) = &self.job {
            let p = &job.progress;
            let (done, total) =
                (p.done.load(std::sync::atomic::Ordering::Relaxed), p.total.load(std::sync::atomic::Ordering::Relaxed));
            let frac = if total == 0 { 0.0 } else { done as f32 / total as f32 };
            ui.add(egui::ProgressBar::new(frac).desired_width(200.0).fill(MAGENTA).show_percentage());
            let detail = p.detail();
            ui.label(format!(
                "{}{}{} · {} findings · {:.0} s{}",
                p.phase().label(),
                if total > 0 { format!(" ({done}/{total})") } else { String::new() },
                if detail.is_empty() { String::new() } else { format!(" · {detail}") },
                self.findings.len(),
                job.elapsed().as_secs_f64(),
                if job.is_cancelled() { " · stopping…" } else { "" },
            ));
        } else if self.scope.is_some() {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 4.5, GREEN);
            ui.label(format!(
                "Assessment {}: {} hosts, {} services, {} findings in {:.0} s",
                if self.demo { "(demo data)" } else { "finished" },
                self.hosts,
                self.services.len(),
                self.findings.len(),
                self.duration_secs
            ));
        } else {
            ui.label(RichText::new("Ready. Choose targets and press Start assessment.").weak());
        }
    }

    pub fn central(&mut self, ui: &mut egui::Ui) {
        if self.findings.is_empty() && self.services.is_empty() {
            let busy_text = self.job.as_ref().map(|j| j.progress.phase().label()).unwrap_or("");
            empty_state(
                ui,
                "🛡",
                self.busy(),
                busy_text,
                "No assessment yet",
                "Find devices on the Network Scanner tab, then press Start assessment to check their services.",
            );
            return;
        }

        // Notes (e.g. "NVD unreachable") at the top, where they are seen.
        for n in &self.notes {
            egui::Frame::new()
                .fill(AMBER.linear_multiply(0.18))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("⚠  {n}")).color(ui.visuals().strong_text_color()));
                });
            ui.add_space(4.0);
        }

        self.summary_cards(ui);
        ui.add_space(8.0);

        // View switch + search.
        ui.horizontal(|ui| {
            let n_all = self.visible().len();
            for (v, label) in [
                (View::Top10, "Top 10 vulnerabilities".to_string()),
                (View::All, format!("All findings ({n_all})")),
                (View::Services, format!("Services ({})", self.services.len())),
            ] {
                if ui.selectable_label(self.view == v, RichText::new(label).strong()).clicked() {
                    self.view = v;
                }
            }
            if self.view != View::Top10 {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("🔍 Filter")
                            .desired_width(200.0)
                            .char_limit(100),
                    );
                    if let Some(s) = self.sev_filter
                        && ui.small_button(format!("✖ {}", s.label())).on_hover_text("Clear severity filter").clicked()
                    {
                        self.sev_filter = None;
                    }
                });
            }
        });
        ui.add_space(4.0);

        match self.view {
            View::Top10 => self.top_table(ui),
            View::All => self.findings_table(ui),
            View::Services => self.services_table(ui),
        }
    }

    /// Five coloured counters; clicking one filters "All findings".
    fn summary_cards(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
            for s in Severity::ALL {
                let n = self.findings.iter().filter(|f| f.severity == s).count();
                let active = self.sev_filter == Some(s);
                let (rect, resp) = ui.allocate_exact_size(Vec2::new(112.0, 58.0), Sense::click());
                let mut fill = severity_color(s);
                if self.sev_filter.is_some() && !active {
                    fill = fill.linear_multiply(0.45);
                }
                ui.painter().rect_filled(rect, CornerRadius::same(8), fill);
                ui.painter().text(
                    rect.center_top() + Vec2::new(0.0, 8.0),
                    egui::Align2::CENTER_TOP,
                    n.to_string(),
                    egui::FontId::proportional(22.0),
                    Color32::WHITE,
                );
                ui.painter().text(
                    rect.center_bottom() - Vec2::new(0.0, 7.0),
                    egui::Align2::CENTER_BOTTOM,
                    s.label(),
                    egui::FontId::proportional(12.0),
                    Color32::WHITE,
                );
                if resp.on_hover_text(format!("Show only {} findings", s.label())).clicked() {
                    self.sev_filter = if active { None } else { Some(s) };
                    self.view = View::All;
                }
            }
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(format!("{} hosts · {} open services", self.hosts, self.services.len())).strong(),
                );
                let kev = self.top.iter().filter(|t| t.finding.kev).count();
                let cves = {
                    let mut ids: Vec<&str> =
                        self.findings.iter().filter(|f| f.is_cve()).map(|f| f.id.as_str()).collect();
                    ids.sort_unstable();
                    ids.dedup();
                    ids.len()
                };
                ui.label(RichText::new(format!("{cves} distinct CVEs · {kev} known exploited in Top 10")).weak());
            });
        });
    }

    fn visible(&self) -> Vec<usize> {
        let q = self.search.trim().to_ascii_lowercase();
        (0..self.findings.len())
            .filter(|&i| {
                let f = &self.findings[i];
                self.sev_filter.is_none_or(|s| f.severity == s)
                    && (q.is_empty()
                        || f.id.to_ascii_lowercase().contains(&q)
                        || f.title.to_ascii_lowercase().contains(&q)
                        || f.ip.to_string().contains(&q)
                        || f.service.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    fn top_table(&mut self, ui: &mut egui::Ui) {
        if self.top.is_empty() {
            ui.add_space(20.0);
            ui.label(RichText::new("No vulnerabilities above informational level were found. 🎉").weak());
            return;
        }
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("top10")
            .striped(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(24.0))
            .column(Column::exact(78.0))
            .column(Column::initial(120.0).at_least(100.0))
            .column(Column::remainder().at_least(160.0).clip(true))
            .column(Column::exact(48.0))
            .column(Column::exact(58.0))
            .column(Column::exact(62.0))
            .column(Column::exact(44.0))
            .column(Column::exact(40.0))
            .column(Column::exact(112.0))
            .header(26.0, |mut h| {
                for t in ["#", "Severity", "ID", "Vulnerability", "Hosts", "CVSS", "EPSS", "PPR", "KEV", "Confidence"] {
                    h.col(|ui| {
                        ui.strong(t).on_hover_text(column_help(t));
                    });
                }
            })
            .body(|body| {
                body.rows(28.0, self.top.len(), |mut row| {
                    let i = row.index();
                    let t = &self.top[i];
                    let f = &t.finding;
                    row.set_selected(self.selected.and_then(|s| self.findings.get(s)).is_some_and(|s| s.id == f.id));
                    row.col(|ui| {
                        ui.label(RichText::new((i + 1).to_string()).strong());
                    });
                    row.col(|ui| {
                        severity_tag(ui, f.severity);
                    });
                    row.col(|ui| {
                        ui.monospace(&f.id);
                    });
                    row.col(|ui| {
                        ui.label(&f.title);
                    });
                    row.col(|ui| {
                        ui.label(t.hosts.to_string());
                    });
                    row.col(|ui| {
                        ui.label(cvss_text(f));
                    });
                    row.col(|ui| {
                        ui.label(epss_text(f));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format!("{:.1}", f.ppr)).strong());
                    });
                    row.col(|ui| {
                        if f.kev {
                            kev_badge(ui);
                        }
                    });
                    row.col(|ui| {
                        confidence_label(ui, f.confidence);
                    });
                    if row.response().clicked() {
                        clicked = Some((f.id.clone(), f.ip, f.port));
                    }
                });
            });
        if let Some(k) = clicked {
            self.selected = self.findings.iter().position(|f| (f.id.clone(), f.ip, f.port) == k);
        }
    }

    fn findings_table(&mut self, ui: &mut egui::Ui) {
        let rows = self.visible();
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("findings")
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(78.0))
            .column(Column::initial(118.0).at_least(90.0))
            .column(Column::remainder().at_least(160.0).clip(true))
            .column(Column::initial(108.0).at_least(90.0))
            .column(Column::exact(48.0))
            .column(Column::exact(58.0))
            .column(Column::exact(62.0))
            .column(Column::exact(44.0))
            .column(Column::exact(40.0))
            .column(Column::exact(112.0))
            .header(26.0, |mut h| {
                for t in ["Severity", "ID", "Title", "Host", "Port", "CVSS", "EPSS", "PPR", "KEV", "Confidence"] {
                    h.col(|ui| {
                        ui.strong(t).on_hover_text(column_help(t));
                    });
                }
            })
            .body(|body| {
                body.rows(26.0, rows.len(), |mut row| {
                    let idx = rows[row.index()];
                    let f = &self.findings[idx];
                    row.set_selected(self.selected == Some(idx));
                    row.col(|ui| {
                        severity_tag(ui, f.severity);
                    });
                    row.col(|ui| {
                        ui.monospace(&f.id);
                    });
                    row.col(|ui| {
                        ui.label(&f.title);
                    });
                    row.col(|ui| {
                        ui.monospace(f.ip.to_string());
                    });
                    row.col(|ui| {
                        ui.label(f.port.to_string());
                    });
                    row.col(|ui| {
                        ui.label(cvss_text(f));
                    });
                    row.col(|ui| {
                        ui.label(epss_text(f));
                    });
                    row.col(|ui| {
                        ui.label(if f.ppr > 0.0 { format!("{:.1}", f.ppr) } else { "—".into() });
                    });
                    row.col(|ui| {
                        if f.kev {
                            kev_badge(ui);
                        }
                    });
                    row.col(|ui| {
                        confidence_label(ui, f.confidence);
                    });
                    if row.response().clicked() {
                        clicked = Some(idx);
                    }
                });
            });
        if let Some(i) = clicked {
            self.selected = Some(i);
        }
    }

    fn services_table(&mut self, ui: &mut egui::Ui) {
        let q = self.search.trim().to_ascii_lowercase();
        let mut list: Vec<&Service> = self
            .services
            .iter()
            .filter(|s| {
                q.is_empty()
                    || s.ip.to_string().contains(&q)
                    || s.name.to_ascii_lowercase().contains(&q)
                    || s.products.iter().any(|p| p.label().to_ascii_lowercase().contains(&q))
            })
            .collect();
        list.sort_by_key(|s| (s.ip, s.port));
        TableBuilder::new(ui)
            .id_salt("services")
            .striped(true)
            .resizable(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(118.0))
            .column(Column::exact(56.0))
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(220.0).clip(true))
            .column(Column::remainder().clip(true))
            .header(26.0, |mut h| {
                for t in ["Host", "Port", "Service", "Software", "Banner"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(24.0, list.len(), |mut row| {
                    let s = list[row.index()];
                    row.col(|ui| {
                        ui.monospace(s.ip.to_string());
                    });
                    row.col(|ui| {
                        ui.label(s.port.to_string());
                    });
                    row.col(|ui| {
                        ui.label(&s.name);
                    });
                    row.col(|ui| {
                        ui.label(s.products.iter().map(|p| p.label()).collect::<Vec<_>>().join(", "));
                    });
                    row.col(|ui| {
                        let r = ui.label(RichText::new(s.banner.as_deref().unwrap_or("")).monospace().weak());
                        if !s.nse.is_empty() {
                            let text: Vec<String> = s.nse.iter().map(|(id, out)| format!("{id}:\n{out}")).collect();
                            r.on_hover_text(RichText::new(text.join("\n\n")).monospace());
                        }
                    });
                });
            });
    }

    /// Right-hand panel: everything about the selected finding.
    pub fn details(&mut self, ui: &mut egui::Ui) {
        let Some(f) = self.selected.and_then(|i| self.findings.get(i)).cloned() else {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.label(RichText::new("Select a finding to see its details.").weak()));
            return;
        };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                severity_tag(ui, f.severity);
                ui.monospace(RichText::new(&f.id).strong());
                if f.kev {
                    kev_badge(ui);
                }
            });
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(&f.title).size(15.0).strong()).wrap());
            ui.add_space(8.0);

            egui::Grid::new("finding").num_columns(2).spacing([12.0, 6.0]).striped(true).show(ui, |ui| {
                ui.label(RichText::new("Confidence").weak());
                confidence_label(ui, f.confidence);
                ui.end_row();
                let mut row = |k: &str, v: String| {
                    ui.label(RichText::new(k).weak());
                    copy_value(ui, v.clone(), &v);
                    ui.end_row();
                };
                row("Host", format!("{}:{}  ({})", f.ip, f.port, f.service));
                if let Some(p) = &f.product {
                    row("Software", p.clone());
                }
                if f.severity == Severity::Review {
                    row("Status", "Needs a manual check — not a confirmed vulnerability".into());
                } else {
                    row(
                        "CVSS",
                        f.cvss
                            .as_ref()
                            .map(|c| format!("{:.1}  (v{})", c.score, c.version))
                            .unwrap_or_else(|| "not scored yet".into()),
                    );
                    row(
                        "EPSS",
                        f.epss
                            .map(|e| {
                                format!(
                                    "{:.2}% chance of exploitation in 30 days (percentile {:.0})",
                                    e.probability * 100.0,
                                    e.percentile * 100.0
                                )
                            })
                            .unwrap_or_else(|| "—".into()),
                    );
                    row("Priority (PPR)", if f.ppr > 0.0 { format!("{:.1} / 10", f.ppr) } else { "—".into() });
                    row("Known exploited", if f.kev { "Yes — listed in CISA KEV".into() } else { "No".into() });
                }
                if let Some(p) = &f.published {
                    row("Published", p.clone());
                }
            });
            if let Some(c) = &f.cvss {
                ui.add_space(4.0);
                copy_value(ui, RichText::new(&c.vector).monospace().small().weak(), &c.vector);
            }
            section(ui, "Description", &f.description);
            section(ui, "Solution", &f.solution);
            if !f.evidence.is_empty() {
                section(ui, "Evidence", &f.evidence);
            }
            let nse = self
                .services
                .iter()
                .find(|s| s.ip == f.ip && s.port == f.port)
                .map(|s| s.nse.clone())
                .unwrap_or_default();
            if !nse.is_empty() {
                ui.add_space(10.0);
                ui.label(RichText::new("Nmap script results on this port").strong());
                for (id, out) in &nse {
                    egui::CollapsingHeader::new(RichText::new(id).monospace()).id_salt(("nse", id)).show(ui, |ui| {
                        copy_value(ui, RichText::new(out).monospace().small(), out);
                    });
                }
            }
            if !f.references.is_empty() {
                ui.add_space(10.0);
                ui.label(RichText::new("References").strong());
                for r in &f.references {
                    // Only http(s) links ever reach this list (checked when parsed).
                    ui.hyperlink_to(RichText::new(r).small(), r);
                }
            }
        });
    }

    /// Example results for screenshots (`PROTON_IP_SCANNER_DEMO=1`). Clearly
    /// marked as demo data in the status bar and reports.
    pub fn load_demo(&mut self) {
        use crate::vuln::checks;
        use crate::vuln::detect::Product;
        use crate::vuln::score::{Cvss, Epss, cve_threat, ppr};
        let ip = |n| Ipv4Addr::new(192, 168, 1, n);
        let prod = |name: &str, v: &str| Product { name: name.into(), version: v.into(), cpe: None, backported: false };
        self.services = vec![
            Service {
                ip: ip(10),
                port: 22,
                name: "SSH".into(),
                products: vec![prod("OpenSSH", "8.9p1")],
                banner: Some("SSH-2.0-OpenSSH_8.9p1".into()),
                nse: vec![("ssh-hostkey".into(), "256 a1:b2:c3:d4 (ECDSA)\n256 e5:f6:07:18 (ED25519)".into())],
            },
            Service {
                ip: ip(10),
                port: 80,
                name: "HTTP (web)".into(),
                products: vec![prod("Apache httpd", "2.4.49")],
                banner: Some("Server: Apache/2.4.49 (Unix)".into()),
                nse: vec![],
            },
            Service {
                ip: ip(10),
                port: 6379,
                name: "Redis".into(),
                products: vec![prod("Redis", "6.0.16")],
                banner: None,
                nse: vec![],
            },
            Service { ip: ip(52), port: 23, name: "Telnet".into(), products: vec![], banner: None, nse: vec![] },
            Service { ip: ip(52), port: 80, name: "HTTP (web)".into(), products: vec![], banner: None, nse: vec![] },
            Service {
                ip: ip(60),
                port: 21,
                name: "FTP".into(),
                products: vec![prod("vsftpd", "3.0.3")],
                banner: Some("220 (vsFTPd 3.0.3)".into()),
                nse: vec![],
            },
        ];
        let cve = |id: &str,
                   n: u8,
                   port: u16,
                   product: &str,
                   title: &str,
                   ver: &str,
                   score: f32,
                   vec: &str,
                   epss: f32,
                   kev: bool| {
            let e = Epss { probability: epss, percentile: 0.5 + epss / 2.0 };
            Finding {
                id: id.into(),
                title: format!("{product}: {title}"),
                ip: ip(n),
                port,
                service: if port == 22 { "SSH".into() } else { "HTTP (web)".into() },
                product: Some(product.into()),
                severity: Severity::from_score(score),
                cvss: Some(Cvss { version: ver.into(), score, vector: vec.into() }),
                epss: Some(e),
                kev,
                ppr: ppr(score, cve_threat(kev, Some(e))),
                description: format!("{title}. (Demo data for screenshots.)"),
                solution: format!("Update {product} to the latest version."),
                evidence: format!("Version-based match: {product} announced on port {port}."),
                references: vec![format!("https://nvd.nist.gov/vuln/detail/{id}")],
                published: Some("2024-01-01".into()),
                confidence: if product.starts_with("OpenSSH") {
                    vuln::Confidence::Backported
                } else {
                    vuln::Confidence::VersionMatch
                },
            }
        };
        let v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        self.findings = vec![
            cve(
                "CVE-2021-41773",
                10,
                80,
                "Apache httpd 2.4.49",
                "Path traversal and file disclosure in Apache HTTP Server 2.4.49",
                "3.1",
                7.5,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                0.94,
                true,
            ),
            cve(
                "CVE-2021-42013",
                10,
                80,
                "Apache httpd 2.4.49",
                "Path traversal and remote code execution in Apache HTTP Server 2.4.49 and 2.4.50",
                "3.1",
                9.8,
                v31,
                0.94,
                true,
            ),
            cve(
                "CVE-2024-6387",
                10,
                22,
                "OpenSSH 8.9p1",
                "Signal handler race condition in sshd (regreSSHion)",
                "3.1",
                8.1,
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                0.40,
                false,
            ),
            cve(
                "CVE-2023-38408",
                10,
                22,
                "OpenSSH 8.9p1",
                "Remote code execution through ssh-agent PKCS#11 provider loading",
                "3.1",
                9.8,
                v31,
                0.06,
                false,
            ),
            cve(
                "CVE-2023-48795",
                10,
                22,
                "OpenSSH 8.9p1",
                "Terrapin attack: prefix truncation of the SSH transport",
                "3.1",
                5.9,
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
                0.55,
                false,
            ),
            checks::REDIS_NOAUTH.finding(ip(10), 6379, "Redis", "INFO command answered without a password."),
            checks::TELNET.finding(ip(52), 23, "Telnet", "Port 23 accepts Telnet connections."),
            checks::HTTP_CLEARTEXT_LOGIN.finding(
                ip(52),
                80,
                "HTTP (web)",
                "http://192.168.1.52:80/ contains a password input field.",
            ),
            checks::FTP_ANONYMOUS.finding(ip(60), 21, "FTP", "Login as 'anonymous' accepted: 230 Login successful."),
            checks::FTP_CLEARTEXT.finding(ip(60), 21, "FTP", "220 (vsFTPd 3.0.3)"),
            checks::VERSION_DISCLOSED.finding(ip(10), 22, "SSH", "OpenSSH 8.9p1"),
            checks::VERSION_DISCLOSED.finding(ip(10), 80, "HTTP (web)", "Apache httpd 2.4.49"),
            // What a patched Samba server looks like: one "needs manual check" item.
            Finding {
                id: "REVIEW-samba".into(),
                title: "Samba smbd 4: exact version unknown — 47 CVEs could apply (2 known exploited)".into(),
                ip: ip(10),
                port: 445,
                service: "microsoft-ds".into(),
                product: Some("Samba smbd 4".into()),
                severity: Severity::Review,
                cvss: None,
                epss: None,
                kev: false,
                ppr: 0.0,
                description: "The scanner can see that this is Samba smbd but not its exact version (Samba smbd 4). \
                              Known vulnerabilities depend on the exact version, so from the network they can be \
                              neither confirmed nor ruled out. (Demo data for screenshots.)"
                    .into(),
                solution: "Check the installed version: On the server run `smbd --version` (or `apt policy samba`). \
                           Compare it with the \"fixed in\" versions listed in the evidence."
                    .into(),
                evidence: "Seen on port 445: \"Samba smbd 4\" — only the version family (4.x) is visible from the \
                           network.\n\nCVEs that affect some 4.x version, worst first:\n\
                           • CVE-2017-7494 · CVSS 9.8 · KEV · fixed in 4.6.4\n\
                           • CVE-2020-1472 · CVSS 5.5 · KEV · fixed in 4.12.4\n\
                           • CVE-2023-3961 · CVSS 9.8 · fixed in 4.19.1\n\
                           • CVE-2021-44142 · CVSS 8.8 · fixed in 4.15.5\n\
                           • CVE-2023-34966 · CVSS 7.5 · fixed in 4.18.5\n\
                           … and 42 more."
                    .into(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-7494".into()],
                published: None,
                confidence: vuln::Confidence::Unverified,
            },
        ];
        self.hosts = 3;
        self.duration_secs = 41.0;
        self.demo = true;
        if self.nmap.is_some() {
            self.engine = vuln::Engine::Nmap;
        }
        self.scope =
            Some(("192.168.1.1-254".into(), vuln::engine_label(Speed::Normal, self.engine, false), CveSource::Online));
        self.resort();
        self.selected = self.findings.iter().position(|f| f.id == "CVE-2021-42013");
    }
}

fn section(ui: &mut egui::Ui, title: &str, text: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).strong());
    copy_value(ui, text, text);
}

fn cvss_text(f: &Finding) -> String {
    match &f.cvss {
        Some(c) if c.score > 0.0 => format!("{:.1}", c.score),
        Some(_) => "0.0".into(),
        None => "—".into(),
    }
}

fn epss_text(f: &Finding) -> String {
    f.epss.map(|e| format!("{:.1}%", e.probability * 100.0)).unwrap_or_else(|| "—".into())
}

fn column_help(col: &str) -> &'static str {
    match col {
        "CVSS" => "CVSS base score 0-10 (v4.0 when published, otherwise v3.x)",
        "EPSS" => "Probability of exploitation in the next 30 days (FIRST EPSS)",
        "PPR" => "Proton Priority Rating 0-10 (VPR-style): severity combined with real-world threat",
        "KEV" => "Listed in CISA's Known Exploited Vulnerabilities catalog",
        "Confidence" => {
            "How the finding was established: Confirmed · Version match · May be backported (distribution build) · \
             Unverified (only an approximate version is visible — check manually)"
        }
        "Hosts" => "Number of hosts with this vulnerability",
        _ => "",
    }
}

fn cve_help(c: CveSource) -> &'static str {
    match c {
        CveSource::Online => {
            "Ask NVD and FIRST during each scan (newest data, fresh every time).\nOnly product names/versions and CVE numbers are sent — never IP addresses.\nIf there is no internet, the offline database is used automatically."
        }
        CveSource::Offline => {
            "Use the downloaded offline database only. Nothing is sent anywhere.\nDatabase → Download on a computer with internet, then Export / Import."
        }
        CveSource::Off => "Skip CVE matching; run only the configuration checks.",
    }
}

fn speed_help(s: Speed) -> &'static str {
    match s {
        Speed::Normal => "Fastest: many probes in parallel. Best for your own home or office network.",
        Speed::Polite => {
            "Fewer parallel probes with short random pauses, shuffled order. Gentler on fragile devices and rate limits."
        }
        Speed::Slow => {
            "One or two probes at a time with 1-3 s random pauses, shuffled order. Much less likely to be blocked by intrusion detection, but slow."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds both reports from the demo results and checks they are valid.
    /// Set `PROTON_REPORT_DIR` to also write them to disk for inspection.
    #[test]
    fn demo_reports_build() {
        let mut tab = VulnTab::new(String::new());
        tab.load_demo();
        tab.notes.push("Demo note: NVD could not be reached (example).".into());
        let d = tab.report_data().unwrap();
        let pdf = report::pdf::build(&d);
        let xlsx = report::xlsx::build(&d).unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4") && pdf.len() > 5_000);
        assert!(xlsx.starts_with(b"PK")); // xlsx is a zip file
        if let Ok(dir) = std::env::var("PROTON_REPORT_DIR") {
            std::fs::write(format!("{dir}/demo-report.pdf"), &pdf).unwrap();
            std::fs::write(format!("{dir}/demo-report.xlsx"), &xlsx).unwrap();
        }
    }
}
