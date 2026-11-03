//! Proton IP Scanner — find the devices on your network, their MAC addresses,
//! names, manufacturers and open ports. Works on Linux and Windows without
//! administrator rights.
//!
//! Code map:
//! * `scanner/` — the scanning engine (no UI code):
//!   `range` (parsing input), `ping` (is it alive?), `mac` (ARP table),
//!   `vendor` (manufacturer list), `names` (DNS + NetBIOS), `ports` (TCP).
//! * `app.rs`   — the graphical window (egui).
//! * `cli.rs`   — the `--scan` command-line mode.
//! * `vuln/`     — vulnerability assessment: service detection, safe
//!   configuration checks, NVD/EPSS lookups, CVSS v4 / EPSS / priority.
//! * `report/`   — Excel and PDF vulnerability reports.
//! * `export.rs`— CSV / HTML device lists.
//! * `icon.rs`  — the window icon, drawn in code.

// No console window behind the GUI on Windows (release builds).
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
// Unsafe code is only allowed in the two small Windows API wrappers
// (scanner/ping.rs and scanner/mac.rs), each with a SAFETY comment.
#![deny(unsafe_op_in_unsafe_fn)]

mod app;
mod cli;
mod config;
mod export;
mod icon;
mod report;
mod scanner;
mod vuln;

#[cfg(test)]
mod fuzz_tests;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Version 1.1.0 cached NVD answers on disk; every scan now starts fresh,
    // so remove any such leftovers.
    vuln::nvd::clear_old_cache();

    // Any argument means command-line mode (help, version, --scan…).
    if !args.is_empty() {
        attach_parent_console();
        std::process::exit(cli::run(&args));
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Proton IP Scanner")
            .with_app_id("org.protonos.ProtonIpScanner")
            .with_inner_size([1180.0, 720.0])
            .with_min_inner_size([760.0, 460.0])
            .with_icon(icon::window_icon()),
        // eframe redraws only when something changes (input or a repaint
        // request), so the idle window uses no CPU.
        ..Default::default()
    };

    if let Err(e) = eframe::run_native("Proton IP Scanner", options, Box::new(|cc| Ok(Box::new(app::App::new(cc))))) {
        eprintln!("Proton IP Scanner could not open its window: {e}");
        std::process::exit(1);
    }
}

/// Release builds on Windows are "GUI" programs with no console, so text
/// printed by the command-line mode would vanish. Attach to the console of
/// the terminal that started us (if any) so `--scan` output is visible.
#[cfg(windows)]
fn attach_parent_console() {
    use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    // SAFETY: plain Win32 call with a constant argument; failure (no parent
    // console) is harmless and simply leaves output unattached.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_parent_console() {}
