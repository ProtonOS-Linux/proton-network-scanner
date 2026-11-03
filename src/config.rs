//! Settings that are remembered between runs, in a small JSON file:
//! `~/.config/proton-ip-scanner/settings.json` (Linux) or
//! `%APPDATA%\proton-ip-scanner\settings.json` (Windows).
//!
//! Only harmless preferences are stored here — never the NVD API key or any
//! scan results. A missing, damaged or hand-edited file simply falls back to
//! the defaults; unknown values are ignored.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Refresh the offline CVE database in the background when the app opens
    /// (at most once a day, and only if it can reach NVD).
    pub auto_update_db: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { auto_update_db: true }
    }
}

fn path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("proton-ip-scanner").join("settings.json"))
}

impl Config {
    pub fn load() -> Config {
        let Some(p) = path() else { return Config::default() };
        // Refuse anything large: this file is a few bytes.
        let Some(bytes) = fs::read(&p).ok().filter(|b| b.len() < 64 * 1024) else { return Config::default() };
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Config { auto_update_db: v["auto_update_db"].as_bool().unwrap_or(true) }
    }

    /// Save (best effort: failure just means the setting is not remembered).
    pub fn save(&self) {
        let Some(p) = path() else { return };
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let tmp = p.with_extension(format!("tmp{}", std::process::id()));
        let body = json!({ "auto_update_db": self.auto_update_db }).to_string();
        if fs::write(&tmp, body).is_ok() {
            let _ = fs::rename(&tmp, &p);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }
}
