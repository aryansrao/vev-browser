//! Session persistence: remember open (non-private) tabs so an accidental
//! quit or crash can be restored on next launch.

use crate::tabs;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Default, Serialize, Deserialize)]
struct Session {
    tabs: Vec<String>,
    active_index: usize,
}

fn path(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.path().app_data_dir().ok().map(|d| d.join("session.json"))
}

/// Persist the current open tabs (skips private/Tor tabs and blank/start
/// pages). Called after tab changes. Main thread only (reads the manager).
pub fn save(app: &AppHandle) {
    let (urls, active): (Vec<String>, Option<u32>) = tabs::with_manager(|m| {
        let infos = m.infos("main");
        let urls = infos
            .iter()
            .filter(|t| !t.is_private && !t.is_tor)
            .filter(|t| t.url.starts_with("http"))
            .map(|t| t.url.clone())
            .collect();
        (urls, m.active_id("main"))
    });
    let active_index = tabs::with_manager(|m| {
        m.infos("main")
            .iter()
            .filter(|t| !t.is_private && !t.is_tor && t.url.starts_with("http"))
            .position(|t| Some(t.id) == active)
            .unwrap_or(0)
    });
    let Some(p) = path(app) else { return };
    let s = Session {
        tabs: urls,
        active_index,
    };
    if let Ok(bytes) = serde_json::to_vec(&s) {
        let _ = std::fs::write(p, bytes);
    }
}

/// URLs of the previous session's tabs (most-relevant order preserved).
pub fn restore_urls(app: &AppHandle) -> Vec<String> {
    let Some(p) = path(app) else { return Vec::new() };
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice::<Session>(&b).ok())
        .map(|s| s.tabs)
        .unwrap_or_default()
}
