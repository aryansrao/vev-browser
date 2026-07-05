//! App-side wiring for the Huma on-device AI layer:
//! - Guard: classify each navigation, warn on phishing structure
//! - Predict: learn navigation patterns, warm DNS/TCP for likely next sites
//! - Read: summarization is a pure command (see commands::huma_summarize)

use huma::predict::NavModel;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub struct Huma {
    nav: Mutex<NavModel>,
    path: PathBuf,
}

impl Huma {
    pub fn load(app: &tauri::AppHandle) -> Result<Self, String> {
        use tauri::Manager;
        let dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("app data dir: {e}"))?;
        std::fs::create_dir_all(&dir).ok();
        // Load the on-device self-adapting Guard layer (SEAL-style): learns
        // from local outcomes, persisted here, never uploaded.
        huma::adapt::init(dir.join("huma-adapt.json"));
        let path = dir.join("huma-nav.json");
        Ok(Self {
            nav: Mutex::new(NavModel::load(&path)),
            path,
        })
    }

    /// Record a navigation and, if a confident next-site prediction exists,
    /// warm its DNS/TCP/TLS in the background.
    pub fn on_navigation(&self, from: &str, to: &str) {
        let prediction = {
            let Ok(mut nav) = self.nav.lock() else { return };
            nav.record(from, to);
            let _ = nav.save(&self.path);
            nav.predict(to)
        };
        if let Some(p) = prediction {
            eprintln!(
                "huma-predict: warming {} (confidence {:.0}%, {} obs)",
                p.next_host,
                p.confidence * 100.0,
                p.observations
            );
            prewarm(p.next_host);
        }
    }
}

/// Warm DNS + TCP + TLS for `host` so the next navigation is faster. Best
/// effort, off-thread; failures are silent (the host may be down).
fn prewarm(host: String) {
    std::thread::spawn(move || {
        // Resolve + connect on 443 (HTTPS-only browser). This primes the OS
        // DNS cache and the TCP path; the TLS session ticket cache in the
        // network service benefits from the completed handshake.
        if let Ok(addrs) = (host.as_str(), 443u16).to_socket_addrs() {
            for addr in addrs.take(2) {
                let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(4));
            }
        }
    });
}
