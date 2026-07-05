//! Thin app-side wrapper around the `vev-tor` embedded Arti proxy.

use std::sync::OnceLock;
use vev_tor::{TorProxy, TorStatus};

static TOR: OnceLock<Option<TorProxy>> = OnceLock::new();

/// Start Arti + the local SOCKS bridge. Called once at startup. Failure to
/// start is non-fatal (normal browsing continues; Tor tabs will error).
pub fn init() {
    let proxy = match vev_tor::start() {
        Ok(p) => {
            eprintln!("vev-tor: proxy listening at {}", p.proxy_url());
            Some(p)
        }
        Err(e) => {
            eprintln!("vev-tor: failed to start: {e}");
            None
        }
    };
    let _ = TOR.set(proxy);
}

/// Address of the shared (default) Arti SOCKS proxy, available synchronously
/// after `init()` (the listener is bound before bootstrap completes). Used
/// for the browser-wide Tor routing switch.
pub fn default_proxy_addr() -> Option<String> {
    TOR.get()
        .and_then(|o| o.as_ref())
        .map(|p| p.socks_addr.to_string())
}

pub fn status_string() -> String {
    match TOR.get().and_then(|o| o.as_ref()) {
        None => "unavailable".into(),
        Some(p) => match p.status() {
            TorStatus::Bootstrapping => "bootstrapping".into(),
            TorStatus::Ready => "ready".into(),
            TorStatus::Failed => "failed".into(),
        },
    }
}

/// Proxy URL for the private threat-probes (sandbox pre-fetch + deep scan).
/// Prefers the embedded Tor bridge when ready (best unlinkability — a fresh
/// exit that can't be tied to the user or their normal browsing), and falls
/// back to the user's configured custom proxy (e.g. a Mullvad SOCKS5
/// endpoint) so the probe still never originates from the user's real IP.
/// `None` means no private route is available and the caller must NOT fetch
/// directly. Returns a full proxy URL (`socks5://…` / `http://…`).
pub fn probe_proxy_url() -> Option<String> {
    if status_string() == "ready" {
        if let Some(addr) = default_proxy_addr() {
            return Some(format!("socks5://{addr}"));
        }
    }
    crate::startpage::load_config()
        .custom_proxy_url
        .map(|u| u.trim().to_string())
        .filter(|u| {
            u.starts_with("socks5://")
                || u.starts_with("socks://")
                || u.starts_with("http://")
                || u.starts_with("https://")
        })
}

/// Address of a fresh isolated SOCKS proxy (own Tor circuits) for a new Tor
/// tab. Errors if Tor is not yet ready.
pub fn isolated_proxy_addr() -> Result<String, String> {
    match TOR.get().and_then(|o| o.as_ref()) {
        None => Err("Tor is unavailable".into()),
        Some(p) => match p.status() {
            TorStatus::Ready => vev_tor::new_isolated_proxy().map(|a| a.to_string()),
            TorStatus::Bootstrapping => Err("Tor is still bootstrapping".into()),
            TorStatus::Failed => Err("Tor failed to start".into()),
        },
    }
}
