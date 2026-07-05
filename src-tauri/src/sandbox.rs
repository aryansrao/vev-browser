//! Huma pre-open isolation sandbox.
//!
//! Before a gated navigation reaches the user's tab, the URL is fetched
//! **through the embedded Tor bridge** into memory — the site sees a Tor
//! exit, never the user's IP, and nothing executes (no JS, no cookies, no
//! renderer). Huma reads the fetched document's text, combines it with the
//! on-device Guard and the configured deep-scan intel sources, and only then
//! decides: clean → the real tab navigates; dangerous → the island nudges
//! with allow/deny and nothing loads until the user chooses.
//!
//! Why a Tor-routed fetch and not a hidden CEF browser: CEF 149 (Alloy)
//! refuses per-request-context proxy preferences (see README "Tor"), so a
//! hidden browser cannot be Tor-routed and would pre-fetch from the user's
//! real IP — the exact leak this feature must never cause. A full hidden
//! render (JS-built phishing pages) becomes possible only under
//! `--vev-tor-all`, where the whole browser is already Tor-routed; that
//! upgrade is future work.
//!
//! Gate modes (config.json `sandbox_gate`):
//! - "off"        — never gate; the plain non-blocking warnings remain.
//! - "suspicious" — gate only URLs the local Guard or community feed flags
//!                  (default: turns those warnings into a real gate).
//! - "all"        — gate every first visit to an unknown host this session.
//!
//! Fail-open by design: if Tor isn't ready the gate steps aside (the
//! navigation proceeds with the usual non-blocking warning) rather than
//! breaking browsing — the pre-fetch must never come from the user's IP.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

const GATE_OFF: u8 = 0;
const GATE_SUSPICIOUS: u8 = 1;
const GATE_ALL: u8 = 2;

/// Cap on the fetched document (pages past this are truncated, not failed).
const FETCH_LIMIT: u64 = 4 * 1024 * 1024;

static MODE: AtomicU8 = AtomicU8::new(GATE_SUSPICIOUS);

/// Hosts cleared for this app run: sandbox-verified clean, user-allowed via
/// the nudge, or organically trusted (the tab was already on them).
static TRUSTED: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn refresh_mode(mode: Option<&str>) {
    let m = match mode {
        Some("off") => GATE_OFF,
        Some("all") => GATE_ALL,
        _ => GATE_SUSPICIOUS,
    };
    MODE.store(m, Ordering::Relaxed);
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .host_str()
        .map(|h| h.to_ascii_lowercase())
}

pub fn trust(host: &str) {
    if let Ok(mut t) = TRUSTED.lock() {
        t.insert(host.to_ascii_lowercase());
    }
}

fn is_trusted(host: &str) -> bool {
    TRUSTED
        .lock()
        .map(|t| t.contains(host))
        .unwrap_or(false)
}

/// Decide whether this main-frame navigation must be intercepted and
/// pre-opened in the sandbox. `current_url` is the frame's URL before the
/// navigation; `suspicious` is what the local Guard/community layers already
/// concluded about the target.
pub fn should_gate(url: &str, current_url: &str, suspicious: bool) -> bool {
    let mode = MODE.load(Ordering::Relaxed);
    if mode == GATE_OFF {
        return false;
    }
    if !url.starts_with("http") {
        return false;
    }
    let Some(host) = host_of(url) else { return false };
    if host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    {
        return false;
    }
    if is_trusted(&host) {
        return false;
    }
    // Staying on the same host is normal browsing, not a new link; trust it.
    if host_of(current_url).as_deref() == Some(host.as_str()) {
        trust(&host);
        return false;
    }
    // The pre-fetch must never expose the user's IP: gate only when a private
    // route (Tor, else the configured custom proxy) is available.
    if crate::tor::probe_proxy_url().is_none() {
        return false;
    }
    match mode {
        GATE_ALL => true,
        _ => suspicious,
    }
}

/// Fetch `url` through a private proxy (`proxy_url` is a full `socks5://…` or
/// `http://…`) and return the raw body text. Never falls back to a direct
/// fetch — no proxy, no request.
fn fetch_via_proxy(url: &str, proxy_url: &str) -> Result<String, String> {
    let mut cfg = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        // Blend in: the same fixed UA every Vev tab presents.
        .user_agent(vev_fingerprint::USER_AGENT);
    match ureq::Proxy::new(proxy_url) {
        Ok(p) => cfg = cfg.proxy(Some(p)),
        // No proxy object = no request. Never fall back to a direct fetch.
        Err(e) => return Err(format!("probe proxy: {e}")),
    }
    let agent = ureq::Agent::new_with_config(cfg.build());
    agent
        .get(url)
        .call()
        .map_err(|e| format!("fetch: {e}"))?
        .body_mut()
        .with_config()
        .limit(FETCH_LIMIT)
        .read_to_string()
        .map_err(|e| format!("read: {e}"))
}

/// Strip an HTML document to visible-ish text: drops script/style/head
/// blocks and tags, decodes the entities that matter for prose. Crude by
/// design — the classifier wants words, not fidelity.
fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 4);
    let mut rest = html;
    let mut skip_until: Option<&str> = None;
    while let Some(lt) = rest.find('<') {
        if skip_until.is_none() {
            out.push_str(&rest[..lt]);
        }
        rest = &rest[lt..];
        let Some(gt) = rest.find('>') else { break };
        let tag = rest[1..gt].trim_start_matches('/').to_ascii_lowercase();
        let tag_name: String = tag
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        match skip_until {
            Some(end) if rest[..gt + 1].to_ascii_lowercase().starts_with(end) => {
                skip_until = None;
            }
            None if matches!(tag_name.as_str(), "script" | "style" | "noscript")
                && !rest.starts_with("</") =>
            {
                skip_until = Some(match tag_name.as_str() {
                    "script" => "</script",
                    "style" => "</style",
                    _ => "</noscript",
                });
            }
            _ => {}
        }
        if skip_until.is_none() && matches!(tag_name.as_str(), "p" | "br" | "div" | "li" | "h1" | "h2" | "h3" | "td" | "tr") {
            out.push('\n');
        }
        rest = &rest[gt + 1..];
    }
    if skip_until.is_none() {
        out.push_str(rest);
    }
    out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
}

/// The document title, if the fetched HTML has one.
fn html_title(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let Some(start) = lower.find("<title") else { return String::new() };
    let Some(open_end) = lower[start..].find('>') else { return String::new() };
    let after = start + open_end + 1;
    let Some(end) = lower[after..].find("</title") else { return String::new() };
    html_to_text(&html[after..after + end]).trim().to_string()
}

/// Intercept `url` for `tab_id`: fetch it through Tor off the UI thread,
/// analyze, and act on the verdict. Called on the main thread from
/// `on_before_browse`; all slow work happens on a worker.
pub fn begin(app: &AppHandle, tab_id: u32, url: String) {
    // Scope the island events to the window owning the gated tab.
    let win = crate::tabs::with_manager(|m| m.window_of(tab_id));
    match &win {
        Some(w) => {
            let _ = app.emit_to(
                w.as_str(),
                "sandbox-checking",
                serde_json::json!({ "url": url, "tabId": tab_id }),
            );
        }
        None => {
            let _ = app.emit(
                "sandbox-checking",
                serde_json::json!({ "url": url, "tabId": tab_id }),
            );
        }
    }

    let app = app.clone();
    std::thread::spawn(move || {
        // Tor when ready, else the configured custom proxy (Mullvad, …).
        let proxy = crate::tor::probe_proxy_url();
        let page = match &proxy {
            Some(px) => {
                eprintln!("vev-sandbox: pre-fetching {url} via {px} (tab {tab_id})");
                fetch_via_proxy(&url, px)
            }
            // should_gate checked availability, but the route can drop between
            // the check and here; URL-only verdict, never a direct fetch.
            None => Err("no private route".into()),
        };
        let (title, text) = match &page {
            Ok(html) => (html_title(html), html_to_text(html)),
            Err(e) => {
                eprintln!("vev-sandbox: pre-fetch failed for {url}: {e}");
                (String::new(), String::new())
            }
        };

        let local = huma::guard::classify_adapted(&url);
        let content = huma::content::analyze(&url, &title, &text);

        let mut signals: Vec<huma::intel::Signal> = Vec::new();
        if !text.is_empty() {
            signals.push(if content.malicious {
                huma::intel::Signal::source_malicious(
                    "Huma sandbox fetch",
                    2.5,
                    content
                        .impersonated
                        .clone()
                        .map(|b| format!("fetched page impersonates {b}"))
                        .unwrap_or_else(|| "fetched page looks like phishing".into()),
                )
            } else {
                huma::intel::Signal::source_clean("Huma sandbox fetch", 1.2)
            });
        }

        // Online intel sources, routed through the same private proxy as the
        // fetch. Only sources with configured keys run; none is fine (local
        // voters still decide).
        let mut keys = crate::startpage::intel_keys();
        keys.proxy = proxy;
        signals.extend(huma::intel::scan_signals(&url, &keys));

        let report = huma::intel::aggregate(&url, local.score, signals);
        let mut reasons = local.reasons.clone();
        reasons.extend(content.reasons.clone());

        let _ = app.run_on_main_thread(move || {
            apply_verdict(tab_id, url, report, reasons, content.impersonated)
        });
    });
}

/// Act on the sandbox verdict. Main thread only.
fn apply_verdict(
    tab_id: u32,
    url: String,
    report: huma::intel::IntelReport,
    reasons: Vec<String>,
    impersonated: Option<String>,
) {
    let Some(app) = crate::cef_engine::app_handle() else { return };
    let clean = !report.malicious;
    eprintln!(
        "vev-sandbox: verdict for {url} (tab {tab_id}): {} {}%",
        if clean { "CLEAN" } else { "DANGEROUS" },
        report.percent
    );
    if clean {
        if let Some(host) = host_of(&url) {
            trust(&host);
        }
        proceed(tab_id, &url);
    }
    let payload = serde_json::json!({
        "url": url,
        "tabId": tab_id,
        "clean": clean,
        "percent": report.percent,
        "signals": report.signals,
        "reasons": reasons,
        "impersonated": impersonated,
        "tor": true,
    });
    match crate::tabs::with_manager(|m| m.window_of(tab_id)) {
        Some(w) => {
            let _ = app.emit_to(w.as_str(), "sandbox-verdict", payload);
        }
        None => {
            let _ = app.emit("sandbox-verdict", payload);
        }
    }
}

/// Navigate the real tab to the (now cleared) URL. Main thread only.
pub fn proceed(tab_id: u32, url: &str) {
    use cef::{ImplBrowser, ImplFrame};
    if let Some(browser) = crate::tabs::browser_for_tab(tab_id) {
        if let Some(frame) = browser.main_frame() {
            frame.load_url(Some(&cef::CefString::from(url)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_html_to_words() {
        let text = html_to_text(
            "<html><head><script>var x = 'evil()';</script><style>p{color:red}</style></head>\
             <body><h1>Sign in to PayPa1</h1><p>Enter your &quot;password&quot; &amp; SSN</p></body></html>",
        );
        assert!(text.contains("Sign in to PayPa1"));
        assert!(text.contains("Enter your \"password\" & SSN"));
        assert!(!text.contains("evil()"));
        assert!(!text.contains("color:red"));
    }

    #[test]
    fn extracts_title() {
        assert_eq!(
            html_title("<html><head><TITLE>Secure Login</TITLE></head></html>"),
            "Secure Login"
        );
        assert_eq!(html_title("<html><body>no title</body></html>"), "");
    }

    #[test]
    fn gate_mode_and_trust_cache() {
        // Only the pre-Tor early-outs are testable here (Tor readiness
        // decides the final yes, and there is no Tor in unit tests).
        refresh_mode(Some("off"));
        assert!(!should_gate("https://new-host.example/x", "", true));
        refresh_mode(Some("all"));
        assert!(!should_gate("vev://settings", "", true));
        assert!(!should_gate("https://localhost:3000/", "", true));
        trust("trusted.example");
        assert!(!should_gate("https://trusted.example/a", "", true));
        // Same-host navigation is never gated.
        assert!(!should_gate(
            "https://same.example/next",
            "https://same.example/",
            true
        ));
        refresh_mode(None); // back to default for other tests
    }
}
