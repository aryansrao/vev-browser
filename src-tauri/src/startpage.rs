//! Vev start / home page. A self-contained page shown for new tabs: the Vev
//! wallpaper + a search box wired to the configured search engine. Users can
//! override it with their own URL or a local HTML file (config.json).

use std::sync::OnceLock;

/// Bundled default wallpaper.
const WALLPAPER: &[u8] = include_bytes!("../../vev-default.png");

/// Search engines Vev offers; first is the default. `{q}` is the query slot.
pub const SEARCH_ENGINES: &[(&str, &str)] = &[
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("Brave", "https://search.brave.com/search?q={q}"),
    ("Startpage", "https://www.startpage.com/sp/search?query={q}"),
    ("Google", "https://www.google.com/search?q={q}"),
];

#[derive(serde::Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Search engine name (must match SEARCH_ENGINES) or a custom `{q}` URL.
    pub search_engine: Option<String>,
    /// Custom home page: an http(s) URL or a local file path.
    pub home_url: Option<String>,
    /// Huma Guard phishing classifier on navigations (default on).
    pub huma_guard: Option<bool>,
    /// Pre-open isolation sandbox gate: "off", "suspicious" (default — gate
    /// URLs the Guard or community feed flags), or "all" (gate every first
    /// visit to an unknown host).
    pub sandbox_gate: Option<String>,
    /// Legacy browser-wide-Tor flag (superseded by `proxy_mode`; still read
    /// so existing configs keep working — maps to proxy_mode "tor").
    pub tor_all: Option<bool>,
    /// Browser-wide proxy mode: "off", "tor", or "custom". Applied at launch
    /// (Chromium proxy switch — the engine refuses runtime changes), so the
    /// private-home picker writes this and relaunches.
    pub proxy_mode: Option<String>,
    /// Proxy server URL used when `proxy_mode` is "custom": a full
    /// `socks5://host:port` or `http://host:port` (e.g. a Mullvad SOCKS5
    /// endpoint). DNS resolves through the proxy for socks5://.
    pub custom_proxy_url: Option<String>,
    /// Override the community phishing feed URL (default the Vev public repo).
    pub community_feed_url: Option<String>,
    /// Opt-in: submit manually-reported phishing hosts to the community feed
    /// (default off — nothing is ever sent without this).
    pub community_reporting: Option<bool>,
    /// Endpoint that ingests reports (a serverless fn / GitHub-backed API).
    pub report_endpoint: Option<String>,
    // --- Deep-scan API keys (opt-in online verification). Stored only in the
    // local config, never in the repo. ---
    pub safe_browsing_key: Option<String>,
    pub virustotal_key: Option<String>,
    pub abusech_key: Option<String>,
    pub otx_key: Option<String>,
}

/// The deep-scan keys from the local config, for `huma::intel`.
pub fn intel_keys() -> huma::intel::IntelKeys {
    let c = load_config();
    huma::intel::IntelKeys {
        safe_browsing: c.safe_browsing_key,
        virustotal: c.virustotal_key,
        abusech: c.abusech_key,
        otx: c.otx_key,
        proxy: None, // set by the command from the live Tor status
    }
}

/// Runtime cache of the Huma Guard toggle so `on_before_browse` doesn't hit
/// the filesystem on every navigation. Initialized at startup, updated by
/// `config_set`.
static HUMA_GUARD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

pub fn huma_guard_enabled() -> bool {
    HUMA_GUARD.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn refresh_runtime_flags() {
    let cfg = load_config();
    HUMA_GUARD.store(
        cfg.huma_guard.unwrap_or(true),
        std::sync::atomic::Ordering::Relaxed,
    );
    crate::sandbox::refresh_mode(cfg.sandbox_gate.as_deref());
}

fn config_path() -> Option<std::path::PathBuf> {
    dirs_data().map(|d| d.join("config.json"))
}

fn dirs_data() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| {
        std::path::PathBuf::from(h)
            .join("Library/Application Support/com.vev.browser")
    })
}

pub fn load_config() -> Config {
    config_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// The search-URL template (`{q}` slot) from config, defaulting to the first
/// engine.
pub fn search_template() -> String {
    let cfg = load_config();
    match cfg.search_engine {
        Some(s) if s.contains("{q}") => s,
        Some(name) => SEARCH_ENGINES
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&name))
            .map(|(_, u)| u.to_string())
            .unwrap_or_else(|| SEARCH_ENGINES[0].1.to_string()),
        None => SEARCH_ENGINES[0].1.to_string(),
    }
}

static START_FILE_URL: OnceLock<String> = OnceLock::new();

const TEMPLATE: &str = "<!doctype html><html><head><meta charset=utf-8>\
<title>New Tab</title><style>\
*{margin:0;box-sizing:border-box}\
html,body{height:100%;font-family:-apple-system,'SF Pro Display',system-ui,sans-serif;font-weight:300}\
body{background:#000 url('wallpaper.png') center/cover no-repeat;\
display:flex;align-items:center;justify-content:center;flex-direction:column}\
.scrim{position:fixed;inset:0;background:radial-gradient(ellipse at center,rgba(0,0,0,.15),rgba(0,0,0,.65))}\
form{position:relative;z-index:1;display:flex;align-items:center;gap:12px;\
background:rgba(20,20,24,.55);backdrop-filter:blur(30px) saturate(160%);\
border:1px solid rgba(255,255,255,.12);border-radius:28px;padding:12px 22px;\
width:min(620px,86vw);box-shadow:0 30px 80px rgba(0,0,0,.5)}\
input{flex:1;border:0;background:transparent;color:#f2f2f5;font:300 19px inherit;outline:none}\
input::placeholder{color:#8a8a92}\
svg{width:22px;height:22px;color:#8a8a92}\
</style></head><body><div class=scrim></div>\
<form id=f><svg viewBox='0 0 24 24' fill=none stroke=currentColor stroke-width=1.5 stroke-linecap=round>\
<path d='M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3'/></svg>\
<input id=q autofocus placeholder='Search the web privately'></form>\
<script>var TMPL='__TMPL__';\
document.getElementById('f').addEventListener('submit',function(e){e.preventDefault();\
var v=document.getElementById('q').value.trim();if(!v)return;\
var url=/^https?:\\/\\//.test(v)?v:(v.indexOf(' ')<0&&v.indexOf('.')>0?'https://'+v:\
TMPL.replace('QQQ',encodeURIComponent(v)));location.href=url;});</script>\
</body></html>";

/// The URL a new tab / home should load. Honors a configured custom home,
/// else a small `file://` start page (wallpaper.png sits next to it — a
/// data: URL with the wallpaper inline was ~1MB and crashed the renderer).
pub fn url() -> String {
    let cfg = load_config();
    if let Some(home) = cfg.home_url.filter(|h| !h.is_empty()) {
        if home.starts_with("http") {
            return home;
        }
        if std::path::Path::new(&home).exists() {
            return format!("file://{home}");
        }
    }
    START_FILE_URL
        .get_or_init(|| {
            let dir = match dirs_data() {
                Some(d) => d.join("startpage"),
                None => return "about:blank".into(),
            };
            if std::fs::create_dir_all(&dir).is_err() {
                return "about:blank".into();
            }
            let _ = std::fs::write(dir.join("wallpaper.png"), WALLPAPER);
            let tmpl = search_template().replace('\'', "\\'").replace("{q}", "QQQ");
            let html = TEMPLATE.replace("__TMPL__", &tmpl);
            let index = dir.join("index.html");
            if std::fs::write(&index, html).is_err() {
                return "about:blank".into();
            }
            format!("file://{}", index.to_string_lossy())
        })
        .clone()
}
