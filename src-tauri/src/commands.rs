//! Tauri command layer: the shell UI's only way to drive tabs and bookmarks.
//! Tab commands hop to the main thread because CEF objects live there.

use crate::storage::Storage;
use crate::tabs::{self, Tab, TabInfo};
use crate::cef_engine;
use tauri::{AppHandle, Manager, State};
use vev_storage::{Bookmark, PasswordEntry};

/// True if this tauri window label is a private (incognito) window. Private
/// browsing only exists in private windows; every tab in one is private.
pub fn is_private_window(label: &str) -> bool {
    label.starts_with("priv-")
}

/// Create a tab on the main thread in the given window and return its id.
pub fn create_tab_on_main(app: &AppHandle, window: &str, url: String) -> Result<u32, String> {
    create_tab_inner(app, window, url, None, false)
}

pub fn create_tab_inner(
    app: &AppHandle,
    window_label: &str,
    url: String,
    proxy_socks: Option<String>,
    private: bool,
) -> Result<u32, String> {
    let window = app
        .get_webview_window(window_label)
        .ok_or("window not found")?;
    // Tabs inside a private window are always private, whatever the caller
    // asked for — normal browsing never runs in a private window.
    let private = private || is_private_window(window_label);
    let id = tabs::with_manager(|m| m.allocate_id());
    let is_tor = proxy_socks.is_some();
    let browser =
        cef_engine::create_browser_ctx(app, &window, &url, proxy_socks.as_deref(), private)?;
    let browser_id = {
        use cef::ImplBrowser;
        browser.identifier()
    };
    tabs::register_browser_window(browser_id, window_label);
    tabs::with_manager(|m| {
        m.insert(Tab {
            id,
            window: window_label.to_string(),
            browser_id,
            browser: Some(browser),
            internal: None,
            url: url.clone(),
            title: String::new(),
            loading: true,
            can_back: false,
            can_forward: false,
            crashed: false,
            is_tor,
            is_private: private,
            favicon: String::new(),
            zoom: 0.0,
        })
    });
    tabs::show_only(id);
    tabs::emit_tabs_changed(app, window_label);
    crate::session::save(app);
    Ok(id)
}

/// Create a shell-rendered internal (`vev://<page>`) tab. Main thread only.
pub fn create_internal_tab_on_main(
    app: &AppHandle,
    window_label: &str,
    page: &str,
) -> Result<u32, String> {
    let id = tabs::with_manager(|m| m.allocate_id());
    let title = internal_title(page);
    tabs::with_manager(|m| {
        m.insert(Tab {
            id,
            window: window_label.to_string(),
            browser_id: 0,
            browser: None,
            internal: Some(page.to_string()),
            url: format!("vev://{page}"),
            title,
            loading: false,
            can_back: false,
            can_forward: false,
            crashed: false,
            is_tor: false,
            is_private: is_private_window(window_label),
            favicon: String::new(),
            zoom: 0.0,
        })
    });
    tabs::show_only(id);
    tabs::emit_tabs_changed(app, window_label);
    Ok(id)
}

fn internal_title(page: &str) -> String {
    match page {
        "settings" => "Settings",
        "history" => "History",
        "bookmarks" => "Bookmarks",
        "downloads" => "Downloads",
        "passwords" => "Passwords",
        "extensions" => "Extensions",
        "private-home" => "Private Browsing",
        "player" => "Player",
        other => other,
    }
    .to_string()
}

/// Open (or focus, if already open in this window) an internal page tab.
#[tauri::command]
pub async fn tabs_create_internal(
    app: AppHandle,
    webview: tauri::WebviewWindow,
    page: String,
) -> Result<u32, String> {
    let app2 = app.clone();
    let win = webview.label().to_string();
    tabs::on_main_thread(&app, move || -> Result<u32, String> {
        if let Some(existing) = tabs::with_manager(|m| m.find_internal(&win, &page)) {
            tabs::show_only(existing);
            tabs::emit_tabs_changed(&app2, &win);
            return Ok(existing);
        }
        create_internal_tab_on_main(&app2, &win, &page)
    })?
}

/// "New private tab" always means a private WINDOW — private and normal
/// browsing never share a window.
#[tauri::command]
pub async fn tabs_create_private(app: AppHandle) -> Result<(), String> {
    crate::open_window(&app, true, None)
}

/// Open a new browser window with its own tabs.
#[tauri::command]
pub async fn window_new(app: AppHandle) -> Result<(), String> {
    crate::open_window(&app, false, None)
}

#[tauri::command]
pub async fn window_new_private(app: AppHandle) -> Result<(), String> {
    crate::open_window(&app, true, None)
}

/// Move keyboard focus to the shell chrome (address bar). Releases the CEF
/// view's focus and makes the shell webview first responder — without this,
/// clicking the omnibox over a focused page left keystrokes going to the page.
#[tauri::command]
pub async fn shell_focus(app: AppHandle, webview: tauri::WebviewWindow) -> Result<(), String> {
    let win = webview.label().to_string();
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || {
        let app = app2;
        use cef::{ImplBrowser, ImplBrowserHost};
        if let Some(host) = tabs::with_manager(|m| m.active_id(&win))
            .and_then(tabs::browser_for_tab)
            .and_then(|b| b.host())
        {
            host.set_focus(0);
        }
        if let Some(w) = app.get_webview_window(&win) {
            crate::platform::focus_shell(&w);
        }
    })
}

/// Current browser-wide proxy state: what this run is using vs. what's saved
/// for next launch, plus Tor's bootstrap status and any custom URL.
#[tauri::command]
pub fn proxy_status() -> serde_json::Value {
    let cfg = crate::startpage::load_config();
    // Desired mode: explicit proxy_mode, else legacy tor_all, else off.
    let desired = cfg
        .proxy_mode
        .clone()
        .unwrap_or_else(|| if cfg.tor_all.unwrap_or(false) { "tor".into() } else { "off".into() });
    serde_json::json!({
        "active_mode": cef_engine::active_proxy_mode(),
        "desired_mode": desired,
        "custom_url": cfg.custom_proxy_url.unwrap_or_default(),
        "tor_status": crate::tor::status_string(),
    })
}

/// Persist the browser-wide proxy choice. It applies on the next launch (the
/// engine refuses runtime proxy changes), so the UI pairs this with a
/// relaunch. `mode` is "off" | "tor" | "custom"; `url` is required (a full
/// socks5://host:port or http://host:port) when mode is "custom".
#[tauri::command]
pub fn proxy_set(mode: String, url: Option<String>) -> Result<(), String> {
    let mode = match mode.as_str() {
        "off" | "tor" | "custom" => mode,
        other => return Err(format!("unknown proxy mode: {other}")),
    };
    if mode == "custom" {
        let u = url.clone().unwrap_or_default();
        let u = u.trim();
        if !(u.starts_with("socks5://") || u.starts_with("socks://") || u.starts_with("http://") || u.starts_with("https://")) {
            return Err("custom proxy must be socks5://host:port or http://host:port".into());
        }
    }
    let dir = std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join("Library/Application Support/com.vev.browser"))
        .ok_or("no home dir")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("config.json");
    let mut val: serde_json::Value = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let obj = val.as_object_mut().ok_or("config not an object")?;
    obj.insert("proxy_mode".into(), serde_json::json!(mode));
    if let Some(u) = url {
        obj.insert("custom_proxy_url".into(), serde_json::json!(u));
    }
    // Drop the legacy flag so it can't contradict the explicit mode.
    obj.remove("tor_all");
    std::fs::write(&path, serde_json::to_vec_pretty(&val).unwrap()).map_err(|e| e.to_string())?;
    Ok(())
}

/// Relaunch Vev so a changed proxy choice takes effect.
#[tauri::command]
pub fn proxy_relaunch(app: AppHandle) {
    app.restart();
}

#[tauri::command]
pub fn history_list(store: State<'_, Storage>, limit: Option<usize>) -> Vec<vev_storage::HistoryEntry> {
    store.history(limit.unwrap_or(200))
}

#[tauri::command]
pub fn search_engines() -> Vec<(String, String)> {
    crate::startpage::SEARCH_ENGINES
        .iter()
        .map(|(n, u)| (n.to_string(), u.to_string()))
        .collect()
}

#[tauri::command]
pub fn config_get() -> serde_json::Value {
    let cfg = crate::startpage::load_config();
    serde_json::json!({
        "search_engine": cfg.search_engine,
        "home_url": cfg.home_url,
        "huma_guard": cfg.huma_guard.unwrap_or(true),
        "community_feed_url": cfg.community_feed_url,
        "community_reporting": cfg.community_reporting.unwrap_or(false),
        "report_endpoint": cfg.report_endpoint,
        // Browser-wide proxy: this run's mode vs. what's saved for next launch.
        "proxy_active_mode": cef_engine::active_proxy_mode(),
        "proxy_mode": cfg.proxy_mode
            .unwrap_or_else(|| if cfg.tor_all.unwrap_or(false) { "tor".into() } else { "off".into() }),
    })
}

#[tauri::command]
pub fn config_set(
    search_engine: Option<String>,
    home_url: Option<String>,
    huma_guard: Option<bool>,
    community_reporting: Option<bool>,
) -> Result<(), String> {
    let dir = std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join("Library/Application Support/com.vev.browser"))
        .ok_or("no home dir")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Merge into the existing config so advanced fields (feed URL, report
    // endpoint) aren't wiped by a settings-page save.
    let path = dir.join("config.json");
    let mut val: serde_json::Value = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let obj = val.as_object_mut().ok_or("config not an object")?;
    obj.insert("search_engine".into(), serde_json::json!(search_engine));
    obj.insert("home_url".into(), serde_json::json!(home_url));
    if let Some(g) = huma_guard {
        obj.insert("huma_guard".into(), serde_json::json!(g));
    }
    if let Some(r) = community_reporting {
        obj.insert("community_reporting".into(), serde_json::json!(r));
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&val).unwrap())
        .map_err(|e| e.to_string())?;
    crate::startpage::refresh_runtime_flags();
    Ok(())
}

#[tauri::command]
pub async fn tabs_create_tor(
    app: AppHandle,
    webview: tauri::WebviewWindow,
    url: Option<String>,
) -> Result<u32, String> {
    // Each Tor tab gets its own isolated circuit set.
    let socks = crate::tor::isolated_proxy_addr()?;
    let url = url
        .map(|u| tabs::resolve_input(&u))
        .unwrap_or_else(|| "https://check.torproject.org/".into());
    let app2 = app.clone();
    let win = webview.label().to_string();
    tabs::on_main_thread(&app, move || {
        create_tab_inner(&app2, &win, url, Some(socks), false)
    })?
}

#[tauri::command]
pub fn tor_status() -> String {
    crate::tor::status_string()
}

#[tauri::command]
pub async fn tabs_create(
    app: AppHandle,
    webview: tauri::WebviewWindow,
    url: Option<String>,
) -> Result<u32, String> {
    let win = webview.label().to_string();
    // A new tab with no URL opens the Vev start page (home), like other
    // browsers — not about:blank. In a private window the "home" is the
    // shell-rendered incognito page (privacy toggles + search).
    let url = match url {
        Some(u) if !u.trim().is_empty() => tabs::resolve_input(&u),
        _ if is_private_window(&win) => {
            let app2 = app.clone();
            return tabs::on_main_thread(&app, move || {
                create_internal_tab_on_main(&app2, &win, "private-home")
            })?;
        }
        _ => crate::startpage::url(),
    };
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || create_tab_on_main(&app2, &win, url))?
}

#[tauri::command]
pub async fn tabs_close(app: AppHandle, id: u32) -> Result<(), String> {
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || {
        let win = tabs::with_manager(|m| m.window_of(id));
        let removed = tabs::with_manager(|m| m.remove(id));
        if let Some(tab) = removed {
            use cef::{ImplBrowser, ImplBrowserHost};
            if let Some(host) = tab.browser.and_then(|b| b.host()) {
                host.close_browser(1);
            }
        }
        if let Some(win) = win {
            if let Some(next) = tabs::with_manager(|m| m.active_id(&win)) {
                tabs::show_only(next);
            }
            tabs::emit_tabs_changed(&app2, &win);
        }
        crate::session::save(&app2);
    })
}

#[tauri::command]
pub async fn tabs_activate(app: AppHandle, id: u32) -> Result<(), String> {
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || {
        tabs::show_only(id);
        if let Some(win) = tabs::with_manager(|m| m.window_of(id)) {
            tabs::emit_tabs_changed(&app2, &win);
        }
        crate::session::save(&app2);
    })
}

#[tauri::command]
pub async fn tabs_list(app: AppHandle, webview: tauri::WebviewWindow) -> Result<Vec<TabInfo>, String> {
    let win = webview.label().to_string();
    tabs::on_main_thread(&app, move || tabs::with_manager(|m| m.infos(&win)))
}

/// Hide/show the web content view so shell overlays can cover the window.
#[tauri::command]
pub async fn content_hidden(
    app: AppHandle,
    webview: tauri::WebviewWindow,
    hidden: bool,
) -> Result<(), String> {
    let win = webview.label().to_string();
    tabs::on_main_thread(&app, move || tabs::set_content_hidden(&win, hidden))
}

#[tauri::command]
pub async fn tabs_restore(app: AppHandle, webview: tauri::WebviewWindow) -> Result<Option<u32>, String> {
    let app2 = app.clone();
    let win = webview.label().to_string();
    tabs::on_main_thread(&app, move || -> Result<Option<u32>, String> {
        let Some(url) = tabs::with_manager(|m| m.pop_closed_url()) else {
            return Ok(None);
        };
        create_tab_on_main(&app2, &win, url).map(Some)
    })?
}

#[tauri::command]
pub async fn nav_navigate(app: AppHandle, id: u32, input: String) -> Result<(), String> {
    let url = tabs::resolve_input(&input);
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || -> Result<(), String> {
        // An internal tab navigating to a real URL gets its CEF browser
        // created in place (private iff its window is private).
        let needs_browser = tabs::with_manager(|m| {
            m.get_mut(id).map(|t| t.browser.is_none()).unwrap_or(false)
        });
        if needs_browser {
            let Some(win_label) = tabs::with_manager(|m| m.window_of(id)) else {
                return Err("tab not found".into());
            };
            let window = app2
                .get_webview_window(&win_label)
                .ok_or("window not found")?;
            let private = is_private_window(&win_label);
            let browser =
                cef_engine::create_browser_ctx(&app2, &window, &url, None, private)?;
            let browser_id = {
                use cef::ImplBrowser;
                browser.identifier()
            };
            tabs::register_browser_window(browser_id, &win_label);
            tabs::with_manager(|m| {
                if let Some(t) = m.get_mut(id) {
                    t.browser = Some(browser);
                    t.browser_id = browser_id;
                    t.internal = None;
                    t.url = url.clone();
                    t.loading = true;
                    t.is_private = private;
                }
            });
            tabs::show_only(id);
            tabs::emit_tabs_changed(&app2, &win_label);
            return Ok(());
        }
        tabs::navigate(id, &url);
        if let Some(win) = tabs::with_manager(|m| m.window_of(id)) {
            tabs::emit_tabs_changed(&app2, &win);
        }
        Ok(())
    })?
}

#[tauri::command]
pub async fn nav_back(app: AppHandle, id: u32) -> Result<(), String> {
    tabs::on_main_thread(&app, move || {
        use cef::ImplBrowser;
        if let Some(browser) = tabs::browser_for_tab(id) {
            browser.go_back();
        }
    })
}

#[tauri::command]
pub async fn nav_forward(app: AppHandle, id: u32) -> Result<(), String> {
    tabs::on_main_thread(&app, move || {
        use cef::ImplBrowser;
        if let Some(browser) = tabs::browser_for_tab(id) {
            browser.go_forward();
        }
    })
}

#[tauri::command]
pub async fn nav_reload(app: AppHandle, id: u32) -> Result<(), String> {
    tabs::on_main_thread(&app, move || {
        use cef::ImplBrowser;
        tabs::with_manager(|m| {
            if let Some(tab) = m.get_mut(id) {
                tab.crashed = false;
            }
        });
        if let Some(browser) = tabs::browser_for_tab(id) {
            browser.reload();
        }
    })
}

#[tauri::command]
pub fn blocklist_add_block(host: String) -> Result<(), String> {
    match crate::blocking::get() {
        Some(bl) => bl.add_user_block(host),
        None => Err("blocklist not initialized".into()),
    }
}

#[tauri::command]
pub fn blocklist_add_allow(host: String) -> Result<(), String> {
    match crate::blocking::get() {
        Some(bl) => bl.add_user_allow(host),
        None => Err("blocklist not initialized".into()),
    }
}

#[tauri::command]
pub fn bookmarks_list(store: State<'_, Storage>) -> Result<Vec<Bookmark>, String> {
    store.bookmarks()
}

#[tauri::command]
pub fn bookmarks_add(
    store: State<'_, Storage>,
    url: String,
    title: String,
) -> Result<Vec<Bookmark>, String> {
    store.add_bookmark(url, title)
}

#[tauri::command]
pub fn bookmarks_remove(
    store: State<'_, Storage>,
    url: String,
) -> Result<Vec<Bookmark>, String> {
    store.remove_bookmark(&url)
}

#[tauri::command]
pub async fn downloads_list(app: AppHandle) -> Result<Vec<crate::downloads::DownloadInfo>, String> {
    tabs::on_main_thread(&app, crate::downloads::list)
}

#[tauri::command]
pub async fn download_control(app: AppHandle, id: u32, action: String) -> Result<(), String> {
    tabs::on_main_thread(&app, move || crate::downloads::control(id, &action))
}

/// Direct segmented download of an explicit URL. Because this is an HTTP
/// fetch, not a page navigation, it never touches the phishing/threat
/// navigation gate — downloading a file the user explicitly chose is their
/// intent, so a flagged host must not block it. `dest_dir` overrides
/// ~/Downloads (set by the confirmation popup).
#[tauri::command]
pub fn download_fast(app: AppHandle, url: String, dest_dir: Option<String>) -> u32 {
    crate::downloads::start_fast(&app, url, dest_dir)
}

// --- Media downloader (yt-dlp / ffmpeg) ---

/// yt-dlp/ffmpeg availability, for the popup to offer the one-time fetch.
#[tauri::command]
pub fn media_tools_status(app: AppHandle) -> vev_media::ToolStatus {
    crate::media::status(&app)
}

/// One-time managed fetch of yt-dlp into app-data.
#[tauri::command]
pub async fn media_fetch_tools(app: AppHandle) -> Result<vev_media::ToolStatus, String> {
    tauri::async_runtime::spawn_blocking(move || crate::media::fetch_tools(&app))
        .await
        .map_err(|e| e.to_string())?
}

/// Probe a page for downloadable media + formats (yt-dlp -J). Off the async
/// worker (spawns a process).
#[tauri::command]
pub async fn media_probe(app: AppHandle, url: String) -> Result<vev_media::MediaInfo, String> {
    tauri::async_runtime::spawn_blocking(move || crate::media::probe(&app, &url))
        .await
        .map_err(|e| e.to_string())?
}

/// Start a media download; it shows in the IDM Downloads list. Returns the id.
#[tauri::command]
pub fn media_download(
    app: AppHandle,
    url: String,
    format_id: String,
    audio_mp3: bool,
    dest_dir: Option<String>,
) -> u32 {
    crate::media::download(&app, url, format_id, audio_mp3, dest_dir)
}

/// Resolve a directly-playable media URL for "Play online".
#[tauri::command]
pub async fn media_resolve_stream(app: AppHandle, url: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || crate::media::resolve_stream(&app, &url))
        .await
        .map_err(|e| e.to_string())?
}

/// Reveal a downloaded file in the OS file manager (Finder / Explorer / the
/// default handler). Used by the "Show in folder" action on completed
/// downloads.
#[tauri::command]
pub fn reveal_in_folder(path: String) -> Result<(), String> {
    let p = std::path::Path::new(&path);
    #[cfg(target_os = "macos")]
    {
        // -R reveals and selects the file in Finder.
        std::process::Command::new("open")
            .arg("-R")
            .arg(&path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(format!("/select,{path}"))
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        // No universal "reveal + select"; open the containing directory.
        let dir = p.parent().unwrap_or(p);
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    let _ = p;
    Ok(())
}

#[tauri::command]
pub async fn torrent_add(magnet: String) -> Result<usize, String> {
    // add() blocks on the torrent runtime; run it off the tauri async worker.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(vev_torrent::add(magnet));
    });
    rx.recv().map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn torrent_list() -> Result<Vec<vev_torrent::TorrentInfo>, String> {
    vev_torrent::list()
}

/// Pause / resume / remove a torrent. `action` is "pause" | "resume" |
/// "remove" (keep files) | "remove_files" (delete them too).
#[tauri::command]
pub async fn torrent_control(id: usize, action: String) -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(vev_torrent::control(id, action));
    });
    rx.recv().map_err(|e| e.to_string())?
}

/// Remove a finished/failed download from the IDM list (does not delete the
/// file — for a completed download the file stays; use Show in folder to open
/// it). Clears stuck or old entries the user wants gone.
#[tauri::command]
pub async fn download_remove(app: AppHandle, id: u32) -> Result<(), String> {
    tabs::on_main_thread(&app, move || crate::downloads::remove_entry(id))
}

// --- Huma on-device AI ---

#[tauri::command]
pub fn huma_classify(url: String) -> huma::guard::Verdict {
    huma::guard::classify_adapted(&url)
}

/// Record a Guard outcome for the on-device self-adapting layer (SEAL-style).
/// `malicious=false` is the "Allow anyway" override → treat the URL's
/// structure as a false positive and lower its future score.
#[tauri::command]
pub fn huma_guard_feedback(url: String, malicious: bool) -> u64 {
    huma::adapt::record_url(&url, malicious);
    huma::adapt::update_count()
}

/// Deep scan a URL against the configured online threat-intelligence sources
/// (Google Safe Browsing, VirusTotal, URLhaus, ThreatFox, OTX) plus the local
/// model, returning a combined danger percentage and per-source signals. This
/// is opt-in / on-demand — it sends the URL off-device, so it never runs
/// automatically. Runs off the async worker (each source is a blocking call).
#[tauri::command]
pub async fn huma_deep_scan(url: String) -> Result<serde_json::Value, String> {
    let mut keys = crate::startpage::intel_keys();
    // Route the scan through a private proxy — Tor when ready, else the
    // configured custom proxy (Mullvad, …) — so the reputation services see
    // the proxy's exit IP, never the user's real address.
    keys.proxy = crate::tor::probe_proxy_url();
    let local = huma::guard::classify_adapted(&url).score;
    let report = tauri::async_runtime::spawn_blocking(move || huma::intel::scan(&url, &keys, local))
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(report).map_err(|e| e.to_string())
}

/// "Open anyway" from the sandbox-gate nudge: trust the host for this session
/// and navigate the tab to the URL the gate held back.
#[tauri::command]
pub async fn sandbox_proceed(app: AppHandle, id: u32, url: String) -> Result<(), String> {
    if let Some(host) = url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        crate::sandbox::trust(&host);
    }
    // Overriding the sandbox verdict is a false-positive signal for the
    // on-device Guard, like "Allow anyway" on the warning card.
    huma::adapt::record_url(&url, false);
    tabs::on_main_thread(&app, move || crate::sandbox::proceed(id, &url))
}

/// Community-confirmed phishing status for a URL (for the address-bar/island
/// display), or null if the host isn't on the crowd feed.
#[tauri::command]
pub fn community_flag(url: String) -> Option<serde_json::Value> {
    crate::blocking::community_flag(&url)
        .map(|f| serde_json::json!({ "percent": f.percent, "reports": f.reports }))
}

/// Report a page as phishing to the community feed. Always reinforces the
/// local self-adapting Guard. Only submits to the network when the user has
/// opted in (config.community_reporting); the submission is the plaintext
/// host + the AI score, never the full URL or any browsing history.
#[tauri::command]
pub fn report_phishing(url: String) -> Result<String, String> {
    huma::adapt::record_url(&url, true);
    let cfg = crate::startpage::load_config();
    if !cfg.community_reporting.unwrap_or(false) {
        return Ok("recorded locally (community reporting is off)".into());
    }
    let host = url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or("no host in URL")?;
    let score = huma::guard::classify_adapted(&url).score;
    // Default to the live Vev report API; overridable via config.
    let endpoint = cfg
        .report_endpoint
        .filter(|e| e.starts_with("https://"))
        .unwrap_or_else(|| "https://vev-browser.vercel.app/api/report".to_string());
    // Off the async worker: a blocking POST of {host, ai_score}.
    std::thread::spawn(move || {
        let payload = serde_json::json!({ "host": host, "ai_score": score });
        let _ = ureq::post(&endpoint)
            .header("content-type", "application/json")
            .send(payload.to_string());
    });
    Ok("reported to the community feed".into())
}

/// Summarize extracted page text (extractive, on-device). `text` is the
/// reader-extracted body the shell pulls from the active page.
#[tauri::command]
pub fn huma_summarize(text: String, max_sentences: Option<usize>) -> String {
    let cleaned = huma::read::clean_extracted(&text);
    let source = if cleaned.split_whitespace().count() > 30 { cleaned } else { text };
    huma::read::summarize(&source, max_sentences.unwrap_or(5))
}

/// Extract + summarize the active tab entirely in the backend (via CEF's
/// frame text), emitting `huma-read-result`. Robust — no shell→DevTools hop.
#[tauri::command]
pub async fn huma_read_active(app: AppHandle, webview: tauri::WebviewWindow) -> Result<(), String> {
    let win = webview.label().to_string();
    tabs::on_main_thread(&app, move || cef_engine::huma_read_active(&win))
}

#[tauri::command]
pub fn passwords_for(
    store: State<'_, Storage>,
    origin: String,
) -> Result<Vec<PasswordEntry>, String> {
    store.passwords_for(&origin)
}

#[tauri::command]
pub fn passwords_save(
    store: State<'_, Storage>,
    origin: String,
    username: String,
    password: String,
) -> Result<(), String> {
    store.save_password(origin, username, password)
}

#[tauri::command]
pub fn passwords_all(store: State<'_, Storage>) -> Result<Vec<PasswordEntry>, String> {
    store.passwords_all()
}

#[tauri::command]
pub fn passwords_delete(
    store: State<'_, Storage>,
    origin: String,
    username: String,
) -> Result<(), String> {
    store.passwords_delete(&origin, &username)
}

#[tauri::command]
pub fn history_clear(store: State<'_, Storage>) -> Result<(), String> {
    store.history_clear()
}

#[tauri::command]
pub fn history_delete(store: State<'_, Storage>, url: String) -> Result<(), String> {
    store.history_delete(&url)
}

// --- Browser basics ---

#[tauri::command]
pub async fn tabs_move(app: AppHandle, id: u32, index: usize) -> Result<(), String> {
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || {
        tabs::with_manager(|m| m.move_tab(id, index));
        if let Some(win) = tabs::with_manager(|m| m.window_of(id)) {
            tabs::emit_tabs_changed(&app2, &win);
        }
        crate::session::save(&app2);
    })
}

#[tauri::command]
pub async fn find_start(
    app: AppHandle,
    id: u32,
    text: String,
    forward: bool,
    match_case: bool,
    find_next: bool,
) -> Result<(), String> {
    tabs::on_main_thread(&app, move || {
        use cef::{ImplBrowser, ImplBrowserHost};
        if let Some(host) = tabs::browser_for_tab(id).and_then(|b| b.host()) {
            host.find(
                Some(&cef::CefString::from(text.as_str())),
                forward as _,
                match_case as _,
                find_next as _,
            );
        }
    })
}

#[tauri::command]
pub async fn find_stop(app: AppHandle, id: u32) -> Result<(), String> {
    tabs::on_main_thread(&app, move || {
        use cef::{ImplBrowser, ImplBrowserHost};
        if let Some(host) = tabs::browser_for_tab(id).and_then(|b| b.host()) {
            host.stop_finding(1);
        }
    })
}

/// Zoom a tab: action is "in", "out", or "reset". Returns the new level.
/// Chromium zoom: percent ≈ 1.2^level, so ±1 steps are 120%/83%.
#[tauri::command]
pub async fn zoom_set(app: AppHandle, id: u32, action: String) -> Result<f64, String> {
    let app2 = app.clone();
    tabs::on_main_thread(&app, move || -> f64 {
        use cef::{ImplBrowser, ImplBrowserHost};
        let level = tabs::with_manager(|m| {
            let Some(tab) = m.get_mut(id) else { return 0.0 };
            tab.zoom = match action.as_str() {
                "in" => (tab.zoom + 1.0).min(8.0),
                "out" => (tab.zoom - 1.0).max(-6.0),
                _ => 0.0,
            };
            tab.zoom
        });
        if let Some(host) = tabs::browser_for_tab(id).and_then(|b| b.host()) {
            host.set_zoom_level(level);
        }
        if let Some(win) = tabs::with_manager(|m| m.window_of(id)) {
            tabs::emit_tabs_changed(&app2, &win);
        }
        level
    })
}

/// Search suggestions from DuckDuckGo's autocomplete endpoint (best-effort;
/// returns [] on any failure so typing never blocks on the network).
#[tauri::command]
pub async fn search_suggest(q: String) -> Vec<String> {
    if q.trim().is_empty() || q.len() > 200 {
        return Vec::new();
    }
    let url = format!(
        "https://duckduckgo.com/ac/?type=list&q={}",
        url::form_urlencoded::byte_serialize(q.as_bytes()).collect::<String>()
    );
    tauri::async_runtime::spawn_blocking(move || {
        let text = ureq::get(&url)
            .call()
            .ok()?
            .body_mut()
            .read_to_string()
            .ok()?;
        let body: serde_json::Value = serde_json::from_str(&text).ok()?;
        // Response shape: ["query", ["s1","s2",...]]
        let list = body.get(1)?.as_array()?;
        Some(
            list.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .take(8)
                .collect::<Vec<_>>(),
        )
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default()
}

// --- Incognito session settings ---

#[tauri::command]
pub fn incognito_settings_get() -> crate::incognito::IncognitoSettings {
    crate::incognito::get()
}

#[tauri::command]
pub fn incognito_settings_set(
    settings: crate::incognito::IncognitoSettings,
) -> crate::incognito::IncognitoSettings {
    crate::incognito::set(settings);
    crate::incognito::get()
}

// --- Extensions ---

#[tauri::command]
pub fn extensions_list() -> Vec<crate::extensions::ExtensionInfo> {
    crate::extensions::list()
}

#[tauri::command]
pub fn extensions_toggle(id: String, enabled: bool) -> Result<(), String> {
    crate::extensions::set_enabled(&id, enabled)
}

#[tauri::command]
pub fn extensions_install(path: String) -> Result<String, String> {
    crate::extensions::install(&path)
}

#[tauri::command]
pub fn extensions_uninstall(id: String) -> Result<(), String> {
    crate::extensions::uninstall(&id)
}

#[tauri::command]
pub fn extensions_reload() {
    crate::extensions::reload()
}

/// Engine/app versions for the About section. The engine string matches the
/// pinned CEF distribution recorded in README "Engine version".
#[tauri::command]
pub fn cef_version() -> serde_json::Value {
    serde_json::json!({
        "vev": env!("CARGO_PKG_VERSION"),
        "cef": "149.0.6",
        "chromium": "149.0.7827.201",
        "huma_model": if huma::model::available() { "ONNX (tract)" } else { "linear fallback" },
    })
}
