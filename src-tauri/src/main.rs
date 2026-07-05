//! Vev browser shell: Tauri 2 window hosting CEF-rendered browser tabs.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autotest;
mod blocking;
mod cef_engine;
mod commands;
mod context_menu;
mod downloads;
mod extensions;
mod huma_layer;
mod incognito;
mod media;
mod platform;
mod sandbox;
mod session;
mod startpage;
#[cfg(target_os = "macos")]
mod macos_app;
mod storage;
mod tabs;
mod tor;

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

/// Start page for the first tab.
const START_URL: &str = "https://example.com";

/// Open a new browser window (its own tabs + CEF views) and give it a start
/// tab once its native window exists. Private windows are the ONLY place
/// private tabs live: they get the incognito shell theme (`?private=1`) and
/// every tab created in them is private. `initial_url` overrides the default
/// start tab (used by "Open link in new private tab").
pub fn open_window(
    app: &tauri::AppHandle,
    private: bool,
    initial_url: Option<String>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let label = if private {
        format!("priv-{n}")
    } else {
        format!("win-{n}")
    };
    let page = if private {
        "index.html?private=1"
    } else {
        "index.html"
    };

    let builder = WebviewWindowBuilder::new(app, &label, WebviewUrl::App(page.into()))
        .title(if private { "Vev — Private" } else { "Vev" })
        .inner_size(1280.0, 820.0);
    // Overlay title bar (chrome under the traffic lights) is a macOS feature;
    // other platforms use a normal decorated window.
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true);
    builder.build().map_err(|e| format!("create window: {e}"))?;

    // Give the window a moment to attach its NSView, then open a start tab.
    // A private window starts on the shell-rendered incognito home page
    // (privacy toggles + search); a normal window starts on the start page.
    let app = app.clone();
    let label2 = label.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let a = app.clone();
        let l = label2.clone();
        let _ = tabs::on_main_thread(&app, move || {
            match initial_url {
                Some(url) => {
                    let _ = commands::create_tab_on_main(&a, &l, url);
                }
                None if private => {
                    let _ = commands::create_internal_tab_on_main(&a, &l, "private-home");
                }
                None => {
                    let _ = commands::create_tab_on_main(&a, &l, startpage::url());
                }
            }
        });
    });
    Ok(())
}

fn main() {
    // Load the CEF framework. On macOS this resolves
    // "../Frameworks/Chromium Embedded Framework.framework" relative to the
    // executable, so the browser must run from the assembled .app bundle.
    #[cfg(target_os = "macos")]
    let _library = {
        let loader = cef::library_loader::LibraryLoader::new(
            &std::env::current_exe().unwrap_or_default(),
            false,
        );
        if !loader.load() {
            eprintln!("vev: failed to load the CEF framework; run Vev from the bundled .app");
            std::process::exit(1);
        }
        loader
    };

    // Fingerprint resistance: force the process timezone to UTC before CEF
    // starts so the C library and V8 both report it. (JS-level overrides in
    // the spoof script cover Intl/Date; this covers the lower layers.)
    std::env::set_var("TZ", vev_fingerprint::TIMEZONE);

    cef_engine::init_api_hash();

    // NSApp must be our CefAppProtocol-conformant subclass before tauri/tao
    // initializes the shared NSApplication.
    #[cfg(target_os = "macos")]
    if let Err(e) = macos_app::install() {
        eprintln!("vev: {e}");
        std::process::exit(1);
    }

    let code = cef_engine::execute_sub_process();
    if code >= 0 {
        std::process::exit(code);
    }

    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::tabs_create,
            commands::tabs_close,
            commands::tabs_activate,
            commands::tabs_list,
            commands::content_hidden,
            commands::tabs_restore,
            commands::nav_navigate,
            commands::nav_back,
            commands::nav_forward,
            commands::nav_reload,
            commands::bookmarks_list,
            commands::bookmarks_add,
            commands::bookmarks_remove,
            commands::passwords_for,
            commands::passwords_save,
            commands::downloads_list,
            commands::download_control,
            commands::download_fast,
            commands::media_tools_status,
            commands::media_fetch_tools,
            commands::media_probe,
            commands::media_download,
            commands::media_resolve_stream,
            commands::reveal_in_folder,
            commands::torrent_add,
            commands::torrent_list,
            commands::torrent_control,
            commands::download_remove,
            commands::huma_classify,
            commands::huma_guard_feedback,
            commands::huma_deep_scan,
            commands::sandbox_proceed,
            commands::community_flag,
            commands::report_phishing,
            commands::huma_summarize,
            commands::huma_read_active,
            commands::blocklist_add_block,
            commands::blocklist_add_allow,
            commands::tabs_create_tor,
            commands::tabs_create_private,
            commands::tabs_create_internal,
            commands::tabs_move,
            commands::window_new,
            commands::window_new_private,
            commands::tor_status,
            commands::history_list,
            commands::history_clear,
            commands::history_delete,
            commands::passwords_all,
            commands::passwords_delete,
            commands::search_engines,
            commands::search_suggest,
            commands::config_get,
            commands::config_set,
            commands::find_start,
            commands::find_stop,
            commands::zoom_set,
            commands::incognito_settings_get,
            commands::incognito_settings_set,
            commands::extensions_list,
            commands::extensions_toggle,
            commands::extensions_install,
            commands::extensions_uninstall,
            commands::extensions_reload,
            commands::cef_version,
            commands::shell_focus,
            commands::proxy_status,
            commands::proxy_set,
            commands::proxy_relaunch,
        ])
        // A closed window must take its tabs (and their CEF browsers) with
        // it. Leaving them in the manager kept live browser views parented to
        // a destroyed native window — the next CEF call on one crashed the
        // whole app (the Cmd+W "whole app closed / crash loop" report).
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                let label = window.label().to_string();
                tabs::close_window_tabs(&label);
                session::save(window.app_handle());
            }
        })
        .setup(|app| {
            app.manage(storage::Storage::open(app.handle())?);
            app.manage(huma_layer::Huma::load(app.handle())?);
            let data_dir = app.handle().path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let bl = blocking::init(&data_dir);
            if let Some(url) = startpage::load_config().community_feed_url {
                if url.starts_with("https://") {
                    bl.set_community_url(url);
                }
            }
            extensions::init(&data_dir);
            startpage::refresh_runtime_flags();
            tor::init();
            // Built-in torrent engine; downloads into ~/Downloads/vev-torrents.
            if let Some(home) = std::env::var_os("HOME") {
                let dir = std::path::PathBuf::from(home).join("Downloads").join("vev-torrents");
                std::fs::create_dir_all(&dir).ok();
                vev_torrent::init(dir);
            }
            cef_engine::initialize(app.handle().clone())?;
            // Cache the X11 display (Linux) for later view show/hide; no-op
            // on other platforms.
            if let Some(w) = app.get_webview_window("main") {
                platform::cache_display(&w);
            }
            // Restore the previous session's tabs, or open the start page.
            let restored = session::restore_urls(app.handle());
            let is_test = std::env::var("VEV_AUTOTEST").is_ok()
                || std::env::args().any(|a| a == "--vev-autotest");
            if !restored.is_empty() && !is_test {
                for url in restored {
                    commands::create_tab_on_main(app.handle(), "main", url)?;
                }
            } else {
                let start = if is_test { START_URL.to_string() } else { startpage::url() };
                commands::create_tab_on_main(app.handle(), "main", start)?;
            }
            // Runtime self-test driving the real command layer; used by the
            // verification workflow, never enabled in normal runs.
            // (argv flag rather than env var: `open --env` does not reliably
            // propagate to the launched app.)
            if std::env::var("VEV_AUTOTEST").is_ok()
                || std::env::args().any(|a| a == "--vev-autotest")
            {
                autotest::spawn(app.handle().clone());
            }
            Ok(())
        })
        .build(tauri::generate_context!());

    let app = match app {
        Ok(app) => app,
        Err(e) => {
            // Startup failure is unrecoverable for a browser shell; exiting
            // with a message is the intended behavior here.
            eprintln!("vev: failed to build tauri app: {e}");
            std::process::exit(1);
        }
    };

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            cef_engine::shutdown();
        }
    });
}
