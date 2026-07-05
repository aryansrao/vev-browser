//! CEF lifecycle: initialization, external message pump, browser creation.
//!
//! CEF on macOS does not support running its message loop on a non-main
//! thread, and tauri (tao) owns the main run loop. We therefore run CEF with
//! `external_message_pump` enabled and drive `do_message_loop_work` on the
//! main thread — see `pump_work` for the two hard-won rules that keep this
//! from crashing or stalling.

use crate::{blocking, tabs};
use cef::{rc::*, sys, *};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

/// Fixed remote debugging port so verification can talk to the DevTools
/// protocol endpoint (http://127.0.0.1:9223/json).
pub const DEVTOOLS_PORT: u16 = 9223;

thread_local! {
    /// Re-entrancy guard: do_message_loop_work must never be called while a
    /// previous call is still on the stack.
    static PUMPING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run one iteration of the CEF message loop on the main thread, skipping
/// (not queueing) if a pump iteration is already running — CEF reschedules
/// via on_schedule_message_pump_work, so dropped calls are self-correcting.
fn pump_work() {
    PUMPING.with(|pumping| {
        if pumping.get() {
            return;
        }
        pumping.set(true);
        do_message_loop_work();
        pumping.set(false);
    });
}

wrap_browser_process_handler! {
    struct VevBrowserProcessHandler {
        app_handle: AppHandle,
    }

    impl BrowserProcessHandler {
        fn on_context_initialized(&self) {
            let policy = network_policy(&self.app_handle);
            eprintln!(
                "vev-network: doh=secure resolver={} ({}), 3p-cookies=blocked, features={}",
                policy.doh_source,
                policy.doh_template,
                vev_network::ENABLED_FEATURES.join(",")
            );
        }

        fn on_schedule_message_pump_work(&self, delay_ms: i64) {
            // CEF may invoke this on the main thread, including from inside
            // cef_initialize. tauri's run_on_main_thread executes its closure
            // INLINE when already on the main thread, which would re-enter
            // CEF's message pump and hit a CHECK (observed as SIGTRAP inside
            // cef_initialize). Always hop through a separate thread so the
            // pump work is queued onto the event loop instead of run inline.
            let handle = self.app_handle.clone();
            std::thread::spawn(move || {
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms as u64));
                }
                let _ = handle.run_on_main_thread(pump_work);
            });
        }
    }
}

wrap_app! {
    struct VevCefApp {
        app_handle: AppHandle,
    }

    impl App {
        fn browser_process_handler(&self) -> Option<BrowserProcessHandler> {
            Some(VevBrowserProcessHandler::new(self.app_handle.clone()))
        }

        fn on_before_command_line_processing(
            &self,
            process_type: Option<&CefString>,
            command_line: Option<&mut CommandLine>,
        ) {
            let is_browser_process = process_type.map(|t| t.to_string().is_empty()).unwrap_or(true);
            let (Some(command_line), true) = (command_line, is_browser_process) else {
                return;
            };
            // Vev never stores secrets through Chromium's os_crypt (its own
            // encrypted store arrives in Phase 6), so skip the macOS
            // "Chromium Safe Storage" Keychain item. Without this, every
            // unsigned dev rebuild re-triggers a Keychain password prompt.
            command_line.append_switch(Some(&CefString::from("use-mock-keychain")));

            // WebRTC hardening (all tabs): candidates only on the default
            // public interface (no local-interface enumeration → no LAN IP
            // in ICE candidates), and honor the mic/cam permission gate
            // before exposing local addresses. Private tabs can additionally
            // remove WebRTC entirely (incognito settings).
            command_line.append_switch_with_value(
                Some(&CefString::from("force-webrtc-ip-handling-policy")),
                Some(&CefString::from("default_public_interface_only")),
            );
            command_line.append_switch(Some(&CefString::from(
                "enforce-webrtc-ip-permission-check",
            )));

            // Fingerprint resistance: fixed UI language.
            command_line.append_switch_with_value(
                Some(&CefString::from("lang")),
                Some(&CefString::from(vev_fingerprint::LANG)),
            );

            // Browser-wide Tor routing (opt-in). CEF 149 (Alloy runtime)
            // refuses per-request-context SetPreference("proxy"), so per-tab
            // in-browser Tor routing is not reachable via the public API;
            // this global switch routes the whole browser through the
            // embedded Arti SOCKS proxy instead. See README "Tor" for the
            // limitation and evidence. socks5:// with remote DNS = no leak.
            // Browser-wide proxy is a Chromium command-line switch: the Alloy
            // runtime refuses proxy changes on both per-request-context AND
            // the global request context (verified — autotest
            // `tor_runtime_proxy_toggle`), so it can only be set at launch and
            // changing it needs a relaunch. Resolve the desired proxy from
            // the terminal flag first, else the persisted config.
            //   --vev-tor-all / VEV_TOR_ALL → Tor
            //   config proxy_mode "tor" (or legacy tor_all=true) → Tor
            //   config proxy_mode "custom" → custom_proxy_url
            let forced_tor = std::env::var("VEV_TOR_ALL").is_ok()
                || std::env::args().any(|a| a == "--vev-tor-all");
            let (server, mode): (Option<String>, &str) = if forced_tor {
                (crate::tor::default_proxy_addr().map(|a| format!("socks5://{a}")), "tor")
            } else {
                let cfg = crate::startpage::load_config();
                match cfg.proxy_mode.as_deref() {
                    Some("tor") => {
                        (crate::tor::default_proxy_addr().map(|a| format!("socks5://{a}")), "tor")
                    }
                    Some("custom") => {
                        let url = cfg.custom_proxy_url.filter(|u| !u.trim().is_empty());
                        (url, "custom")
                    }
                    Some("off") => (None, "off"),
                    // Legacy: tor_all=true before proxy_mode existed.
                    _ if cfg.tor_all.unwrap_or(false) => {
                        (crate::tor::default_proxy_addr().map(|a| format!("socks5://{a}")), "tor")
                    }
                    _ => (None, "off"),
                }
            };
            if let Some(server) = server {
                // Chromium resolves DNS through the proxy for socks5://
                // (remote resolution), so no separate resolver rule is needed
                // and none must leak locally.
                command_line.append_switch_with_value(
                    Some(&CefString::from("proxy-server")),
                    Some(&CefString::from(server.as_str())),
                );
                *ACTIVE_PROXY_MODE.lock().unwrap() = mode.to_string();
                eprintln!("vev-proxy: browser-wide proxy [{mode}] via {server}");
            }

            // Network hardening features (ECH, third-party storage
            // partitioning, 3p-cookie blocking) — see
            // vev_network::ENABLED_FEATURES for why.
            command_line.append_switch_with_value(
                Some(&CefString::from("enable-features")),
                Some(&CefString::from(
                    vev_network::ENABLED_FEATURES.join(",").as_str(),
                )),
            );

            // DoH + cookie policy switches (loaded with the user override so
            // a configured resolver reaches the network service at startup).
            let policy = network_policy(&self.app_handle);
            for (name, value) in vev_network::command_line_switches(&policy) {
                match value {
                    Some(v) => command_line.append_switch_with_value(
                        Some(&CefString::from(name.as_str())),
                        Some(&CefString::from(v.as_str())),
                    ),
                    None => {
                        command_line.append_switch(Some(&CefString::from(name.as_str())))
                    }
                }
            }
        }
    }
}

/// The browser-wide proxy mode actually applied at CEF startup this run:
/// "off", "tor", or "custom". A proxy is a launch-time command-line switch
/// (the Alloy runtime refuses runtime proxy changes), so this is fixed for
/// the process lifetime and the UI compares it against the desired config to
/// decide whether a relaunch is needed.
pub static ACTIVE_PROXY_MODE: std::sync::LazyLock<std::sync::Mutex<String>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new("off".to_string()));

/// The proxy mode this run is actually using.
pub fn active_proxy_mode() -> String {
    ACTIVE_PROXY_MODE.lock().unwrap().clone()
}

fn network_policy(app_handle: &AppHandle) -> vev_network::NetworkPolicy {
    let config_path = app_handle
        .path()
        .app_data_dir()
        .map(|d| d.join("network.json"))
        .unwrap_or_default();
    vev_network::NetworkPolicy::load(&config_path).unwrap_or_else(|e| {
        eprintln!("vev-network: override rejected ({e}); using defaults");
        vev_network::NetworkPolicy::default()
    })
}

wrap_life_span_handler! {
    struct VevLifeSpanHandler {
        app_handle: AppHandle,
    }

    impl LifeSpanHandler {
        fn on_before_popup(
            &self,
            browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            _popup_id: ::std::os::raw::c_int,
            target_url: Option<&CefString>,
            _target_frame_name: Option<&CefString>,
            _target_disposition: WindowOpenDisposition,
            user_gesture: ::std::os::raw::c_int,
            _popup_features: Option<&PopupFeatures>,
            _window_info: Option<&mut WindowInfo>,
            _client: Option<&mut Option<Client>>,
            _settings: Option<&mut BrowserSettings>,
            _extra_info: Option<&mut Option<DictionaryValue>>,
            _no_javascript_access: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            let url = target_url.map(|u| u.to_string()).unwrap_or_default();

            // Popup blocker (Brave-style): a popup with NO user gesture is a
            // script-spawned pop-under/ad — the kind sketchy streaming/torrent
            // sites fire on click. Block it silently. Only a popup that came
            // from a real click/keypress becomes a tab. Also block popups to
            // hosts on the threat feed, gesture or not.
            let blocked_threat = url.starts_with("http") && blocking::is_threat(&url);
            if user_gesture == 0 || blocked_threat {
                eprintln!(
                    "vev: blocked popup {url} (gesture={user_gesture}, threat={blocked_threat})"
                );
                if let Some((_, win)) = browser.and_then(|b| tabs::tab_for_browser(b.identifier())) {
                    let _ = self.app_handle.emit_to(win.as_str(), "popup-blocked", &url);
                }
                return 1; // cancel; do not open a tab
            }

            // Genuine user-initiated popup: open as a normal tab in the
            // opener's window instead of CEF's bare chrome-less window.
            // (Private windows keep it private — derived from the label.)
            let window = browser
                .and_then(|b| tabs::tab_for_browser(b.identifier()))
                .map(|(_, w)| w)
                .unwrap_or_else(|| "main".to_string());
            let app = self.app_handle.clone();
            // Queue the tab creation instead of creating a browser inside
            // this CEF callback (browser creation here can re-enter CEF).
            std::thread::spawn(move || {
                let app2 = app.clone();
                let _ = tabs::on_main_thread(&app, move || {
                    let url = if url.is_empty() { "about:blank".into() } else { url };
                    if let Err(e) = crate::commands::create_tab_inner(&app2, &window, url, None, false) {
                        eprintln!("vev: popup-to-tab failed: {e}");
                    }
                });
            });
            1 // cancel the native popup
        }

        fn do_close(&self, browser: Option<&mut Browser>) -> ::std::os::raw::c_int {
            // Default CEF close behavior sends a close to the host window —
            // which is Vev's main window, so closing any tab would quit the
            // whole app. Detach the view ourselves and return 1 to suppress
            // the window-close chain; CEF then finalizes the browser and fires
            // on_before_close.
            if let Some(host) = browser.and_then(|b| b.host()) {
                crate::platform::detach_view(&host);
            }
            1
        }

        fn on_after_created(&self, browser: Option<&mut Browser>) {
            // Pin the CEF view to its parent's size so window resizes
            // propagate without manual frame bookkeeping (platform-specific).
            if let Some(host) = browser.and_then(|b| b.host()) {
                crate::platform::pin_view(&host);
            }
        }
    }
}

wrap_display_handler! {
    struct VevDisplayHandler {
        app_handle: AppHandle,
    }

    impl DisplayHandler {
        fn on_title_change(&self, browser: Option<&mut Browser>, title: Option<&CefString>) {
            let Some(browser) = browser else { return };
            let Some((id, win)) = tabs::tab_for_browser(browser.identifier()) else { return };
            let title = title.map(|t| t.to_string()).unwrap_or_default();
            tabs::with_manager(|m| {
                if let Some(tab) = m.get_mut(id) {
                    tab.title = title;
                }
            });
            tabs::emit_tabs_changed(&self.app_handle, &win);
        }

        fn on_address_change(
            &self,
            browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            url: Option<&CefString>,
        ) {
            let (Some(browser), Some(frame)) = (browser, frame) else { return };
            if frame.is_main() == 0 {
                return;
            }
            let Some((id, win)) = tabs::tab_for_browser(browser.identifier()) else { return };
            let url = url.map(|u| u.to_string()).unwrap_or_default();
            // Capture the previous URL for the Huma Predict transition.
            let prev_url = tabs::with_manager(|m| m.get_mut(id).map(|t| t.url.clone()));
            // Derive the favicon from the page origin (host/favicon.ico) —
            // the standard location every site serves, no extra tracking.
            let favicon = url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(|h| (u.scheme().to_string(), h.to_string())))
                .filter(|(s, _)| s == "http" || s == "https")
                .map(|(s, h)| format!("{s}://{h}/favicon.ico"))
                .unwrap_or_default();
            let title = tabs::with_manager(|m| {
                m.get_mut(id).map(|tab| {
                    tab.url = url.clone();
                    tab.favicon = favicon;
                    tab.title.clone()
                })
            });
            // Huma Predict: learn the from->to transition and warm the likely
            // next site's DNS/TCP.
            if let (Some(prev), false) = (prev_url, url.is_empty()) {
                if !prev.is_empty() && prev != url {
                    use tauri::Manager;
                    if let Some(huma) = self.app_handle.try_state::<crate::huma_layer::Huma>() {
                        huma.on_navigation(&prev, &url);
                    }
                }
            }
            // Record encrypted history for the top-level navigation.
            if let Some(title) = title {
                use tauri::Manager;
                if let Some(store) = self.app_handle.try_state::<crate::storage::Storage>() {
                    store.add_history(url, title);
                }
            }
            tabs::emit_tabs_changed(&self.app_handle, &win);
            // Keep the restorable session current with the latest URLs.
            crate::session::save(&self.app_handle);
        }

    }
}

wrap_load_handler! {
    struct VevLoadHandler {
        app_handle: AppHandle,
    }

    impl LoadHandler {
        fn on_load_start(
            &self,
            browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            _transition_type: TransitionType,
        ) {
            // document_start injections — before the frame's own scripts run.
            let Some(frame) = frame else { return };
            // Private tabs honor the incognito session toggles; normal tabs
            // always get the fixed fingerprint profile.
            let is_private = browser
                .and_then(|b| tabs::tab_for_browser(b.identifier()))
                .map(|(id, _)| {
                    tabs::with_manager(|m| {
                        m.get_mut(id).map(|t| t.is_private).unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            let inc = crate::incognito::get();
            if !is_private || inc.fingerprint_spoof {
                frame.execute_java_script(
                    Some(&CefString::from(vev_fingerprint::spoof_js())),
                    Some(&CefString::from("vev://fingerprint")),
                    0,
                );
            }
            if is_private && inc.block_webrtc {
                frame.execute_java_script(
                    Some(&CefString::from(crate::incognito::WEBRTC_KILL_JS)),
                    Some(&CefString::from("vev://webrtc-shield")),
                    0,
                );
            }
            let url = CefString::from(&frame.url()).to_string();
            let shields = !is_private || inc.page_shields;
            // YouTube ad neutralization must run at document_start so the
            // player response is pruned before the player reads it.
            if shields {
                blocking::inject_youtube_adblock(frame, &url);
            }
            // Extension content scripts declared run_at=document_start.
            if frame.is_main() != 0 {
                crate::extensions::inject(frame, &url, crate::extensions::RunAt::DocumentStart);
            }
        }

        fn on_loading_state_change(
            &self,
            browser: Option<&mut Browser>,
            is_loading: ::std::os::raw::c_int,
            can_go_back: ::std::os::raw::c_int,
            can_go_forward: ::std::os::raw::c_int,
        ) {
            let Some(browser) = browser else { return };
            let Some((id, win)) = tabs::tab_for_browser(browser.identifier()) else { return };
            tabs::with_manager(|m| {
                if let Some(tab) = m.get_mut(id) {
                    tab.loading = is_loading != 0;
                    tab.can_back = can_go_back != 0;
                    tab.can_forward = can_go_forward != 0;
                }
            });
            tabs::emit_tabs_changed(&self.app_handle, &win);
        }

        fn on_load_end(
            &self,
            browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            _http_status_code: ::std::os::raw::c_int,
        ) {
            // Cosmetic filtering: inject element-hiding CSS once the main
            // frame's document exists.
            let Some(frame) = frame else { return };
            if frame.is_main() == 0 {
                return;
            }
            // Resolve the owning tab once (browser is consumed here).
            let tab = browser.and_then(|b| tabs::tab_for_browser(b.identifier()));
            let is_private = tab
                .as_ref()
                .map(|(id, _)| {
                    tabs::with_manager(|m| m.get_mut(*id).map(|t| t.is_private).unwrap_or(false))
                })
                .unwrap_or(false);
            let url = CefString::from(&frame.url()).to_string();
            if !is_private || crate::incognito::get().page_shields {
                blocking::inject_cosmetic_css(frame, &url);
            }
            // Extension content scripts (document_end / idle).
            crate::extensions::inject(frame, &url, crate::extensions::RunAt::DocumentEnd);

            // Huma content-phishing check: read the page's actual text and
            // flag brand-impersonation-with-domain-mismatch. Runs on top-level
            // http(s) loads when Guard is enabled.
            if url.starts_with("http") && crate::startpage::huma_guard_enabled() {
                if let (Some(app), Some((id, win))) = (APP_HANDLE.get(), tab) {
                    let title = tabs::with_manager(|m| {
                        m.get_mut(id).map(|t| t.title.clone()).unwrap_or_default()
                    });
                    let mut visitor = ContentGuardVisitor::new(app.clone(), url.clone(), title, win);
                    frame.text(Some(&mut visitor));
                }
            }
        }
    }
}

wrap_request_handler! {
    struct VevRequestHandler {
        app_handle: AppHandle,
    }

    impl RequestHandler {
        fn on_before_browse(
            &self,
            browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            request: Option<&mut Request>,
            _user_gesture: ::std::os::raw::c_int,
            _is_redirect: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int {
            let (Some(frame), Some(request)) = (frame, request) else {
                return 0;
            };
            if frame.is_main() == 0 {
                return 0;
            }
            let url = CefString::from(&request.url()).to_string();
            let browser_id = browser.as_ref().map(|b| b.identifier()).unwrap_or(0);

            // Magnet links belong to the torrent engine, not a navigation:
            // hand off and cancel so the page doesn't error on the scheme.
            if url.starts_with("magnet:") {
                let app = self.app_handle.clone();
                let magnet = url.clone();
                std::thread::spawn(move || {
                    match vev_torrent::add(magnet) {
                        Ok(_) => {
                            let _ = app.emit("torrent-added", serde_json::json!({ "name": "magnet link" }));
                        }
                        Err(e) => eprintln!("vev-torrent: add magnet failed: {e}"),
                    }
                });
                return 1;
            }

            // Huma Guard: on-device phishing-structure classifier runs before
            // the request — an extra layer alongside the filter lists + threat
            // feed. Its verdict also feeds the sandbox-gate decision below.
            let guard_verdict = (url.starts_with("http")
                && crate::startpage::huma_guard_enabled())
            .then(|| huma::guard::classify_adapted(&url))
            .filter(|v| v.malicious);
            if let Some(v) = &guard_verdict {
                eprintln!(
                    "huma-guard: phishing-structure score {:.2} for {url} ({})",
                    v.score,
                    v.reasons.join("; ")
                );
            }

            // Community feed: crowd-confirmed phishing status for this host.
            let community = url
                .starts_with("http")
                .then(|| blocking::community_flag(&url))
                .flatten();

            // Threat feed: block navigation to known phishing/malware hosts.
            if blocking::is_threat(&url) {
                eprintln!("vev-blocklist: THREAT block {url}");
                // Confirmed-malicious outcome: reinforce the Guard's learning
                // so structurally-similar URLs score higher next time.
                huma::adapt::record_url(&url, true);
                frame.load_url(Some(&CefString::from(
                    blocking::threat_block_page(&url).as_str(),
                )));
                return 1;
            }

            // HTTPS-only mode: rewrite plain-HTTP top-level navigations.
            // (Chromium's compiled-in HSTS preload list already upgrades
            // known hosts; this covers everything else.) The https re-entry
            // of this handler evaluates the sandbox gate.
            if let Some(upgraded) = vev_network::https_upgrade(&url) {
                eprintln!("vev-network: upgrading {url} -> {upgraded}");
                frame.load_url(Some(&CefString::from(upgraded.as_str())));
                return 1; // cancel the plain-HTTP navigation
            }

            // Huma pre-open sandbox: intercept the navigation and render it
            // in a hidden Tor-routed browser first; the verdict decides
            // whether the real tab proceeds. Tor tabs skip the gate — they
            // are already isolated and Tor-routed by construction.
            let suspicious = guard_verdict.is_some() || community.is_some();
            let current_url = CefString::from(&frame.url()).to_string();
            if crate::sandbox::should_gate(&url, &current_url, suspicious) {
                let tab = tabs::tab_for_browser(browser_id)
                    .map(|(id, _)| id)
                    .filter(|id| {
                        !tabs::with_manager(|m| {
                            m.get_mut(*id).map(|t| t.is_tor).unwrap_or(false)
                        })
                    });
                if let Some(tab_id) = tab {
                    crate::sandbox::begin(&self.app_handle, tab_id, url);
                    return 1;
                }
            }

            // Not gated: surface the non-blocking warnings as before, only
            // in the window that owns this browser.
            if let Some(v) = guard_verdict {
                tabs::emit_to_browser_window(
                    &self.app_handle,
                    browser_id,
                    "huma-guard-warning",
                    serde_json::json!({
                        "score": v.score,
                        "reasons": v.reasons,
                        "url": url,
                    }),
                );
            }
            if let Some(flag) = community {
                tabs::emit_to_browser_window(
                    &self.app_handle,
                    browser_id,
                    "community-flag",
                    serde_json::json!({
                        "url": url,
                        "percent": flag.percent,
                        "reports": flag.reports,
                    }),
                );
            }
            0
        }

        fn resource_request_handler(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            _request: Option<&mut Request>,
            _is_navigation: ::std::os::raw::c_int,
            _is_download: ::std::os::raw::c_int,
            _request_initiator: Option<&CefString>,
            _disable_default_handling: Option<&mut ::std::os::raw::c_int>,
        ) -> Option<ResourceRequestHandler> {
            // Network-layer ad/tracker blocking runs inside this handler's
            // on_before_resource_load.
            Some(blocking::make_resource_request_handler())
        }

        fn on_render_process_terminated(
            &self,
            browser: Option<&mut Browser>,
            status: TerminationStatus,
            error_code: ::std::os::raw::c_int,
            error_string: Option<&CefString>,
        ) {
            let Some(browser) = browser else { return };
            let Some((id, win)) = tabs::tab_for_browser(browser.identifier()) else { return };
            eprintln!(
                "vev: renderer for tab {id} terminated (status={status:?} code={error_code} msg={:?})",
                error_string.map(|s| s.to_string())
            );
            tabs::with_manager(|m| {
                if let Some(tab) = m.get_mut(id) {
                    tab.crashed = true;
                    tab.loading = false;
                }
            });
            tabs::emit_tabs_changed(&self.app_handle, &win);
            let _ = self.app_handle.emit_to(win.as_str(), "tab-crashed", id);
        }
    }
}

// CEF event-flag bitmask values (stable across CEF).
const EVENTFLAG_SHIFT_DOWN: u32 = 1 << 1;
const EVENTFLAG_CONTROL_DOWN: u32 = 1 << 2;
const EVENTFLAG_COMMAND_DOWN: u32 = 1 << 7;

/// Map a Ctrl/Cmd keyboard shortcut to a shell action name, forwarded to the
/// shell UI as a "shortcut" event so shortcuts work while a web page has
/// focus (the shell webview never receives those key events otherwise).
fn shortcut_for(key: i32, shift: bool) -> Option<&'static str> {
    // Windows VK codes: A-Z are ASCII uppercase, 0-9 are ASCII digits.
    match key as u8 as char {
        '1'..='9' => Some(match key as u8 as char {
            '1' => "tab-1", '2' => "tab-2", '3' => "tab-3", '4' => "tab-4",
            '5' => "tab-5", '6' => "tab-6", '7' => "tab-7", '8' => "tab-8",
            _ => "tab-9",
        }),
        '0' => Some("zoom-reset"),
        'T' => Some(if shift { "reopen-tab" } else { "new-tab" }),
        'N' if shift => Some("new-private-window"),
        'N' => Some("new-window"),
        'W' => Some("close-tab"),
        'L' | 'K' => Some("focus-address"),
        'R' => Some("reload"),
        'D' => Some("bookmark"),
        'F' => Some("find"),
        'J' => Some("downloads"),
        'P' => Some("command-palette"),
        'Y' if shift => Some("history"),
        'U' if shift => Some("view-source"),
        _ => match key {
            188 => Some("settings"),                                  // ','
            219 => Some(if shift { "prev-tab" } else { "back" }),     // '['
            221 => Some(if shift { "next-tab" } else { "forward" }),  // ']'
            187 => Some("zoom-in"),                                   // '=' / '+'
            189 => Some("zoom-out"),                                  // '-'
            37 => Some("back"),                                       // Left
            39 => Some("forward"),                                    // Right
            _ => None,
        },
    }
}

wrap_string_visitor! {
    struct HumaReadVisitor {
        app_handle: AppHandle,
        window: String,
    }

    impl CefStringVisitor {
        fn visit(&self, string: Option<&CefString>) {
            let text = string.map(|s| s.to_string()).unwrap_or_default();
            let summary = if text.split_whitespace().count() < 40 {
                "Not enough article text on this page to summarize.".to_string()
            } else {
                let cleaned = huma::read::clean_extracted(&text);
                let src = if cleaned.split_whitespace().count() > 30 { cleaned } else { text };
                huma::read::summarize(&src, 6)
            };
            let _ = self.app_handle.emit_to(self.window.as_str(), "huma-read-result", summary);
        }
    }
}

wrap_string_visitor! {
    struct ContentGuardVisitor {
        app_handle: AppHandle,
        url: String,
        title: String,
        window: String,
    }

    impl CefStringVisitor {
        fn visit(&self, string: Option<&CefString>) {
            let text = string.map(|s| s.to_string()).unwrap_or_default();
            let verdict = huma::content::analyze(&self.url, &self.title, &text);
            if verdict.malicious {
                eprintln!(
                    "huma-content: phishing content score {:.2} for {} (impersonates {:?})",
                    verdict.score, self.url, verdict.impersonated
                );
                // Confirmed-structure outcome feeds the self-adapting Guard too.
                huma::adapt::record_url(&self.url, true);
                let _ = self.app_handle.emit_to(
                    self.window.as_str(),
                    "huma-guard-warning",
                    serde_json::json!({
                        "score": verdict.score,
                        "reasons": verdict.reasons,
                        "url": self.url,
                        "source": "content",
                        "impersonated": verdict.impersonated,
                    }),
                );
            }
        }
    }
}

/// Extract the active tab's visible text via CEF and summarize it on-device,
/// emitting `huma-read-result`. Runs on the main thread. This avoids the
/// shell webview having to reach the DevTools endpoint (which WKWebView
/// blocks), which is why the earlier Huma Read failed.
pub fn huma_read_active(window: &str) {
    use cef::ImplBrowser;
    let active = tabs::with_manager(|m| m.active_id(window));
    let Some(id) = active else { return };
    let Some(browser) = tabs::browser_for_tab(id) else { return };
    let Some(frame) = browser.main_frame() else { return };
    // The app handle lives in the client; grab it from any browser's handler
    // is awkward, so we stash it globally at init.
    if let Some(app) = APP_HANDLE.get() {
        let mut visitor = HumaReadVisitor::new(app.clone(), window.to_string());
        frame.text(Some(&mut visitor));
    }
}

static APP_HANDLE: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

/// The app handle stashed at CEF init — usable from any module/thread to emit
/// events (e.g. blocking emits `resource-blocked` for the Huma island).
pub fn app_handle() -> Option<AppHandle> {
    APP_HANDLE.get().cloned()
}

wrap_keyboard_handler! {
    struct VevKeyboardHandler {
        app_handle: AppHandle,
    }

    impl KeyboardHandler {
        // The final `os_event` parameter's type is platform-specific in CEF
        // (raw pointer on macOS, a wrapped X event on Linux, MSG on Windows).
        // We don't use it, so the override is macOS-only; on other platforms
        // the default handler is used and shell-level shortcuts still work.
        #[cfg(target_os = "macos")]
        fn on_key_event(
            &self,
            browser: Option<&mut Browser>,
            event: Option<&KeyEvent>,
            _os_event: *mut u8,
        ) -> ::std::os::raw::c_int {
            let Some(event) = event else { return 0 };
            // Only act on key-down; ignore auto-repeat char events.
            if event.type_ != KeyEventType::RAWKEYDOWN && event.type_ != KeyEventType::KEYDOWN {
                return 0;
            }
            // Route the shortcut ONLY to the shell of the window this browser
            // lives in. A broadcast here made one ⌘W close a tab in EVERY
            // open window (and ⌘T open a tab in each).
            let browser_id = browser.map(|b| b.identifier()).unwrap_or(0);
            let m = event.modifiers;
            // Forward Escape (no modifier) so overlays can close while the
            // hidden web view holds keyboard focus. Don't consume it (return
            // 0) — the page may also want Escape.
            if event.windows_key_code == 27 {
                tabs::emit_to_browser_window(&self.app_handle, browser_id, "shortcut", "close-overlay");
                return 0;
            }
            let cmd = m & (EVENTFLAG_COMMAND_DOWN | EVENTFLAG_CONTROL_DOWN) != 0;
            if !cmd {
                return 0;
            }
            let shift = m & EVENTFLAG_SHIFT_DOWN != 0;
            if let Some(action) = shortcut_for(event.windows_key_code, shift) {
                tabs::emit_to_browser_window(&self.app_handle, browser_id, "shortcut", action);
                return 1; // consume — don't pass the shortcut to the page
            }
            0
        }
    }
}

wrap_find_handler! {
    struct VevFindHandler {
        app_handle: AppHandle,
    }

    impl FindHandler {
        fn on_find_result(
            &self,
            browser: Option<&mut Browser>,
            _identifier: ::std::os::raw::c_int,
            count: ::std::os::raw::c_int,
            _selection_rect: Option<&Rect>,
            active_match_ordinal: ::std::os::raw::c_int,
            _final_update: ::std::os::raw::c_int,
        ) {
            let browser_id = browser.map(|b| b.identifier()).unwrap_or(0);
            tabs::emit_to_browser_window(
                &self.app_handle,
                browser_id,
                "find-result",
                serde_json::json!({ "total": count, "current": active_match_ordinal }),
            );
        }
    }
}

wrap_client! {
    struct VevClient {
        app_handle: AppHandle,
    }

    impl Client {
        fn life_span_handler(&self) -> Option<LifeSpanHandler> {
            Some(VevLifeSpanHandler::new(self.app_handle.clone()))
        }

        fn find_handler(&self) -> Option<FindHandler> {
            Some(VevFindHandler::new(self.app_handle.clone()))
        }

        fn display_handler(&self) -> Option<DisplayHandler> {
            Some(VevDisplayHandler::new(self.app_handle.clone()))
        }

        fn load_handler(&self) -> Option<LoadHandler> {
            Some(VevLoadHandler::new(self.app_handle.clone()))
        }

        fn request_handler(&self) -> Option<RequestHandler> {
            Some(VevRequestHandler::new(self.app_handle.clone()))
        }

        fn download_handler(&self) -> Option<DownloadHandler> {
            Some(crate::downloads::make_handler(&self.app_handle))
        }

        fn keyboard_handler(&self) -> Option<KeyboardHandler> {
            Some(VevKeyboardHandler::new(self.app_handle.clone()))
        }

        fn context_menu_handler(&self) -> Option<ContextMenuHandler> {
            Some(crate::context_menu::make_handler(&self.app_handle))
        }
    }
}

/// Initialize CEF in the browser process. Must be called on the main thread
/// after the NSApplication subclass is installed and the tauri app exists.
pub fn initialize(app_handle: AppHandle) -> Result<(), String> {
    let _ = APP_HANDLE.set(app_handle.clone());
    let cache_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app data dir: {e}"))?
        .join("cef-cache");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("cannot create cache dir {cache_dir:?}: {e}"))?;

    let args = args::Args::new();
    let pump_handle = app_handle.clone();
    let mut app = VevCefApp::new(app_handle);

    let settings = Settings {
        external_message_pump: 1,
        no_sandbox: !cfg!(feature = "sandbox") as _,
        root_cache_path: CefString::from(cache_dir.to_string_lossy().as_ref()),
        cache_path: CefString::from(cache_dir.to_string_lossy().as_ref()),
        remote_debugging_port: DEVTOOLS_PORT as _,
        // Fingerprint resistance: fixed UA + Accept-Language for all sites.
        user_agent: CefString::from(vev_fingerprint::USER_AGENT),
        accept_language_list: CefString::from(vev_fingerprint::ACCEPT_LANGUAGE),
        ..Default::default()
    };

    let ok = cef::initialize(
        Some(args.as_main_args()),
        Some(&settings),
        Some(&mut app),
        std::ptr::null_mut(),
    );
    if ok != 1 {
        return Err(format!(
            "cef::initialize failed (exit code {})",
            get_exit_code()
        ));
    }

    // Steady 10ms timer pump in addition to CEF's schedule hints: the
    // hint-driven path alone was observed to stall after the first iteration
    // (CEF stops rescheduling if a hint is missed around initialization).
    // The PUMPING guard makes overlapping requests harmless. Cost is one
    // queued closure per tick; revisit with profiling data if it shows up.
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(10));
        if pump_handle.run_on_main_thread(pump_work).is_err() {
            break;
        }
    });

    Ok(())
}

/// Create a CEF browser as a child view of the given tauri window, sized to
/// fill it below the shell toolbar, and navigate to `url`. Returns the
/// browser handle. Main thread only.
/// Build a `proxy` preference dictionary for a fixed SOCKS5 server, matching
/// Chromium's ProxyConfig JSON shape.
fn socks_proxy_dict(socks_addr: &str) -> Option<DictionaryValue> {
    proxy_server_dict(&format!("socks5://{socks_addr}"))
}

/// A `proxy` preference dictionary pointing at a fixed proxy server URL
/// (`socks5://host:port`, `http://host:port`, …), matching Chromium's
/// ProxyConfig JSON shape.
fn proxy_server_dict(server_url: &str) -> Option<DictionaryValue> {
    let dict = dictionary_value_create()?;
    dict.set_string(
        Some(&CefString::from("mode")),
        Some(&CefString::from("fixed_servers")),
    );
    dict.set_string(
        Some(&CefString::from("server")),
        Some(&CefString::from(server_url)),
    );
    Some(dict)
}

wrap_request_context_handler! {
    struct VevProxyContextHandler {
        socks_addr: String,
    }

    impl RequestContextHandler {
        fn on_request_context_initialized(
            &self,
            request_context: Option<&mut RequestContext>,
        ) {
            // The proxy preference can only be set once the context is fully
            // initialized (setting it earlier returns 0 with an empty error).
            let Some(ctx) = request_context else { return };
            let (Some(mut dict), Some(mut value)) =
                (socks_proxy_dict(&self.socks_addr), value_create())
            else {
                return;
            };
            value.set_dictionary(Some(&mut dict));
            let mut err = CefString::default();
            let ok = ctx.set_preference(
                Some(&CefString::from("proxy")),
                Some(&mut value),
                Some(&mut err),
            );
            if ok == 1 {
                eprintln!("vev-tor: proxy set on request context -> {}", self.socks_addr);
            } else {
                eprintln!("vev-tor: failed to set proxy pref: {err:?}");
            }
        }
    }
}

thread_local! {
    /// The shared incognito RequestContext (main thread only, like all CEF
    /// objects here). Created lazily on the first private tab.
    static INCOGNITO_CTX: std::cell::RefCell<Option<RequestContext>> =
        const { std::cell::RefCell::new(None) };
}

/// The app-run-wide ephemeral incognito context (created on first use).
fn incognito_context() -> Result<RequestContext, String> {
    INCOGNITO_CTX.with(|cell| {
        let mut slot = cell.borrow_mut();
        if let Some(ctx) = slot.as_ref() {
            return Ok(ctx.clone());
        }
        // Empty cache_path = in-memory only; nothing touches disk.
        let ctx_settings = RequestContextSettings::default();
        let ctx = request_context_create_context(Some(&ctx_settings), None)
            .ok_or("failed to create incognito request context")?;
        *slot = Some(ctx.clone());
        Ok(ctx)
    })
}

/// Like `create_browser`, but if `proxy_socks` is set the browser runs in an
/// isolated RequestContext whose `proxy` preference routes all traffic (and,
/// because it's SOCKS5, DNS) through that proxy — used for Tor tabs.
pub fn create_browser_ctx(
    app_handle: &AppHandle,
    window: &tauri::WebviewWindow,
    url: &str,
    proxy_socks: Option<&str>,
    private: bool,
) -> Result<Browser, String> {
    // Native child-view embedding is platform-specific — see `platform`.
    let window_info = crate::platform::child_window_info(window)?;

    let mut client = VevClient::new(app_handle.clone());
    let url = CefString::from(url);
    let browser_settings = BrowserSettings::default();

    // Tor tabs get their own RequestContext with a SOCKS5 proxy preference so
    // traffic + DNS route through Arti; a fresh isolated context per Tor tab
    // also keeps cookies/cache separate from normal tabs.
    let mut request_context = match proxy_socks {
        Some(socks_addr) => {
            // Distinct on-disk path per Tor context isolates cookies/cache
            // from normal tabs. A unique dir also avoids clashing with the
            // global context's storage.
            let ctx_cache = app_handle
                .path()
                .app_data_dir()
                .map_err(|e| format!("app data dir: {e}"))?
                .join("tor-contexts")
                .join(format!(
                    "ctx-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                ));
            std::fs::create_dir_all(&ctx_cache)
                .map_err(|e| format!("tor ctx cache: {e}"))?;
            let ctx_settings = RequestContextSettings {
                cache_path: CefString::from(ctx_cache.to_string_lossy().as_ref()),
                ..Default::default()
            };
            // The proxy is applied by the handler on context init (see
            // VevProxyContextHandler) — setting it before init returns 0.
            let mut handler = VevProxyContextHandler::new(socks_addr.to_string());
            let ctx = request_context_create_context(Some(&ctx_settings), Some(&mut handler))
                .ok_or("failed to create Tor request context")?;
            Some(ctx)
        }
        // Private tab: ONE shared ephemeral in-memory RequestContext for the
        // whole incognito session (empty cache_path — nothing persisted).
        // Shared so private tabs across all private windows see the same
        // session cookies, like other browsers' incognito; dropped only when
        // the app exits.
        None if private => Some(incognito_context()?),
        None => None,
    };

    browser_host_create_browser_sync(
        Some(&window_info),
        Some(&mut client),
        Some(&url),
        Some(&browser_settings),
        None,
        request_context.as_mut(),
    )
    .ok_or_else(|| "browser_host_create_browser_sync returned no browser".to_string())
}

/// Set (or clear) the browser-wide proxy at runtime on the GLOBAL request
/// context. `server_url` is a full proxy URL (`socks5://host:port`,
/// `http://host:port`, …) or `None` to go direct. This is the standard
/// Chromium runtime-proxy mechanism and is distinct from the
/// per-request-context `proxy` preference that the Alloy runtime refuses
/// (see `VevProxyContextHandler`). Returns Ok(true) if the preference was
/// accepted (takes effect without a relaunch), Ok(false) if the runtime
/// refused it (caller falls back to config + relaunch). Main thread only.
pub fn set_global_proxy(server_url: Option<&str>) -> Result<bool, String> {
    let ctx = request_context_get_global_context()
        .ok_or("no global request context")?;
    if ctx.can_set_preference(Some(&CefString::from("proxy"))) != 1 {
        return Ok(false);
    }
    let (Some(mut dict), Some(mut value)) = (
        match server_url {
            Some(url) => proxy_server_dict(url),
            None => {
                let d = dictionary_value_create().ok_or("dict create failed")?;
                d.set_string(
                    Some(&CefString::from("mode")),
                    Some(&CefString::from("direct")),
                );
                Some(d)
            }
        },
        value_create(),
    ) else {
        return Err("proxy value alloc failed".into());
    };
    value.set_dictionary(Some(&mut dict));
    let mut err = CefString::default();
    let ok = ctx.set_preference(
        Some(&CefString::from("proxy")),
        Some(&mut value),
        Some(&mut err),
    );
    if ok == 1 {
        eprintln!(
            "vev-proxy: runtime proxy {} on global context",
            server_url.map(|u| format!("-> {u}")).unwrap_or_else(|| "cleared".into())
        );
        Ok(true)
    } else {
        eprintln!("vev-proxy: runtime proxy set refused: {err:?}");
        Ok(false)
    }
}

pub fn shutdown() {
    cef::shutdown();
}

/// Sub-process dispatch required by CEF's startup contract. Returns an exit
/// code >= 0 if this process was a CEF sub-process (never the case on macOS,
/// where helpers are separate binaries); -1 for the browser process.
pub fn execute_sub_process() -> i32 {
    let args = args::Args::new();
    cef::execute_process(
        Some(args.as_main_args()),
        None::<&mut App>,
        std::ptr::null_mut(),
    )
}

/// Initialize the CEF API version hash. Must precede all other CEF calls.
pub fn init_api_hash() {
    let _ = api_hash(sys::CEF_API_VERSION_LAST, 0);
}
