//! Tab manager. CEF browser objects are not Send, so all tab state lives in
//! a thread_local on the main thread; tauri commands hop here via
//! `on_main_thread` and get results back over a channel.

use cef::{ImplBrowser, ImplFrame};
use serde::Serialize;
use std::cell::RefCell;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

/// Height (logical px) reserved at the top of the window for the shell UI
/// (tab strip + toolbar). Must match the CSS in src/shell.css.
pub const TOOLBAR_HEIGHT: f64 = 88.0;

pub struct Tab {
    pub id: u32,
    /// Which browser window this tab belongs to (tauri window label).
    pub window: String,
    /// Cached CEF browser identifier: lookups must not call into CEF while
    /// the manager RefCell is borrowed (CEF calls can synchronously re-enter
    /// handlers that also borrow the manager — observed as a
    /// "RefCell already borrowed" panic). 0 when the tab has no browser yet
    /// (internal pages).
    pub browser_id: i32,
    /// None for internal (`vev://`) pages, which are rendered by the shell
    /// webview instead of a CEF view.
    pub browser: Option<cef::Browser>,
    /// Internal page name ("settings", "history", …) when this tab is a
    /// shell-rendered `vev://` page.
    pub internal: Option<String>,
    pub url: String,
    pub title: String,
    pub loading: bool,
    pub can_back: bool,
    pub can_forward: bool,
    pub crashed: bool,
    pub is_tor: bool,
    pub is_private: bool,
    pub favicon: String,
    /// Chromium zoom level (0.0 = 100%; percent ≈ 1.2^level).
    pub zoom: f64,
}

#[derive(Clone, Serialize)]
pub struct TabInfo {
    pub id: u32,
    pub url: String,
    pub title: String,
    pub loading: bool,
    pub can_back: bool,
    pub can_forward: bool,
    pub crashed: bool,
    pub active: bool,
    pub is_tor: bool,
    pub is_private: bool,
    pub favicon: String,
    pub internal: Option<String>,
    pub zoom: f64,
}

struct ClosedTab {
    url: String,
}

#[derive(Default)]
pub struct TabManager {
    tabs: Vec<Tab>,
    /// Active tab per window label.
    active: std::collections::HashMap<String, u32>,
    next_id: u32,
    closed: Vec<ClosedTab>,
}

thread_local! {
    static MANAGER: RefCell<TabManager> = RefCell::new(TabManager::default());
}

/// Run `f` with the tab manager. Main thread only.
pub fn with_manager<R>(f: impl FnOnce(&mut TabManager) -> R) -> R {
    MANAGER.with(|m| f(&mut m.borrow_mut()))
}

/// Run a closure on the main thread from any thread and wait for its result.
pub fn on_main_thread<R: Send + 'static>(
    app: &AppHandle,
    f: impl FnOnce() -> R + Send + 'static,
) -> Result<R, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = tx.send(f());
    })
    .map_err(|e| format!("run_on_main_thread: {e}"))?;
    rx.recv_timeout(Duration::from_secs(10))
        .map_err(|e| format!("main thread reply: {e}"))
}

impl TabManager {
    pub fn allocate_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    pub fn insert(&mut self, tab: Tab) {
        self.tabs.push(tab);
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Tab> {
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    /// Active tab id for a window.
    pub fn active_id(&self, window: &str) -> Option<u32> {
        self.active.get(window).copied()
    }

    pub fn window_of(&self, id: u32) -> Option<String> {
        self.tabs.iter().find(|t| t.id == id).map(|t| t.window.clone())
    }

    pub fn remove(&mut self, id: u32) -> Option<Tab> {
        let idx = self.tabs.iter().position(|t| t.id == id)?;
        let win = self.tabs[idx].window.clone();
        // Window-local position of the tab being closed, so we can activate
        // its neighbor (not always the first tab — that was the "⌘W jumps to
        // tab 1" bug).
        let local_pos = self.tabs[..idx].iter().filter(|t| t.window == win).count();
        let tab = self.tabs.remove(idx);
        unregister_browser_window(tab.browser_id);
        if !tab.url.is_empty() && tab.url != "about:blank" {
            self.closed.push(ClosedTab { url: tab.url.clone() });
        }
        // If the closed tab was active, activate the tab that slid into its
        // slot (the one to the right), or the new last tab if it was last.
        if self.active.get(&win) == Some(&id) {
            let remaining: Vec<u32> = self
                .tabs
                .iter()
                .filter(|t| t.window == win)
                .map(|t| t.id)
                .collect();
            match remaining.get(local_pos).or_else(|| remaining.last()) {
                Some(&n) => {
                    self.active.insert(win, n);
                }
                None => {
                    self.active.remove(&win);
                }
            }
        }
        Some(tab)
    }

    pub fn pop_closed_url(&mut self) -> Option<String> {
        self.closed.pop().map(|c| c.url)
    }

    /// Tab list for one window.
    pub fn infos(&self, window: &str) -> Vec<TabInfo> {
        let active = self.active.get(window).copied();
        self.tabs
            .iter()
            .filter(|t| t.window == window)
            .map(|t| TabInfo {
                id: t.id,
                url: t.url.clone(),
                title: t.title.clone(),
                loading: t.loading,
                can_back: t.can_back,
                can_forward: t.can_forward,
                crashed: t.crashed,
                active: active == Some(t.id),
                is_tor: t.is_tor,
                is_private: t.is_private,
                favicon: t.favicon.clone(),
                internal: t.internal.clone(),
                zoom: t.zoom,
            })
            .collect()
    }

    /// Move a tab to `to_index` within its own window's tab order.
    pub fn move_tab(&mut self, id: u32, to_index: usize) {
        let Some(from) = self.tabs.iter().position(|t| t.id == id) else {
            return;
        };
        let window = self.tabs[from].window.clone();
        let tab = self.tabs.remove(from);
        // Global index of the window's to_index-th tab (or end of window run).
        let mut seen = 0usize;
        let mut insert_at = self.tabs.len();
        for (i, t) in self.tabs.iter().enumerate() {
            if t.window == window {
                if seen == to_index {
                    insert_at = i;
                    break;
                }
                seen += 1;
                insert_at = i + 1;
            }
        }
        self.tabs.insert(insert_at, tab);
    }

    /// First tab id in a window whose internal page is `page`, if open.
    pub fn find_internal(&self, window: &str, page: &str) -> Option<u32> {
        self.tabs
            .iter()
            .find(|t| t.window == window && t.internal.as_deref() == Some(page))
            .map(|t| t.id)
    }

}

/// Emit a window's tab list to its shell UI. Main thread only.
/// Targeted emit: `Emitter::emit` broadcasts to every webview (all windows),
/// which made every shell render the last window's tab list — a private
/// window opening turned the normal window "private". `emit_to` + the shell's
/// window-scoped listener keep each window's state its own.
pub fn emit_tabs_changed(app: &AppHandle, window: &str) {
    let infos = with_manager(|m| m.infos(window));
    let _ = app.emit_to(window, "tabs-changed", infos);
}

/// browser id -> window label, readable from ANY thread (CEF resource
/// handlers run on the IO thread, where the thread_local manager is empty).
static BROWSER_WINDOWS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<i32, String>>,
> = std::sync::LazyLock::new(Default::default);

pub fn register_browser_window(browser_id: i32, window: &str) {
    if browser_id != 0 {
        BROWSER_WINDOWS
            .lock()
            .unwrap()
            .insert(browser_id, window.to_string());
    }
}

fn unregister_browser_window(browser_id: i32) {
    if browser_id != 0 {
        BROWSER_WINDOWS.lock().unwrap().remove(&browser_id);
    }
}

/// Emit an event only to the shell of the window owning `browser_id`, falling
/// back to a broadcast when the browser isn't a tracked tab (e.g. sandbox).
/// Safe from any thread.
pub fn emit_to_browser_window<S: serde::Serialize + Clone>(
    app: &AppHandle,
    browser_id: i32,
    event: &str,
    payload: S,
) {
    let win = BROWSER_WINDOWS.lock().unwrap().get(&browser_id).cloned();
    match win {
        Some(win) => {
            let _ = app.emit_to(win.as_str(), event, payload);
        }
        None => {
            let _ = app.emit(event, payload);
        }
    }
}

/// Remove every tab belonging to `window` (the native window was closed) and
/// close their CEF browsers. Without this, closing a window leaked its
/// browsers as children of a dead native window — the next CEF call touching
/// them crashed the app. Main thread only.
pub fn close_window_tabs(window: &str) {
    let removed: Vec<Option<cef::Browser>> = with_manager(|m| {
        let mut taken = Vec::new();
        let mut i = 0;
        while i < m.tabs.len() {
            if m.tabs[i].window == window {
                let tab = m.tabs.remove(i);
                unregister_browser_window(tab.browser_id);
                taken.push(tab.browser);
            } else {
                i += 1;
            }
        }
        m.active.remove(window);
        taken
    });
    for browser in removed.into_iter().flatten() {
        use cef::{ImplBrowser, ImplBrowserHost};
        if let Some(host) = browser.host() {
            host.close_browser(1);
        }
    }
}

/// Find (tab id, window) owning a CEF browser. No CEF calls.
pub fn tab_for_browser(browser_id: i32) -> Option<(u32, String)> {
    with_manager(|m| {
        m.tabs
            .iter()
            .find(|t| t.browser_id == browser_id)
            .map(|t| (t.id, t.window.clone()))
    })
}

/// Clone a tab's browser handle out of the manager so CEF can be called
/// without holding the RefCell borrow. None for internal tabs.
pub fn browser_for_tab(id: u32) -> Option<cef::Browser> {
    with_manager(|m| m.get_mut(id).and_then(|t| t.browser.clone()))
}

/// Show only the given tab's CEF view within its window; hide that window's
/// other tabs. If the active tab is an internal (shell-rendered) page, every
/// CEF view in the window is hidden. Main thread only.
pub fn show_only(active_id: u32) {
    let Some(win) = with_manager(|m| m.window_of(active_id)) else { return };
    let browsers: Vec<(u32, Option<cef::Browser>)> = with_manager(|m| {
        m.tabs
            .iter()
            .filter(|t| t.window == win)
            .map(|t| (t.id, t.browser.clone()))
            .collect()
    });
    with_manager(|m| {
        m.active.insert(win.clone(), active_id);
    });
    for (id, browser) in browsers {
        let Some(browser) = browser else { continue };
        let Some(host) = browser.host() else { continue };
        // Switching tabs hands keyboard focus to the newly shown page;
        // overlay show/hide (set_content_hidden) deliberately does not.
        crate::platform::set_view_hidden_focus(&host, id != active_id, id == active_id);
    }
}

/// Hide/show a window's active-tab CEF view so shell overlays can cover it.
pub fn set_content_hidden(window: &str, hidden: bool) {
    let active = with_manager(|m| m.active_id(window));
    let Some(active_id) = active else { return };
    let Some(browser) = browser_for_tab(active_id) else { return };
    let Some(host) = browser.host() else { return };
    crate::platform::set_view_hidden(&host, hidden);
}

/// Resolve address bar input into a navigable URL: absolute URLs pass
/// through, bare domains get https://, everything else becomes a search.
pub fn resolve_input(input: &str) -> String {
    let t = input.trim();
    if t.is_empty() {
        return "about:blank".into();
    }
    // Browser meta-schemes pass through verbatim (view page source, internal
    // pages, chrome:// diagnostics).
    if t.starts_with("view-source:")
        || t.starts_with("about:")
        || t.starts_with("chrome://")
        || t.starts_with("vev://")
        || t.starts_with("data:")
    {
        return t.to_string();
    }
    if let Ok(u) = url::Url::parse(t) {
        if matches!(u.scheme(), "http" | "https" | "file") {
            return u.into();
        }
    }
    if !t.contains(char::is_whitespace) && t.contains('.') {
        if let Ok(u) = url::Url::parse(&format!("https://{t}")) {
            return u.into();
        }
    }
    let q: String =
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("q", t)
            .finish();
    format!("https://duckduckgo.com/?{q}")
}

/// Navigate a tab that already has a CEF browser. Main thread only.
/// (Internal tabs get a browser first — see `commands::nav_navigate`.)
pub fn navigate(id: u32, url: &str) {
    let browser = with_manager(|m| {
        m.get_mut(id).and_then(|tab| {
            if tab.crashed {
                // A fresh navigation revives the renderer process.
                tab.crashed = false;
            }
            tab.browser.clone()
        })
    });
    // load_url outside the borrow: it can synchronously fire handlers.
    if let Some(browser) = browser {
        if let Some(frame) = browser.main_frame() {
            frame.load_url(Some(&cef::CefString::from(url)));
        }
        // Hand keyboard focus to the page (Enter in the omnibox behaves like
        // other browsers: the loaded page is what you interact with next).
        use cef::ImplBrowserHost;
        if let Some(host) = browser.host() {
            host.set_focus(1);
        }
    }
}
