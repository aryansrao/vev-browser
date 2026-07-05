//! Cross-platform window embedding for the CEF child view.
//!
//! Vev draws its chrome in a system webview and embeds each tab's CEF browser
//! as a native child of the window, below the chrome. The native handle and
//! the show/hide/detach operations differ per OS; this module isolates them so
//! the rest of the browser is platform-agnostic.
//!
//! macOS is the verified path. Windows (HWND) and Linux (X11) are implemented
//! here and built in CI, but need on-hardware runtime verification.

use cef::{ImplBrowserHost, Rect, RuntimeStyle, WindowInfo};
use tauri::WebviewWindow;

/// Height (logical px) reserved at the top for the shell chrome. Mirrors
/// `tabs::TOOLBAR_HEIGHT`.
use crate::tabs::TOOLBAR_HEIGHT;

/// Build the `WindowInfo` to embed a CEF browser as a child of `window`,
/// sized to fill it below the chrome.
pub fn child_window_info(window: &WebviewWindow) -> Result<WindowInfo, String> {
    let bounds = content_bounds(window)?;
    let parent = parent_handle(window)?;
    // Alloy runtime style: a Chrome-style browser cannot be embedded as a
    // native child view (it needs CEF's Views framework or its own window);
    // with the default style the view attaches but never paints.
    Ok(WindowInfo {
        runtime_style: RuntimeStyle::ALLOY,
        ..Default::default()
    }
    .set_as_child(parent, &bounds))
}

// ===================== macOS =====================
#[cfg(target_os = "macos")]
fn parent_handle(window: &WebviewWindow) -> Result<cef::sys::cef_window_handle_t, String> {
    let ns_view = window
        .ns_view()
        .map_err(|e| format!("cannot get NSView of window: {e}"))?;
    Ok(ns_view.cast())
}

#[cfg(target_os = "macos")]
fn content_bounds(window: &WebviewWindow) -> Result<Rect, String> {
    use objc2_app_kit::NSView;
    let ns_view = window.ns_view().map_err(|e| e.to_string())?;
    let view_ptr = ns_view.cast::<NSView>();
    if view_ptr.is_null() {
        return Err("window NSView is null".into());
    }
    // tao lays the shell webview over the FULL content view; the chrome is a
    // fixed band from the top, so the CEF view fills from the bottom up to
    // (full content height - TOOLBAR_HEIGHT).
    // SAFETY: main thread; pointer is the live content view of `window`.
    unsafe {
        let content = (*view_ptr).frame().size;
        Ok(Rect {
            x: 0,
            y: 0,
            width: content.width as i32,
            height: (content.height - TOOLBAR_HEIGHT).max(0.0) as i32,
        })
    }
}

#[cfg(target_os = "macos")]
pub fn set_view_hidden(host: &cef::BrowserHost, hidden: bool) {
    set_view_hidden_focus(host, hidden, false);
}

/// Like `set_view_hidden`, optionally giving the CEF view keyboard focus when
/// shown. Focus must be explicit: unconditionally grabbing it on every unhide
/// stole the keyboard from the shell's address bar mid-typing (every
/// suggestion-close re-showed the view and re-focused the page).
#[cfg(target_os = "macos")]
pub fn set_view_hidden_focus(host: &cef::BrowserHost, hidden: bool, focus: bool) {
    use objc2_app_kit::NSView;
    let view_ptr = host.window_handle().cast::<NSView>();
    if !view_ptr.is_null() {
        // SAFETY: main thread; live browser NSView.
        unsafe { (*view_ptr).setHidden(hidden) };
    }
    host.was_hidden(hidden as _);
    if !hidden && focus {
        host.set_focus(true as _);
    }
}

/// Move keyboard focus to the shell webview (the WKWebView hosting the
/// chrome). Clicking the omnibox doesn't reliably take first-responder away
/// from the CEF child view, which left the address bar caret visible but the
/// keystrokes going to the page.
#[cfg(target_os = "macos")]
pub fn focus_shell(window: &WebviewWindow) {
    use objc2::runtime::AnyClass;
    use objc2::runtime::NSObjectProtocol as _;
    use objc2_app_kit::NSView;
    let Ok(ns_view) = window.ns_view() else { return };
    let content = ns_view.cast::<NSView>();
    if content.is_null() {
        return;
    }
    let Some(wk_class) = AnyClass::get(c"WKWebView") else { return };
    // SAFETY: main thread; live content view of `window`.
    unsafe {
        fn find_wk(
            view: &objc2_app_kit::NSView,
            wk_class: &objc2::runtime::AnyClass,
        ) -> Option<objc2::rc::Retained<objc2_app_kit::NSView>> {
            for sub in view.subviews().iter() {
                if sub.isKindOfClass(wk_class) {
                    return Some(sub);
                }
                if let Some(found) = find_wk(&sub, wk_class) {
                    return Some(found);
                }
            }
            None
        }
        let Some(ns_window) = (*content).window() else { return };
        if let Some(wk) = find_wk(&*content, wk_class) {
            ns_window.makeFirstResponder(Some(&wk));
        }
    }
}

#[cfg(target_os = "macos")]
pub fn detach_view(host: &cef::BrowserHost) {
    use objc2_app_kit::NSView;
    let view_ptr = host.window_handle().cast::<NSView>();
    if !view_ptr.is_null() {
        // SAFETY: main thread; live browser NSView.
        unsafe { (*view_ptr).removeFromSuperview() };
    }
}

#[cfg(target_os = "macos")]
pub fn pin_view(host: &cef::BrowserHost) {
    use objc2_app_kit::{NSAutoresizingMaskOptions, NSView};
    let view_ptr = host.window_handle().cast::<NSView>();
    if view_ptr.is_null() {
        return;
    }
    // SAFETY: CEF UI thread (== process main thread); live browser NSView.
    unsafe {
        (*view_ptr).setAutoresizingMask(
            NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewHeightSizable,
        );
    }
}

// ===================== Windows =====================
#[cfg(target_os = "windows")]
fn parent_handle(window: &WebviewWindow) -> Result<cef::sys::cef_window_handle_t, String> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match window.window_handle().map_err(|e| e.to_string())?.as_raw() {
        // cef_window_handle_t on Windows is HWND(*mut HWND__).
        RawWindowHandle::Win32(h) => Ok(cef::sys::HWND(h.hwnd.get() as *mut _)),
        _ => Err("expected a Win32 window handle".into()),
    }
}

#[cfg(target_os = "windows")]
fn content_bounds(window: &WebviewWindow) -> Result<Rect, String> {
    let sz = window.inner_size().map_err(|e| e.to_string())?;
    let scale = window.scale_factor().unwrap_or(1.0);
    let toolbar = (TOOLBAR_HEIGHT * scale) as i32;
    Ok(Rect {
        x: 0,
        y: 0,
        width: sz.width as i32,
        height: (sz.height as i32 - toolbar).max(0),
    })
}

#[cfg(target_os = "windows")]
fn hwnd(host: &cef::BrowserHost) -> windows::Win32::Foundation::HWND {
    // cef's HWND is a newtype over *mut HWND__; unwrap to the raw pointer for
    // the windows-crate HWND(*mut c_void).
    windows::Win32::Foundation::HWND(host.window_handle().0 as *mut _)
}

#[cfg(target_os = "windows")]
pub fn set_view_hidden(host: &cef::BrowserHost, hidden: bool) {
    set_view_hidden_focus(host, hidden, false);
}

#[cfg(target_os = "windows")]
pub fn set_view_hidden_focus(host: &cef::BrowserHost, hidden: bool, focus: bool) {
    use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE, SW_SHOW};
    // SAFETY: FFI to Win32 with the browser's live child HWND.
    unsafe { let _ = ShowWindow(hwnd(host), if hidden { SW_HIDE } else { SW_SHOW }); }
    host.was_hidden(hidden as _);
    if !hidden && focus {
        host.set_focus(true as _);
    }
}

/// No-op outside macOS: tao routes keyboard focus normally there.
#[cfg(target_os = "windows")]
pub fn focus_shell(_window: &WebviewWindow) {}

#[cfg(target_os = "windows")]
pub fn detach_view(host: &cef::BrowserHost) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::SetParent;
    // Reparent to the desktop so closing the tab's browser doesn't destroy the
    // host window. SAFETY: FFI with the live child HWND.
    unsafe { let _ = SetParent(hwnd(host), HWND(std::ptr::null_mut())); }
}

#[cfg(target_os = "windows")]
pub fn pin_view(_host: &cef::BrowserHost) {
    // Windows child windows don't auto-resize; the resize handler in the
    // event loop repositions them (see cef_engine window resize wiring).
}

// ===================== Linux (X11) =====================
#[cfg(target_os = "linux")]
fn parent_handle(window: &WebviewWindow) -> Result<cef::sys::cef_window_handle_t, String> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match window.window_handle().map_err(|e| e.to_string())?.as_raw() {
        RawWindowHandle::Xlib(h) => Ok(h.window as cef::sys::cef_window_handle_t),
        RawWindowHandle::Xcb(h) => Ok(u32::from(h.window) as cef::sys::cef_window_handle_t),
        _ => Err("CEF child embedding needs X11 (Wayland is not supported)".into()),
    }
}

#[cfg(target_os = "linux")]
fn content_bounds(window: &WebviewWindow) -> Result<Rect, String> {
    let sz = window.inner_size().map_err(|e| e.to_string())?;
    let scale = window.scale_factor().unwrap_or(1.0);
    let toolbar = (TOOLBAR_HEIGHT * scale) as i32;
    Ok(Rect {
        x: 0,
        y: 0,
        width: sz.width as i32,
        height: (sz.height as i32 - toolbar).max(0),
    })
}

#[cfg(target_os = "linux")]
mod x11state {
    use std::sync::OnceLock;
    pub static DISPLAY: OnceLock<usize> = OnceLock::new();
    /// Cache the X display pointer (as usize for Send) from a window.
    pub fn set_display(ptr: *mut std::ffi::c_void) {
        let _ = DISPLAY.set(ptr as usize);
    }
    pub fn display() -> Option<*mut std::ffi::c_void> {
        DISPLAY.get().map(|p| *p as *mut std::ffi::c_void)
    }
}

/// Cache the X11 display for later show/hide calls. Called once with the main
/// window on Linux; a no-op elsewhere.
#[cfg(target_os = "linux")]
pub fn cache_display(window: &WebviewWindow) {
    use raw_window_handle::{HasDisplayHandle, RawDisplayHandle};
    if let Ok(h) = window.display_handle() {
        if let RawDisplayHandle::Xlib(d) = h.as_raw() {
            if let Some(p) = d.display {
                x11state::set_display(p.as_ptr());
            }
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub fn cache_display(_window: &WebviewWindow) {}

#[cfg(target_os = "linux")]
fn xlib() -> Option<x11_dl::xlib::Xlib> {
    x11_dl::xlib::Xlib::open().ok()
}

#[cfg(target_os = "linux")]
pub fn set_view_hidden(host: &cef::BrowserHost, hidden: bool) {
    set_view_hidden_focus(host, hidden, false);
}

#[cfg(target_os = "linux")]
pub fn set_view_hidden_focus(host: &cef::BrowserHost, hidden: bool, focus: bool) {
    if let (Some(xlib), Some(display)) = (xlib(), x11state::display()) {
        let win = host.window_handle() as std::os::raw::c_ulong;
        // SAFETY: FFI to Xlib with the cached display and the browser's child
        // X window.
        unsafe {
            if hidden {
                (xlib.XUnmapWindow)(display as *mut _, win);
            } else {
                (xlib.XMapWindow)(display as *mut _, win);
            }
            (xlib.XFlush)(display as *mut _);
        }
    }
    host.was_hidden(hidden as _);
    if !hidden && focus {
        host.set_focus(true as _);
    }
}

/// No-op outside macOS: tao routes keyboard focus normally there.
#[cfg(target_os = "linux")]
pub fn focus_shell(_window: &WebviewWindow) {}

#[cfg(target_os = "linux")]
pub fn detach_view(host: &cef::BrowserHost) {
    // Unmap so the child stops rendering; CEF then finalizes the browser.
    if let (Some(xlib), Some(display)) = (xlib(), x11state::display()) {
        let win = host.window_handle() as std::os::raw::c_ulong;
        // SAFETY: FFI to Xlib with the cached display + child window.
        unsafe {
            (xlib.XUnmapWindow)(display as *mut _, win);
            (xlib.XFlush)(display as *mut _);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn pin_view(_host: &cef::BrowserHost) {
    // X11 child windows are repositioned by the resize handler.
}
