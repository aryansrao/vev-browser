//! Native right-click context menu for web content, built on CEF's
//! ContextMenuHandler. Adds Vev actions (open link in a new / private tab,
//! copy link, search the selection with the configured engine) on top of the
//! standard navigation items.

use cef::{rc::*, *};
use tauri::AppHandle;

// Custom command IDs must be >= MENU_ID_USER_FIRST (26500).
const ID_OPEN_NEW_TAB: i32 = 26500;
const ID_OPEN_PRIVATE: i32 = 26501;
const ID_COPY_LINK: i32 = 26502;
const ID_SEARCH_SEL: i32 = 26503;
const ID_BACK: i32 = 26504;
const ID_FORWARD: i32 = 26505;
const ID_RELOAD: i32 = 26506;
const ID_VIEW_SOURCE: i32 = 26507;

fn s(v: cef::CefStringUserfree) -> String {
    CefString::from(&v).to_string()
}

wrap_context_menu_handler! {
    struct VevContextMenuHandler {
        app_handle: AppHandle,
    }

    impl ContextMenuHandler {
        fn on_before_context_menu(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            params: Option<&mut ContextMenuParams>,
            model: Option<&mut MenuModel>,
        ) {
            use cef::{ImplContextMenuParams, ImplMenuModel};
            let (Some(params), Some(model)) = (params, model) else { return };
            // Replace Chromium's default menu with Vev's.
            model.clear();

            let link = s(params.link_url());
            let selection = s(params.selection_text());

            if !link.is_empty() {
                model.add_item(ID_OPEN_NEW_TAB, Some(&CefString::from("Open link in new tab")));
                model.add_item(ID_OPEN_PRIVATE, Some(&CefString::from("Open link in new private tab")));
                model.add_item(ID_COPY_LINK, Some(&CefString::from("Copy link address")));
                model.add_separator();
            }
            if !selection.is_empty() {
                let short: String = selection.chars().take(24).collect();
                model.add_item(
                    ID_SEARCH_SEL,
                    Some(&CefString::from(format!("Search for \u{201c}{short}\u{201d}").as_str())),
                );
                model.add_separator();
            }
            model.add_item(ID_BACK, Some(&CefString::from("Back")));
            model.add_item(ID_FORWARD, Some(&CefString::from("Forward")));
            model.add_item(ID_RELOAD, Some(&CefString::from("Reload")));
            model.add_separator();
            model.add_item(ID_VIEW_SOURCE, Some(&CefString::from("View page source")));
        }

        fn on_context_menu_command(
            &self,
            browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            params: Option<&mut ContextMenuParams>,
            command_id: ::std::os::raw::c_int,
            _event_flags: EventFlags,
        ) -> ::std::os::raw::c_int {
            use cef::{ImplBrowser, ImplContextMenuParams};
            let Some(params) = params else { return 0 };
            let link = s(params.link_url());
            let selection = s(params.selection_text());
            let page = s(params.page_url());
            // Which window this browser belongs to (new tabs open there).
            let window = browser
                .as_ref()
                .and_then(|b| crate::tabs::tab_for_browser(b.identifier()))
                .map(|(_, w)| w)
                .unwrap_or_else(|| "main".to_string());

            match command_id {
                ID_OPEN_NEW_TAB if !link.is_empty() => {
                    let _ = crate::commands::create_tab_inner(&self.app_handle, &window, link, None, false);
                    1
                }
                ID_OPEN_PRIVATE if !link.is_empty() => {
                    // Private tabs only live in private windows: a "private"
                    // tab inside a normal window shared its session with the
                    // normal tabs and confused the whole window's state.
                    let _ = crate::open_window(&self.app_handle, true, Some(link));
                    1
                }
                ID_COPY_LINK if !link.is_empty() => {
                    set_clipboard(&link);
                    1
                }
                ID_SEARCH_SEL if !selection.is_empty() => {
                    let tmpl = crate::startpage::search_template();
                    let q: String = url::form_urlencoded::byte_serialize(selection.as_bytes()).collect();
                    let url = tmpl.replace("{q}", &q);
                    let _ = crate::commands::create_tab_inner(&self.app_handle, &window, url, None, false);
                    1
                }
                ID_BACK => {
                    if let Some(b) = browser { b.go_back(); }
                    1
                }
                ID_FORWARD => {
                    if let Some(b) = browser { b.go_forward(); }
                    1
                }
                ID_RELOAD => {
                    if let Some(b) = browser { b.reload(); }
                    1
                }
                ID_VIEW_SOURCE if !page.is_empty() => {
                    if let Some(frame) = browser.and_then(|b| b.main_frame()) {
                        use cef::ImplFrame;
                        frame.load_url(Some(&CefString::from(format!("view-source:{page}").as_str())));
                    }
                    1
                }
                _ => 0,
            }
        }
    }
}

pub fn make_handler(app_handle: &AppHandle) -> ContextMenuHandler {
    VevContextMenuHandler::new(app_handle.clone())
}

/// Write text to the macOS system pasteboard.
#[cfg(target_os = "macos")]
fn set_clipboard(text: &str) {
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::NSString;
    autoreleasepool(|_| {
        // SAFETY: main/UI thread; standard AppKit pasteboard access.
        unsafe {
            let pb = NSPasteboard::generalPasteboard();
            pb.clearContents();
            let ns = NSString::from_str(text);
            let _ = pb.setString_forType(&ns, objc2_app_kit::NSPasteboardTypeString);
        }
    });
}

#[cfg(not(target_os = "macos"))]
fn set_clipboard(_text: &str) {}
