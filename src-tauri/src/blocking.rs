//! Glue between the CEF request pipeline and the `vev-blocklist` engine:
//! resource-level network blocking, cosmetic CSS injection, and the live
//! threat-feed navigation check.

use cef::{rc::*, *};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use vev_blocklist::Blocklist;

/// The process-wide blocklist. Set once at startup; read from CEF handlers
/// (which run on the main/UI thread) and from tauri commands.
static BLOCKLIST: OnceLock<Arc<Blocklist>> = OnceLock::new();

/// How often to refresh the live threat feed.
const THREAT_REFRESH: Duration = Duration::from_secs(6 * 60 * 60);

pub fn init(data_dir: &std::path::Path) -> Arc<Blocklist> {
    let bl = Arc::new(Blocklist::load(data_dir));
    let _ = BLOCKLIST.set(bl.clone());

    // Refresh the threat + community feeds now and on a schedule, off the UI
    // thread.
    let refresher = bl.clone();
    std::thread::spawn(move || loop {
        match refresher.refresh_threat_feed() {
            Ok(n) => eprintln!("vev-blocklist: threat feed refreshed, {n} hosts"),
            Err(e) => eprintln!("vev-blocklist: threat feed refresh failed: {e}"),
        }
        match refresher.refresh_community_feed() {
            Ok(n) => eprintln!("vev-blocklist: community feed refreshed, {n} hosts"),
            Err(e) => eprintln!("vev-blocklist: community feed refresh failed: {e}"),
        }
        std::thread::sleep(THREAT_REFRESH);
    });

    bl
}

/// Community-confirmed phishing status for a URL (percent + report count).
pub fn community_flag(url: &str) -> Option<vev_blocklist::HostFlag> {
    get().and_then(|bl| bl.community_flag(url))
}

pub fn get() -> Option<Arc<Blocklist>> {
    BLOCKLIST.get().cloned()
}

/// Map a CEF resource type to adblock-rust's request-type vocabulary.
fn adblock_type(rt: ResourceType) -> &'static str {
    match rt {
        ResourceType::MAIN_FRAME => "document",
        ResourceType::SUB_FRAME => "sub_frame",
        ResourceType::STYLESHEET => "stylesheet",
        ResourceType::SCRIPT => "script",
        ResourceType::IMAGE | ResourceType::FAVICON => "image",
        ResourceType::FONT_RESOURCE => "font",
        ResourceType::OBJECT | ResourceType::PLUGIN_RESOURCE => "object",
        ResourceType::MEDIA => "media",
        ResourceType::XHR => "xmlhttprequest",
        ResourceType::PING | ResourceType::CSP_REPORT => "ping",
        ResourceType::WORKER
        | ResourceType::SHARED_WORKER
        | ResourceType::SERVICE_WORKER => "script",
        _ => "other",
    }
}

wrap_resource_request_handler! {
    struct VevResourceRequestHandler;

    impl ResourceRequestHandler {
        fn on_before_resource_load(
            &self,
            browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            request: Option<&mut Request>,
            _callback: Option<&mut Callback>,
        ) -> ReturnValue {
            let browser_id = browser.map(|b| {
                use cef::ImplBrowser;
                b.identifier()
            }).unwrap_or(0);
            let Some(request) = request else {
                return ReturnValue::CONTINUE;
            };
            let Some(bl) = get() else {
                return ReturnValue::CONTINUE;
            };

            let url = CefString::from(&request.url()).to_string();
            // Source (first-party) URL: the document the request comes from.
            let source = frame
                .and_then(|f| {
                    let u = CefString::from(&f.url()).to_string();
                    if u.is_empty() { None } else { Some(u) }
                })
                .unwrap_or_default();
            let rtype = adblock_type(request.resource_type());

            let decision = bl.check(&url, &source, rtype);
            if decision.blocked {
                eprintln!("vev-blocklist: BLOCK [{}] {rtype} {url}", decision.reason);
                emit_blocked(browser_id, &url, rtype, decision.reason);
                return ReturnValue::CANCEL;
            }
            ReturnValue::CONTINUE
        }
    }
}

/// Build the resource request handler CEF asks for on each request.
pub fn make_resource_request_handler() -> ResourceRequestHandler {
    VevResourceRequestHandler::new()
}

/// Emit a `resource-blocked` event so the shell's Huma island can show what
/// was blocked (host + kind) with an Allow action. Deduped per host in the
/// shell; here we just forward the registrable host so the UI stays readable.
/// Scoped to the window owning the browser (runs on the CEF IO thread, so it
/// uses the thread-safe browser->window map, never the tab manager).
fn emit_blocked(browser_id: i32, url: &str, rtype: &str, reason: &str) {
    let Some(app) = crate::cef_engine::app_handle() else { return };
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| url.to_string());
    crate::tabs::emit_to_browser_window(
        &app,
        browser_id,
        "resource-blocked",
        serde_json::json!({ "host": host, "kind": rtype, "reason": reason }),
    );
}

/// Cosmetic filtering: inject element-hiding CSS for `page_url` into `frame`.
/// Called on load end of the main frame.
pub fn inject_cosmetic_css(frame: &mut Frame, page_url: &str) {
    use cef::ImplFrame;
    let Some(bl) = get() else { return };
    let css = bl.cosmetic_css(page_url);
    if css.is_empty() {
        return;
    }
    // Escape for a JS string literal, then insert a <style> element.
    let escaped = css.replace('\\', "\\\\").replace('`', "\\`");
    let js = format!(
        "(function(){{try{{var s=document.createElement('style');\
         s.setAttribute('data-vev','cosmetic');s.textContent=`{escaped}`;\
         (document.head||document.documentElement).appendChild(s);}}catch(e){{}}}})();"
    );
    frame.execute_java_script(
        Some(&CefString::from(js.as_str())),
        Some(&CefString::from("vev://cosmetic")),
        0,
    );
}

/// Inject the YouTube ad-skip scriptlet if `page_url` is a YouTube page.
/// Network blocking cannot remove YouTube's in-player ads (muxed with the
/// video), so this runs in the page to skip them.
pub fn inject_youtube_adblock(frame: &mut Frame, page_url: &str) {
    use cef::ImplFrame;
    if !vev_blocklist::is_youtube(page_url) {
        return;
    }
    frame.execute_java_script(
        Some(&CefString::from(vev_blocklist::YOUTUBE_SCRIPT)),
        Some(&CefString::from("vev://youtube-adblock")),
        0,
    );
}

/// True if navigating to `url` should be blocked as a known threat.
pub fn is_threat(url: &str) -> bool {
    get().map(|bl| bl.is_threat(url)).unwrap_or(false)
}

/// A minimal interstitial shown in place of a blocked threat navigation.
pub fn threat_block_page(url: &str) -> String {
    let safe = url.replace('<', "&lt;").replace('&', "&amp;");
    format!(
        "data:text/html,<html><body style='font:16px system-ui;background:%23300;\
         color:%23fff;padding:40px'><h1>&#9888; Blocked by Vev</h1>\
         <p>The site <b>{safe}</b> is on a phishing/malware threat feed and was \
         blocked before loading.</p></body></html>"
    )
}
