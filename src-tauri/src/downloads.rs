//! Download manager (IDM-style): pause/resume/cancel + live progress on top
//! of CEF's Chromium download engine (which handles the actual high-speed,
//! multi-connection transfer). State lives on the main/UI thread because the
//! CEF download callbacks are only valid there.

use cef::{rc::*, *};
use serde::Serialize;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use tauri::{AppHandle, Emitter};

#[derive(Clone, Serialize)]
pub struct DownloadInfo {
    pub id: u32,
    pub url: String,
    pub file_name: String,
    pub full_path: String,
    pub received: i64,
    pub total: i64,
    pub percent: i32,
    pub speed: i64,
    pub state: &'static str, // "in_progress" | "paused" | "complete" | "canceled"
    /// True if this is a media file that could be streamed instead
    /// (powers the "Watch online" offer — Phase 7 sandbox scope).
    pub is_media: bool,
    pub mime: String,
    /// Unix seconds when the download finished (for "Downloaded 2m ago").
    pub completed_unix: Option<u64>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Size of a finished file on disk, for the completed-row display.
fn file_size(path: &str) -> i64 {
    std::fs::metadata(path).map(|m| m.len() as i64).unwrap_or(0)
}

fn is_media_mime(mime: &str) -> bool {
    mime.starts_with("video/") || mime.starts_with("audio/")
}

/// Ids already routed to the torrent engine, so the completion sniff runs once.
static TORRENT_HANDLED: LazyLock<Mutex<std::collections::HashSet<u32>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

fn handled_torrent(id: u32) -> bool {
    TORRENT_HANDLED.lock().map(|s| s.contains(&id)).unwrap_or(false)
}
fn mark_torrent_handled(id: u32) {
    if let Ok(mut s) = TORRENT_HANDLED.lock() {
        s.insert(id);
    }
}

/// True if `path` is a bencoded `.torrent` file. A torrent is a bencode dict
/// (`d…e`) whose top level contains `info` and usually `announce`; we look for
/// the tell-tale keys so name/mime/URL don't matter. Reads only the head.
fn looks_like_torrent_file(path: &str) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut head = [0u8; 512];
    let n = f.read(&mut head).unwrap_or(0);
    if n == 0 || head[0] != b'd' {
        return false; // bencoded dicts start with 'd'
    }
    let win = &head[..n];
    let has = |needle: &[u8]| win.windows(needle.len()).any(|w| w == needle);
    // "8:announce" (tracker) or the "4:infod" info dict with "piece length".
    has(b"8:announce") || has(b"4:info") || has(b"12:piece length")
}

struct Entry {
    info: DownloadInfo,
    /// Latest callback CEF handed us, used to drive pause/resume/cancel.
    callback: Option<DownloadItemCallback>,
}

thread_local! {
    static DOWNLOADS: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
}

/// Non-CEF downloads (segmented fast + yt-dlp media) live here so they show in
/// the same IDM Downloads list as CEF downloads. They run on worker threads,
/// so this is a plain Mutex (not the CEF-only thread_local above). Each has a
/// cancel flag the worker polls.
struct ManualEntry {
    info: DownloadInfo,
    cancel: Arc<AtomicBool>,
}
static MANUAL: LazyLock<Mutex<Vec<ManualEntry>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Upsert a manual download and broadcast the update to the Downloads UI.
pub fn manual_update(app: &AppHandle, info: DownloadInfo, cancel: Arc<AtomicBool>) {
    if let Ok(mut m) = MANUAL.lock() {
        if let Some(e) = m.iter_mut().find(|e| e.info.id == info.id) {
            e.info = info.clone();
        } else {
            m.push(ManualEntry { info: info.clone(), cancel });
        }
    }
    let _ = app.emit("download-updated", info);
}

/// Allocate a synthetic id for a manual download (above the CEF id space).
pub fn next_manual_id() -> u32 {
    use std::sync::atomic::AtomicU32;
    static NEXT: AtomicU32 = AtomicU32::new(1_000_000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn state_str(item: &DownloadItem) -> &'static str {
    use cef::ImplDownloadItem;
    if item.is_complete() != 0 {
        "complete"
    } else if item.is_canceled() != 0 {
        "canceled"
    } else if item.is_paused() != 0 {
        "paused"
    } else {
        "in_progress"
    }
}

wrap_download_handler! {
    struct VevDownloadHandler {
        app_handle: AppHandle,
    }

    impl DownloadHandler {
        fn can_download(
            &self,
            _browser: Option<&mut Browser>,
            _url: Option<&CefString>,
            _request_method: Option<&CefString>,
        ) -> ::std::os::raw::c_int {
            // Allow all downloads (default is 0 = blocked).
            1
        }

        fn on_before_download(
            &self,
            _browser: Option<&mut Browser>,
            download_item: Option<&mut DownloadItem>,
            suggested_name: Option<&CefString>,
            callback: Option<&mut BeforeDownloadCallback>,
        ) -> ::std::os::raw::c_int {
            use cef::{ImplBeforeDownloadCallback, ImplDownloadItem};
            let Some(callback) = callback else { return 0 };
            let name = suggested_name.map(|s| s.to_string()).unwrap_or_else(|| "download".into());
            // A .torrent file (by name or bittorrent MIME) belongs to the
            // torrent engine, not the file system: hand its URL to librqbit
            // and don't save the .torrent itself. The user gets the actual
            // media, streamed with live progress, in the torrents list.
            let src_url = download_item
                .as_ref()
                .map(|i| CefString::from(&i.url()).to_string())
                .unwrap_or_default();
            let mime = download_item
                .as_ref()
                .map(|i| CefString::from(&i.mime_type()).to_string())
                .unwrap_or_default();
            // Detect torrents broadly: many trackers serve them with a
            // non-.torrent suggested name, a generic octet-stream mime, and a
            // query string on the URL, so also look at the URL path.
            let url_path = src_url.split(['?', '#']).next().unwrap_or(&src_url).to_ascii_lowercase();
            let is_torrent = name.to_ascii_lowercase().ends_with(".torrent")
                || url_path.ends_with(".torrent")
                || mime == "application/x-bittorrent";
            if is_torrent && src_url.starts_with("http") {
                let app = self.app_handle.clone();
                std::thread::spawn(move || {
                    match vev_torrent::add(src_url.clone()) {
                        Ok(_) => {
                            let _ = app.emit("torrent-added", serde_json::json!({ "name": name }));
                        }
                        Err(e) => eprintln!("vev-torrent: add from download failed: {e}"),
                    }
                });
                // Cancel the .torrent file save (empty path cancels the item).
                callback.cont(Some(&CefString::from("")), 0);
                return 1;
            }
            // Save into the user's Downloads dir under the suggested name;
            // no save dialog (show_dialog = 0) — IDM-style silent start.
            let dir = dirs_download_dir();
            let target = dir.join(&name);
            std::fs::create_dir_all(&dir).ok();
            callback.cont(
                Some(&CefString::from(target.to_string_lossy().as_ref())),
                0,
            );
            // Immediate feedback so a download is never silent (the "nothing
            // happened" bug). The shell shows a popup with actions (show in
            // Downloads, and for media: play online / pick another format).
            let _ = self.app_handle.emit(
                "download-started",
                serde_json::json!({
                    "name": name,
                    "path": target.to_string_lossy(),
                    "dir": dir.to_string_lossy(),
                }),
            );
            1
        }

        fn on_download_updated(
            &self,
            _browser: Option<&mut Browser>,
            download_item: Option<&mut DownloadItem>,
            callback: Option<&mut DownloadItemCallback>,
        ) {
            use cef::ImplDownloadItem;
            let Some(item) = download_item else { return };
            let id = item.id();
            let mime = CefString::from(&item.mime_type()).to_string();
            let st = state_str(item);
            let info = DownloadInfo {
                id,
                url: CefString::from(&item.url()).to_string(),
                file_name: CefString::from(&item.suggested_file_name()).to_string(),
                full_path: CefString::from(&item.full_path()).to_string(),
                received: item.received_bytes(),
                total: item.total_bytes(),
                percent: item.percent_complete(),
                speed: item.current_speed(),
                state: st,
                is_media: is_media_mime(&mime),
                mime,
                completed_unix: (st == "complete").then(now_unix),
            };
            // Content-sniff safety net: some torrent sites serve a .torrent
            // with a movie-title filename and a generic mime, so the name/mime
            // checks in on_before_download miss it and it saves as a file.
            // When ANY download finishes, peek its bytes: if it's a bencoded
            // torrent, hand it to the engine and remove the file. Bulletproof
            // regardless of name/mime/URL.
            if info.state == "complete" && !info.full_path.is_empty() {
                let path = info.full_path.clone();
                if !handled_torrent(id) && looks_like_torrent_file(&path) {
                    mark_torrent_handled(id);
                    let app = self.app_handle.clone();
                    std::thread::spawn(move || {
                        match vev_torrent::add(path.clone()) {
                            Ok(_) => {
                                let name = std::path::Path::new(&path)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| "torrent".into());
                                let _ = std::fs::remove_file(&path);
                                let _ = app.emit("torrent-added", serde_json::json!({ "name": name }));
                            }
                            Err(e) => eprintln!("vev-torrent: sniffed-file add failed: {e}"),
                        }
                    });
                    // Don't surface the .torrent as a finished file download.
                    return;
                }
            }
            DOWNLOADS.with(|d| {
                let mut d = d.borrow_mut();
                if let Some(e) = d.iter_mut().find(|e| e.info.id == id) {
                    e.info = info.clone();
                    e.callback = callback.cloned();
                } else {
                    d.push(Entry {
                        info: info.clone(),
                        callback: callback.cloned(),
                    });
                }
            });
            let _ = self.app_handle.emit("download-updated", info);
        }
    }
}

pub fn make_handler(app_handle: &AppHandle) -> DownloadHandler {
    VevDownloadHandler::new(app_handle.clone())
}

pub fn list() -> Vec<DownloadInfo> {
    // CEF downloads (thread_local, main thread) + manual downloads (Mutex).
    let mut v: Vec<DownloadInfo> =
        DOWNLOADS.with(|d| d.borrow().iter().map(|e| e.info.clone()).collect());
    if let Ok(m) = MANUAL.lock() {
        v.extend(m.iter().map(|e| e.info.clone()));
    }
    v
}

/// Remove a download from the IDM list (both CEF and manual registries). If
/// it's still running it's canceled first. The file on disk is left alone.
/// Main thread only (touches the CEF thread_local).
pub fn remove_entry(id: u32) {
    // Cancel an in-flight manual download so its worker stops.
    if id >= 1_000_000 {
        if let Ok(m) = MANUAL.lock() {
            if let Some(e) = m.iter().find(|e| e.info.id == id) {
                e.cancel.store(true, Ordering::Relaxed);
            }
        }
    }
    DOWNLOADS.with(|d| {
        let mut d = d.borrow_mut();
        if let Some(pos) = d.iter().position(|e| e.info.id == id) {
            use cef::ImplDownloadItemCallback;
            if d[pos].info.state == "in_progress" || d[pos].info.state == "paused" {
                if let Some(cb) = &d[pos].callback {
                    cb.cancel();
                }
            }
            d.remove(pos);
        }
    });
    if let Ok(mut m) = MANUAL.lock() {
        m.retain(|e| e.info.id != id);
    }
}

/// Apply a control action to a download by id. Main thread only.
pub fn control(id: u32, action: &str) {
    use cef::ImplDownloadItemCallback;
    // Manual downloads: only cancel is supported (a yt-dlp/segmented worker
    // can't pause mid-flight). The worker polls this flag and stops.
    if id >= 1_000_000 {
        if let Ok(m) = MANUAL.lock() {
            if let Some(e) = m.iter().find(|e| e.info.id == id) {
                if action == "cancel" {
                    e.cancel.store(true, Ordering::Relaxed);
                }
            }
        }
        return;
    }
    DOWNLOADS.with(|d| {
        if let Some(e) = d.borrow().iter().find(|e| e.info.id == id) {
            if let Some(cb) = &e.callback {
                match action {
                    "pause" => cb.pause(),
                    "resume" => cb.resume(),
                    "cancel" => cb.cancel(),
                    _ => {}
                }
            }
        }
    });
}

/// Start a segmented high-speed download (parallel range requests) off the
/// main thread, showing in the IDM list like any other download. `dest_dir`
/// overrides the default (~/Downloads) when the confirmation popup picked a
/// location. Returns the synthetic download id.
pub fn start_fast(app: &AppHandle, url: String, dest_dir: Option<String>) -> u32 {
    let id = next_manual_id();
    let cancel = Arc::new(AtomicBool::new(false));

    let file_name = url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download")
        .split('?')
        .next()
        .unwrap_or("download")
        .to_string();
    let dir = dest_dir.map(std::path::PathBuf::from).unwrap_or_else(dirs_download_dir);
    let dest = dir.join(&file_name);
    std::fs::create_dir_all(dest.parent().unwrap_or(&dest)).ok();

    let app = app.clone();
    let cancel_worker = cancel.clone();
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let progress = std::sync::Arc::new(vev_download::Progress::default());
        let purl = url.clone();
        let pdest = dest.clone();
        let prog2 = progress.clone();
        let worker = std::thread::spawn(move || {
            vev_download::download_into(&purl, &pdest, vev_download::DEFAULT_SEGMENTS, &prog2)
        });

        let is_media = {
            let ext = file_name.rsplit('.').next().unwrap_or("").to_lowercase();
            matches!(ext.as_str(), "mp4" | "webm" | "mkv" | "mov" | "m4v" | "mp3" | "m4a" | "ogg" | "wav")
        };
        loop {
            let received = progress.downloaded.load(Ordering::Relaxed) as i64;
            let total = progress.total.load(Ordering::Relaxed) as i64;
            let done = progress.done.load(Ordering::Relaxed);
            let failed = progress.failed.load(Ordering::Relaxed) || cancel_worker.load(Ordering::Relaxed);
            let secs = started.elapsed().as_secs_f64().max(0.001);
            let full = dest.to_string_lossy().into_owned();
            let recv = if done { file_size(&full).max(received) } else { received };
            let info = DownloadInfo {
                id,
                url: url.clone(),
                file_name: file_name.clone(),
                full_path: full,
                received: recv,
                total: if done { recv } else { total },
                percent: if total > 0 { ((received * 100) / total) as i32 } else { 0 },
                speed: (received as f64 / secs) as i64,
                state: if failed { "canceled" } else if done { "complete" } else { "in_progress" },
                is_media,
                mime: String::new(),
                completed_unix: done.then(now_unix),
            };
            manual_update(&app, info, cancel_worker.clone());
            if done || failed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        let _ = worker.join();
    });
    id
}

pub fn dirs_download_dir() -> std::path::PathBuf {
    // ~/Downloads on macOS/Linux; USERPROFILE\Downloads on Windows.
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        std::path::PathBuf::from(home).join("Downloads")
    } else {
        std::env::temp_dir()
    }
}
