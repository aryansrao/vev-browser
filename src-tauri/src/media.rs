//! App-side glue for `vev-media`: resolve the yt-dlp/ffmpeg tools, probe a
//! page for downloadable formats, run a media download that shows in the IDM
//! Downloads list, and resolve a playable URL for "Play online".

use crate::downloads::{self, DownloadInfo};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use vev_media::Tools;

/// Where managed tool binaries are installed.
fn tools_dir(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("tools")
}

fn tools(app: &AppHandle) -> Tools {
    Tools::resolve(&tools_dir(app))
}

/// Availability of yt-dlp/ffmpeg, for the popup to offer the one-time fetch.
pub fn status(app: &AppHandle) -> vev_media::ToolStatus {
    let dir = tools_dir(app);
    Tools::resolve(&dir).status(&dir)
}

/// Fetch yt-dlp into app-data (one-time). ffmpeg auto-fetch is best-effort and
/// currently not offered — video downloads work without it; mp3/convert asks
/// the user to install ffmpeg.
pub fn fetch_tools(app: &AppHandle) -> Result<vev_media::ToolStatus, String> {
    let dir = tools_dir(app);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    vev_media::fetch::fetch_ytdlp(&dir)?;
    Ok(status(app))
}

/// Probe a page for media info (title, thumbnail, formats), routed through the
/// browser-wide proxy if one is configured.
pub fn probe(app: &AppHandle, url: &str) -> Result<vev_media::MediaInfo, String> {
    let proxy = probe_proxy(app);
    vev_media::probe(&tools(app), url, proxy.as_deref())
}

/// Resolve a directly-playable URL for Play-online.
pub fn resolve_stream(app: &AppHandle, url: &str) -> Result<String, String> {
    let proxy = probe_proxy(app);
    vev_media::resolve_stream_url(&tools(app), url, proxy.as_deref())
}

/// The proxy a media request should use: whatever the browser is browser-wide
/// set to (Tor/custom) so a media fetch matches the user's chosen exit. None
/// when direct. (Distinct from the threat-probe proxy, which prefers Tor.)
fn probe_proxy(app: &AppHandle) -> Option<String> {
    let _ = app;
    let cfg = crate::startpage::load_config();
    match cfg.proxy_mode.as_deref() {
        Some("tor") => crate::tor::default_proxy_addr().map(|a| format!("socks5://{a}")),
        Some("custom") => cfg
            .custom_proxy_url
            .filter(|u| !u.trim().is_empty()),
        _ => None,
    }
}

/// Start a media download via yt-dlp on a worker thread; progress flows into
/// the IDM Downloads list. `format_id` empty + `audio_mp3` true → mp3 extract.
/// Returns the synthetic download id.
pub fn download(
    app: &AppHandle,
    url: String,
    format_id: String,
    audio_mp3: bool,
    dest_dir: Option<String>,
) -> u32 {
    let id = downloads::next_manual_id();
    let cancel = Arc::new(AtomicBool::new(false));
    let dir = dest_dir
        .map(PathBuf::from)
        .unwrap_or_else(downloads::dirs_download_dir);
    let out_template = dir.join("%(title)s.%(ext)s").to_string_lossy().into_owned();
    let proxy = probe_proxy(app);
    let tools = tools(app);
    let app = app.clone();

    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        // Seed the list immediately so the popup's download appears at once.
        let seed = DownloadInfo {
            id,
            url: url.clone(),
            file_name: "Preparing…".into(),
            full_path: dir.to_string_lossy().into_owned(),
            received: 0,
            total: 0,
            percent: 0,
            speed: 0,
            state: "in_progress",
            is_media: true,
            mime: String::new(),
            completed_unix: None,
        };
        downloads::manual_update(&app, seed, cancel.clone());

        let dir_str = dir.to_string_lossy().into_owned();
        let url_for_info = url.clone();
        let cancel_cb = cancel.clone();
        let app_cb = app.clone();
        let result = vev_media::download(
            &tools,
            &url,
            &format_id,
            &out_template,
            audio_mp3,
            proxy.as_deref(),
            |p| {
                if cancel_cb.load(Ordering::Relaxed) {
                    return;
                }
                let total = p.total_bytes.unwrap_or(0) as i64;
                let received = p.downloaded_bytes.unwrap_or(0) as i64;
                let secs = started.elapsed().as_secs_f64().max(0.001);
                let info = DownloadInfo {
                    id,
                    url: url_for_info.clone(),
                    file_name: "Downloading…".into(),
                    full_path: dir_str.clone(),
                    received,
                    total,
                    percent: p.percent as i32,
                    speed: p.speed_bps.map(|s| s as i64).unwrap_or((received as f64 / secs) as i64),
                    state: if p.done { "complete" } else { "in_progress" },
                    is_media: true,
                    mime: String::new(),
                    completed_unix: None,
                };
                downloads::manual_update(&app_cb, info, cancel_cb.clone());
            },
        );

        let final_info = match result {
            Ok(path) => {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "media".into());
                let size = std::fs::metadata(&path).map(|m| m.len() as i64).unwrap_or(0);
                DownloadInfo {
                    id,
                    url,
                    file_name: name,
                    full_path: path.to_string_lossy().into_owned(),
                    received: size,
                    total: size,
                    percent: 100,
                    speed: 0,
                    state: "complete",
                    is_media: true,
                    mime: String::new(),
                    completed_unix: Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    ),
                }
            }
            Err(e) => {
                eprintln!("vev-media: download failed: {e}");
                DownloadInfo {
                    id,
                    url,
                    file_name: format!("Failed: {e}"),
                    full_path: dir.to_string_lossy().into_owned(),
                    received: 0,
                    total: 0,
                    percent: 0,
                    speed: 0,
                    state: "canceled",
                    is_media: true,
                    mime: String::new(),
                    completed_unix: None,
                }
            }
        };
        downloads::manual_update(&app, final_info, cancel.clone());
    });
    id
}
