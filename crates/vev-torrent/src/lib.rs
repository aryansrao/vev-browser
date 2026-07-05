//! Built-in BitTorrent via librqbit, embedded on a background Tokio runtime.
//! Exposes a small command surface: add a magnet/URL, list active torrents
//! with live progress. Downloads land in the user's chosen directory.

use librqbit::{AddTorrent, AddTorrentOptions, AddTorrentResponse, Session};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::{Handle, Runtime};

struct Core {
    session: Arc<Session>,
    handle: Handle,
    // Keep the runtime alive for the process lifetime.
    _rt: Runtime,
}

static CORE: OnceLock<Mutex<Option<Arc<Core>>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Arc<Core>>> {
    CORE.get_or_init(|| Mutex::new(None))
}

#[derive(Clone, Serialize)]
pub struct TorrentInfo {
    pub id: usize,
    pub name: String,
    pub progress_bytes: u64,
    pub total_bytes: u64,
    pub percent: u32,
    pub finished: bool,
    pub state: String,
    pub down_mbps: f64,
    pub up_mbps: f64,
}

/// Initialize the torrent session, downloading into `download_dir`. Runs the
/// session on a dedicated multi-thread Tokio runtime. Non-fatal on failure.
pub fn init(download_dir: PathBuf) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vev-torrent: runtime: {e}");
            return;
        }
    };
    let handle = rt.handle().clone();
    let session = match handle.block_on(Session::new(download_dir.clone())) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vev-torrent: session init failed: {e}");
            return;
        }
    };
    eprintln!("vev-torrent: session ready, downloads -> {download_dir:?}");
    if let Ok(mut guard) = slot().lock() {
        *guard = Some(Arc::new(Core {
            session,
            handle,
            _rt: rt,
        }));
    }
}

fn core() -> Result<Arc<Core>, String> {
    slot()
        .lock()
        .map_err(|_| "torrent core lock".to_string())?
        .clone()
        .ok_or_else(|| "torrent session not initialized".to_string())
}

/// Add a torrent from a magnet link, an http(s) `.torrent` URL, or a local
/// `.torrent` file path. Returns the torrent id.
pub fn add(magnet_or_url: String) -> Result<usize, String> {
    let core = core()?;
    let session = core.session.clone();
    // `AddTorrent::from_url` only understands URL schemes. A bare path to a
    // downloaded `.torrent` (or one the user pastes) must be read as bytes.
    let src = magnet_or_url.trim().to_string();
    let is_url = src.starts_with("magnet:")
        || src.starts_with("http://")
        || src.starts_with("https://");
    let add_torrent = if !is_url && std::path::Path::new(&src).exists() {
        match std::fs::read(&src) {
            Ok(bytes) => AddTorrent::from_bytes(bytes),
            Err(e) => return Err(format!("read {src}: {e}")),
        }
    } else {
        AddTorrent::from_url(src)
    };
    core.handle.block_on(async move {
        let resp = session
            .add_torrent(add_torrent, Some(AddTorrentOptions::default()))
            .await
            .map_err(|e| format!("add_torrent: {e}"))?;
        match resp {
            AddTorrentResponse::Added(id, _handle) => Ok(id),
            AddTorrentResponse::AlreadyManaged(id, _) => Ok(id),
            AddTorrentResponse::ListOnly(_) => {
                Err("torrent added as list-only (no download)".to_string())
            }
        }
    })
}

/// Control a torrent by id: "pause", "resume", "remove" (keep the downloaded
/// files), or "remove_files" (delete them too).
pub fn control(id: usize, action: String) -> Result<(), String> {
    let core = core()?;
    let session = core.session.clone();
    core.handle.block_on(async move {
        match action.as_str() {
            "pause" => {
                let h = session.get(id.into()).ok_or("torrent not found")?;
                session.pause(&h).await.map_err(|e| e.to_string())
            }
            "resume" => {
                let h = session.get(id.into()).ok_or("torrent not found")?;
                session.unpause(&h).await.map_err(|e| e.to_string())
            }
            "remove" => session.delete(id.into(), false).await.map_err(|e| e.to_string()),
            "remove_files" => session.delete(id.into(), true).await.map_err(|e| e.to_string()),
            _ => Err(format!("unknown torrent action: {action}")),
        }
    })
}

/// List all active torrents with live stats.
pub fn list() -> Result<Vec<TorrentInfo>, String> {
    let core = core()?;
    let session = core.session.clone();
    let out = std::cell::RefCell::new(Vec::new());
    session.with_torrents(|torrents| {
        for (id, handle) in torrents {
            let stats = handle.stats();
            let name = handle
                .metadata
                .load()
                .as_ref()
                .map(|m| m.name.clone().unwrap_or_default())
                .unwrap_or_else(|| format!("torrent {id}"));
            let (down, up) = stats
                .live
                .as_ref()
                .map(|l| (l.download_speed.mbps, l.upload_speed.mbps))
                .unwrap_or((0.0, 0.0));
            let percent = if stats.total_bytes > 0 {
                ((stats.progress_bytes * 100) / stats.total_bytes) as u32
            } else {
                0
            };
            out.borrow_mut().push(TorrentInfo {
                id,
                name,
                progress_bytes: stats.progress_bytes,
                total_bytes: stats.total_bytes,
                percent,
                finished: stats.finished,
                state: format!("{:?}", stats.state),
                down_mbps: down,
                up_mbps: up,
            });
        }
    });
    Ok(out.into_inner())
}
