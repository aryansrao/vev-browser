//! Managed one-time fetch of the yt-dlp (and, best-effort, ffmpeg) binaries
//! into Vev's app-data `tools/` dir, so the downloader "works everywhere"
//! without bloating the installer. yt-dlp ships a single standalone binary
//! per OS from its GitHub releases; ffmpeg static builds have no single
//! canonical URL, so ffmpeg auto-fetch is best-effort and the UI still works
//! (video downloads) if only yt-dlp is present — only mp3/convert needs it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// yt-dlp release asset name for the current OS/arch.
fn ytdlp_asset() -> &'static str {
    if cfg!(target_os = "windows") {
        "yt-dlp.exe"
    } else if cfg!(target_os = "macos") {
        "yt-dlp_macos"
    } else {
        "yt-dlp_linux"
    }
}

fn ytdlp_url() -> String {
    format!(
        "https://github.com/yt-dlp/yt-dlp/releases/latest/download/{}",
        ytdlp_asset()
    )
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into()
}

/// Download `url` to `dest` and mark it executable. Overwrites atomically via
/// a temp file next to the destination.
fn download_binary(url: &str, dest: &Path) -> Result<(), String> {
    let tmp = dest.with_extension("part");
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
    }
    let mut resp = agent().get(url).call().map_err(|e| format!("GET {url}: {e}"))?;
    let mut reader = resp.body_mut().as_reader();
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create {tmp:?}: {e}"))?;
    std::io::copy(&mut reader, &mut file).map_err(|e| format!("write {tmp:?}: {e}"))?;
    file.flush().ok();
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {tmp:?}: {e}"))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| format!("rename into place: {e}"))?;
    Ok(())
}

/// Fetch yt-dlp into `tools_dir`. Returns the installed path.
pub fn fetch_ytdlp(tools_dir: &Path) -> Result<PathBuf, String> {
    let name = if cfg!(windows) { "yt-dlp.exe" } else { "yt-dlp" };
    let dest = tools_dir.join(name);
    download_binary(&ytdlp_url(), &dest)?;
    Ok(dest)
}

/// Whether an ffmpeg auto-fetch URL is known for this platform. ffmpeg static
/// builds are large and host-specific; on the platforms without a stable
/// direct URL we return None and the UI tells the user to install ffmpeg
/// (mp3/convert only — plain video downloads still work).
pub fn ffmpeg_available_for_fetch() -> bool {
    false
}
