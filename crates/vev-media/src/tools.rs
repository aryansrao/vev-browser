//! Locate the yt-dlp and ffmpeg binaries: a system install on PATH, else a
//! managed copy in Vev's app-data `tools/` dir (populated by `fetch`).

use serde::Serialize;
use std::path::{Path, PathBuf};

/// Resolved tool locations for this run.
#[derive(Clone, Debug)]
pub struct Tools {
    ytdlp: Option<PathBuf>,
    ffmpeg: Option<PathBuf>,
}

/// UI-facing availability, so the download popup can offer the one-time fetch.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ToolStatus {
    pub ytdlp: bool,
    pub ffmpeg: bool,
    /// Where a managed fetch would install to.
    pub tools_dir: String,
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Find `name` on PATH (like `which`), returning its full path.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let want = exe(name);
    std::env::split_paths(&path)
        .map(|dir| dir.join(&want))
        .find(|p| p.is_file())
}

impl Tools {
    /// Resolve tools: PATH first (a user's own, kept up to date), else the
    /// managed copies in `tools_dir`.
    pub fn resolve(tools_dir: &Path) -> Self {
        let ytdlp = which("yt-dlp").or_else(|| {
            let p = tools_dir.join(exe("yt-dlp"));
            p.is_file().then_some(p)
        });
        let ffmpeg = which("ffmpeg").or_else(|| {
            let p = tools_dir.join(exe("ffmpeg"));
            p.is_file().then_some(p)
        });
        Tools { ytdlp, ffmpeg }
    }

    pub fn ytdlp(&self) -> Option<&Path> {
        self.ytdlp.as_deref()
    }

    pub fn ffmpeg(&self) -> Option<&Path> {
        self.ffmpeg.as_deref()
    }

    /// Directory holding ffmpeg, for yt-dlp's `--ffmpeg-location`.
    pub fn ffmpeg_dir(&self) -> Option<PathBuf> {
        self.ffmpeg.as_ref().and_then(|p| p.parent().map(Path::to_path_buf))
    }

    pub fn status(&self, tools_dir: &Path) -> ToolStatus {
        ToolStatus {
            ytdlp: self.ytdlp.is_some(),
            ffmpeg: self.ffmpeg.is_some(),
            tools_dir: tools_dir.to_string_lossy().into_owned(),
        }
    }
}
