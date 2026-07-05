//! Media extraction/conversion via the yt-dlp + ffmpeg binaries.
//!
//! Rust orchestration only: binary discovery, a managed one-time fetch into
//! app-data, `yt-dlp -J` format probing, and download-with-progress. The
//! JSON/progress parsers are pure functions with unit tests; the process
//! plumbing is thin.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub mod fetch;
pub mod tools;

pub use tools::{Tools, ToolStatus};

/// A single downloadable/streamable format yt-dlp reported for a URL.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Format {
    pub id: String,
    /// "video", "audio", or "video+audio".
    pub kind: String,
    pub ext: String,
    /// Human label, e.g. "1080p", "720p60", "audio 128k".
    pub label: String,
    /// Vertical resolution when known (for sorting/labeling).
    pub height: Option<u32>,
    /// Approx size in bytes when yt-dlp knows it.
    pub filesize: Option<u64>,
    /// True if this format is a direct progressive URL that a browser can
    /// play as-is (used by "Play online"). HLS/DASH manifests are false.
    pub progressive: bool,
}

/// What yt-dlp knows about a page URL: title, thumbnail, and formats.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct MediaInfo {
    pub title: String,
    pub thumbnail: Option<String>,
    pub duration_secs: Option<u64>,
    pub webpage_url: String,
    pub is_playlist: bool,
    pub formats: Vec<Format>,
}

/// A progress tick parsed from yt-dlp's `--newline` output.
#[derive(Clone, Debug, PartialEq)]
pub struct Progress {
    pub percent: f32,
    pub downloaded_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub speed_bps: Option<u64>,
    pub done: bool,
}

/// Probe a URL for media info. Runs `yt-dlp -J` through the resolved binary.
/// `proxy` is a full proxy URL applied with `--proxy` when set.
pub fn probe(tools: &Tools, url: &str, proxy: Option<&str>) -> Result<MediaInfo, String> {
    let ytdlp = tools.ytdlp().ok_or("yt-dlp not available")?;
    let mut cmd = Command::new(ytdlp);
    cmd.args(["-J", "--no-warnings", "--no-playlist"]);
    if let Some(p) = proxy {
        cmd.args(["--proxy", p]);
    }
    cmd.arg(url);
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn yt-dlp: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "yt-dlp failed: {}",
            String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("unknown error")
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("parse yt-dlp json: {e}"))?;
    Ok(parse_info(&v, url))
}

/// Build the yt-dlp argument list for a download. Extracted so it's testable
/// without spawning. `format_id` is a yt-dlp format selector; `audio_mp3`
/// requests on-the-fly mp3 extraction (needs ffmpeg).
pub fn download_args(
    url: &str,
    format_id: &str,
    out_template: &str,
    audio_mp3: bool,
    ffmpeg_dir: Option<&Path>,
    proxy: Option<&str>,
) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "--newline".into(),
        "--no-warnings".into(),
        "--no-playlist".into(),
        "-o".into(),
        out_template.into(),
    ];
    if audio_mp3 {
        // Extract + transcode to mp3 as it downloads (ffmpeg muxes on the fly).
        a.push("--extract-audio".into());
        a.push("--audio-format".into());
        a.push("mp3".into());
        a.push("--audio-quality".into());
        a.push("0".into());
    } else if !format_id.is_empty() {
        a.push("-f".into());
        a.push(format_id.into());
    }
    if let Some(dir) = ffmpeg_dir {
        a.push("--ffmpeg-location".into());
        a.push(dir.to_string_lossy().into_owned());
    }
    if let Some(p) = proxy {
        a.push("--proxy".into());
        a.push(p.into());
    }
    a.push(url.into());
    a
}

/// Resolve a single directly-playable URL for "Play online" — yt-dlp's `-g`
/// with a progressive-preferring format selector. Returns the media URL.
pub fn resolve_stream_url(tools: &Tools, url: &str, proxy: Option<&str>) -> Result<String, String> {
    let ytdlp = tools.ytdlp().ok_or("yt-dlp not available")?;
    let mut cmd = Command::new(ytdlp);
    // Prefer a progressive mp4 a browser can play directly; fall back to best.
    cmd.args([
        "-g",
        "-f",
        "best[ext=mp4][protocol^=http]/best[protocol^=http]/best",
        "--no-warnings",
        "--no-playlist",
    ]);
    if let Some(p) = proxy {
        cmd.args(["--proxy", p]);
    }
    cmd.arg(url);
    let out = cmd.output().map_err(|e| format!("spawn yt-dlp: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "yt-dlp -g failed: {}",
            String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("")
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .find(|l| l.starts_with("http"))
        .map(|l| l.to_string())
        .ok_or_else(|| "no playable URL resolved".into())
}

/// Spawn a yt-dlp download, invoking `on_progress` for each parsed tick.
/// Blocks until the process exits; run it on a worker thread. `dir` is the
/// directory the output template lives in (created if missing).
pub fn download(
    tools: &Tools,
    url: &str,
    format_id: &str,
    out_template: &str,
    audio_mp3: bool,
    proxy: Option<&str>,
    mut on_progress: impl FnMut(Progress),
) -> Result<PathBuf, String> {
    use std::io::{BufRead, BufReader};
    let ytdlp = tools.ytdlp().ok_or("yt-dlp not available")?;
    if let Some(parent) = Path::new(out_template).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let args = download_args(
        url,
        format_id,
        out_template,
        audio_mp3,
        tools.ffmpeg_dir().as_deref(),
        proxy,
    );
    let mut child = Command::new(ytdlp)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn yt-dlp: {e}"))?;

    let mut final_path: Option<PathBuf> = None;
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(p) = parse_progress_line(&line) {
                on_progress(p);
            }
            if let Some(path) = parse_destination(&line) {
                final_path = Some(PathBuf::from(path));
            }
        }
    }
    let status = child.wait().map_err(|e| format!("wait yt-dlp: {e}"))?;
    if !status.success() {
        let mut err = String::new();
        if let Some(mut se) = child.stderr.take() {
            use std::io::Read;
            let _ = se.read_to_string(&mut err);
        }
        return Err(format!("yt-dlp exited {status}: {}", err.lines().last().unwrap_or("")));
    }
    on_progress(Progress { percent: 100.0, downloaded_bytes: None, total_bytes: None, speed_bps: None, done: true });
    final_path.ok_or_else(|| "download finished but path unknown".into())
}

// ---- pure parsers ----

fn parse_info(v: &serde_json::Value, url: &str) -> MediaInfo {
    let is_playlist = v.get("_type").and_then(|t| t.as_str()) == Some("playlist");
    let mut formats = Vec::new();
    if let Some(arr) = v.get("formats").and_then(|f| f.as_array()) {
        for f in arr {
            if let Some(fmt) = parse_format(f) {
                formats.push(fmt);
            }
        }
    }
    // Highest quality first; audio-only sinks to the bottom.
    formats.sort_by(|a, b| b.height.unwrap_or(0).cmp(&a.height.unwrap_or(0)));
    MediaInfo {
        title: v.get("title").and_then(|t| t.as_str()).unwrap_or("media").to_string(),
        thumbnail: v.get("thumbnail").and_then(|t| t.as_str()).map(String::from),
        duration_secs: v.get("duration").and_then(|d| d.as_f64()).map(|d| d as u64),
        webpage_url: v.get("webpage_url").and_then(|u| u.as_str()).unwrap_or(url).to_string(),
        is_playlist,
        formats,
    }
}

fn parse_format(f: &serde_json::Value) -> Option<Format> {
    let id = f.get("format_id")?.as_str()?.to_string();
    let vcodec = f.get("vcodec").and_then(|c| c.as_str()).unwrap_or("none");
    let acodec = f.get("acodec").and_then(|c| c.as_str()).unwrap_or("none");
    let has_video = vcodec != "none";
    let has_audio = acodec != "none";
    if !has_video && !has_audio {
        return None; // storyboards, etc.
    }
    let kind = match (has_video, has_audio) {
        (true, true) => "video+audio",
        (true, false) => "video",
        _ => "audio",
    }
    .to_string();
    let ext = f.get("ext").and_then(|e| e.as_str()).unwrap_or("").to_string();
    let height = f.get("height").and_then(|h| h.as_u64()).map(|h| h as u32);
    let filesize = f
        .get("filesize")
        .or_else(|| f.get("filesize_approx"))
        .and_then(|s| s.as_u64());
    let protocol = f.get("protocol").and_then(|p| p.as_str()).unwrap_or("");
    let progressive = has_video && has_audio && protocol.starts_with("http") && !protocol.contains("m3u8") && !protocol.contains("dash");
    let label = if has_video {
        match (height, f.get("fps").and_then(|x| x.as_f64())) {
            (Some(h), Some(fps)) if fps > 30.0 => format!("{h}p{}", fps as u32),
            (Some(h), _) => format!("{h}p"),
            _ => f.get("format_note").and_then(|n| n.as_str()).unwrap_or("video").to_string(),
        }
    } else {
        let abr = f.get("abr").and_then(|a| a.as_f64());
        match abr {
            Some(a) => format!("audio {}k", a as u32),
            None => "audio".to_string(),
        }
    };
    Some(Format { id, kind, ext, label, height, filesize, progressive })
}

/// Parse a yt-dlp `--newline` progress line like:
/// `[download]  42.3% of 10.00MiB at 1.20MiB/s ETA 00:05`
pub fn parse_progress_line(line: &str) -> Option<Progress> {
    let l = line.trim();
    if !l.starts_with("[download]") {
        return None;
    }
    let rest = l.trim_start_matches("[download]").trim();
    let pct_tok = rest.split_whitespace().next()?;
    if !pct_tok.ends_with('%') {
        return None;
    }
    let percent: f32 = pct_tok.trim_end_matches('%').parse().ok()?;
    let total_bytes = rest
        .split(" of ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(parse_size);
    let speed_bps = rest
        .split(" at ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(parse_size);
    let downloaded_bytes = total_bytes.map(|t| (t as f32 * percent / 100.0) as u64);
    Some(Progress { percent, downloaded_bytes, total_bytes, speed_bps, done: percent >= 100.0 })
}

/// Parse a size like "10.00MiB" / "1.20MiB/s" / "512.00KiB" into bytes.
fn parse_size(tok: &str) -> Option<u64> {
    let t = tok.trim_end_matches("/s");
    let (num, unit) = t.split_at(t.find(|c: char| c.is_alphabetic())?);
    let n: f64 = num.parse().ok()?;
    let mult = match unit {
        "B" => 1.0,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0f64.powi(4),
        _ => return None,
    };
    Some((n * mult) as u64)
}

/// Parse the final destination path from yt-dlp output lines:
/// `[download] Destination: /path/file.mp4` or
/// `[ExtractAudio] Destination: /path/file.mp3` or
/// `[download] /path/file.mp4 has already been downloaded`.
pub fn parse_destination(line: &str) -> Option<String> {
    let l = line.trim();
    if let Some(idx) = l.find("Destination: ") {
        return Some(l[idx + "Destination: ".len()..].trim().to_string());
    }
    if let Some(rest) = l.strip_prefix("[download] ") {
        if let Some(path) = rest.strip_suffix(" has already been downloaded") {
            return Some(path.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_line_parses() {
        let p = parse_progress_line("[download]  42.3% of 10.00MiB at 1.20MiB/s ETA 00:05").unwrap();
        assert!((p.percent - 42.3).abs() < 0.01);
        assert_eq!(p.total_bytes, Some((10.0 * 1024.0 * 1024.0) as u64));
        assert_eq!(p.speed_bps, Some((1.20 * 1024.0 * 1024.0) as u64));
        assert!(!p.done);
    }

    #[test]
    fn progress_line_100_is_done() {
        let p = parse_progress_line("[download] 100% of 5.00MiB").unwrap();
        assert!(p.done);
    }

    #[test]
    fn non_progress_lines_ignored() {
        assert!(parse_progress_line("[info] Downloading 1 format(s): 22").is_none());
        assert!(parse_progress_line("random text").is_none());
    }

    #[test]
    fn destination_parsed() {
        assert_eq!(
            parse_destination("[download] Destination: /Users/x/Downloads/vid.mp4"),
            Some("/Users/x/Downloads/vid.mp4".to_string())
        );
        assert_eq!(
            parse_destination("[ExtractAudio] Destination: /Users/x/Downloads/song.mp3"),
            Some("/Users/x/Downloads/song.mp3".to_string())
        );
        assert_eq!(
            parse_destination("[download] /Users/x/f.mp4 has already been downloaded"),
            Some("/Users/x/f.mp4".to_string())
        );
        assert_eq!(parse_destination("[download] 50% of 1.00MiB"), None);
    }

    #[test]
    fn download_args_mp3() {
        let a = download_args("u", "140", "/d/%(title)s.%(ext)s", true, None, None);
        assert!(a.windows(2).any(|w| w[0] == "--audio-format" && w[1] == "mp3"));
        // mp3 extraction ignores -f video selector.
        assert!(!a.iter().any(|x| x == "-f"));
        assert_eq!(a.last().unwrap(), "u");
    }

    #[test]
    fn download_args_video_with_proxy() {
        let a = download_args("u", "22", "/d/o", false, None, Some("socks5://127.0.0.1:9050"));
        assert!(a.windows(2).any(|w| w[0] == "-f" && w[1] == "22"));
        assert!(a.windows(2).any(|w| w[0] == "--proxy" && w[1] == "socks5://127.0.0.1:9050"));
    }

    #[test]
    fn format_parse_progressive_flag() {
        let f = serde_json::json!({
            "format_id": "22", "ext": "mp4", "vcodec": "avc1", "acodec": "mp4a",
            "height": 720, "protocol": "https", "fps": 30
        });
        let fmt = parse_format(&f).unwrap();
        assert_eq!(fmt.kind, "video+audio");
        assert!(fmt.progressive);
        assert_eq!(fmt.label, "720p");

        let hls = serde_json::json!({
            "format_id": "301", "ext": "mp4", "vcodec": "avc1", "acodec": "mp4a",
            "height": 1080, "protocol": "m3u8_native"
        });
        assert!(!parse_format(&hls).unwrap().progressive);
    }
}
