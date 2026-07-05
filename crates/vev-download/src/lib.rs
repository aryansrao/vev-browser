//! Segmented high-speed downloader: splits a file into N byte ranges and
//! fetches them in parallel, each on its own thread, writing directly to the
//! target file at the right offset. On servers that cap per-connection
//! throughput (common), this is materially faster than a single stream; when
//! the server does not support ranges it transparently falls back to a single
//! sequential download.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Number of parallel segments. 8 is a good default: enough to beat
/// per-connection caps without hammering the server.
pub const DEFAULT_SEGMENTS: usize = 8;

#[derive(Default)]
pub struct Progress {
    pub downloaded: AtomicU64,
    pub total: AtomicU64,
    pub done: AtomicBool,
    pub failed: AtomicBool,
}

pub struct DownloadHandle {
    pub progress: Arc<Progress>,
    pub dest: PathBuf,
}

/// Probe the URL for total size and range support (HTTP Accept-Ranges).
fn probe(url: &str) -> Result<(u64, bool), String> {
    let resp = ureq::head(url)
        .call()
        .map_err(|e| format!("HEAD {url}: {e}"))?;
    let len = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let ranges = resp
        .headers()
        .get("accept-ranges")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("bytes"))
        .unwrap_or(false);
    Ok((len, ranges))
}

fn fetch_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>, String> {
    // Inclusive range per RFC 7233.
    let range = format!("bytes={start}-{end}");
    let mut resp = ureq::get(url)
        .header("Range", &range)
        .call()
        .map_err(|e| format!("GET {range}: {e}"))?;
    let mut buf = Vec::with_capacity((end - start + 1) as usize);
    resp.body_mut()
        .as_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {range}: {e}"))?;
    Ok(buf)
}

/// Download `url` to `dest` using up to `segments` parallel range requests.
/// Blocking; returns when the whole file is written. Progress is reported
/// through the returned handle's atomics (poll from another thread/UI).
pub fn download(url: &str, dest: &Path, segments: usize) -> Result<Arc<Progress>, String> {
    let progress = Arc::new(Progress::default());
    download_into(url, dest, segments, &progress)?;
    Ok(progress)
}

/// Same as [`download`], but writes progress into a caller-provided handle so
/// another thread can poll it live.
pub fn download_into(
    url: &str,
    dest: &Path,
    segments: usize,
    progress: &Arc<Progress>,
) -> Result<(), String> {
    let (total, ranges) = probe(url)?;
    progress.total.store(total, Ordering::Relaxed);

    // Fall back to a single sequential stream if the server can't range or we
    // don't know the size.
    if !ranges || total == 0 || segments <= 1 {
        single_stream(url, dest, progress)?;
        progress.done.store(true, Ordering::Relaxed);
        return Ok(());
    }

    // Pre-allocate the destination so every segment can seek to its offset.
    let file = File::create(dest).map_err(|e| format!("create {dest:?}: {e}"))?;
    file.set_len(total).map_err(|e| format!("set_len: {e}"))?;
    drop(file);

    let seg_size = total / segments as u64;
    let mut handles = Vec::new();
    for i in 0..segments {
        let start = i as u64 * seg_size;
        let end = if i == segments - 1 {
            total - 1
        } else {
            start + seg_size - 1
        };
        let url = url.to_string();
        let dest = dest.to_path_buf();
        let progress = progress.clone();
        handles.push(std::thread::spawn(move || -> Result<(), String> {
            let data = fetch_range(&url, start, end)?;
            let mut f = File::options()
                .write(true)
                .open(&dest)
                .map_err(|e| format!("open for write: {e}"))?;
            f.seek(SeekFrom::Start(start))
                .map_err(|e| format!("seek: {e}"))?;
            f.write_all(&data).map_err(|e| format!("write: {e}"))?;
            progress
                .downloaded
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        }));
    }

    let mut first_err: Option<String> = None;
    for h in handles {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(_) => {
                first_err.get_or_insert_with(|| "segment thread panicked".into());
            }
        }
    }
    if let Some(e) = first_err {
        progress.failed.store(true, Ordering::Relaxed);
        return Err(e);
    }
    progress.done.store(true, Ordering::Relaxed);
    Ok(())
}

fn single_stream(url: &str, dest: &Path, progress: &Arc<Progress>) -> Result<(), String> {
    let mut resp = ureq::get(url).call().map_err(|e| format!("GET {url}: {e}"))?;
    let mut file = File::create(dest).map_err(|e| format!("create {dest:?}: {e}"))?;
    let mut reader = resp.body_mut().as_reader();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(|e| format!("write: {e}"))?;
        progress.downloaded.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve a fixed payload with Range support on a local port, then confirm
    /// the segmented downloader reassembles it byte-for-byte.
    #[test]
    fn segmented_download_reassembles_correctly() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let body = payload.clone();
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let url = format!("http://{addr}/file.bin");

        let handle = std::thread::spawn(move || {
            for _ in 0..12 {
                let Ok(req) = server.recv() else { break };
                let range = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Range"))
                    .map(|h| h.value.as_str().to_string());
                let (data, status): (Vec<u8>, u16) = match range {
                    Some(r) => {
                        // bytes=start-end
                        let nums: Vec<u64> = r
                            .trim_start_matches("bytes=")
                            .split('-')
                            .filter_map(|s| s.parse().ok())
                            .collect();
                        let (s, e) = (nums[0] as usize, nums[1] as usize);
                        (body[s..=e].to_vec(), 206)
                    }
                    None => (body.clone(), 200),
                };
                let mut resp = tiny_http::Response::from_data(data)
                    .with_status_code(status);
                resp.add_header(
                    tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap(),
                );
                let _ = req.respond(resp);
            }
        });

        // Give the HEAD probe an Accept-Ranges answer too (tiny_http replies
        // to HEAD via the same loop).
        let dir = std::env::temp_dir().join(format!("vevdl{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("out.bin");
        let progress = download(&url, &dest, 4).expect("download");

        let mut got = Vec::new();
        File::open(&dest).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), payload.len(), "size mismatch");
        assert_eq!(got, payload, "content mismatch after reassembly");
        assert!(progress.done.load(Ordering::Relaxed));
        drop(handle);
    }
}
