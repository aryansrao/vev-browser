//! Benchmark: single-stream vs 8-segment download of the same file.
//! Run: cargo run -p vev-download --example bench --release -- <url>
use std::time::Instant;

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://speed.cloudflare.com/__down?bytes=20000000".into());
    let dir = std::env::temp_dir();

    for (label, segs) in [("single-stream", 1usize), ("8-segment", 8usize)] {
        let dest = dir.join(format!("vevbench-{segs}.bin"));
        let t = Instant::now();
        match vev_download::download(&url, &dest, segs) {
            Ok(p) => {
                let bytes = p.downloaded.load(std::sync::atomic::Ordering::Relaxed);
                let secs = t.elapsed().as_secs_f64();
                let mbps = (bytes as f64 / 1_048_576.0) / secs;
                println!(
                    "{label:>14}: {:.1} MB in {secs:.2}s = {mbps:.1} MB/s",
                    bytes as f64 / 1_048_576.0
                );
            }
            Err(e) => println!("{label:>14}: FAILED {e}"),
        }
    }
}
