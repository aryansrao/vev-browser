//! Feature-vector dumper for training the Huma Guard ML model.
//!
//! Reads `url<TAB>label` lines from stdin and writes CSV
//! `f0,f1,...,f12,label` to stdout, where the features are exactly what
//! `huma::guard::extract_features(...).vector()` produces at inference time.
//! Training on this output guarantees the model sees the same features the
//! browser will feed it. Run via `scripts/train_guard/run.sh`.

use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Header.
    let mut header: Vec<String> =
        huma::guard::FEATURE_NAMES.iter().map(|s| s.to_string()).collect();
    header.push("label".into());
    writeln!(out, "{}", header.join(",")).unwrap();

    for line in stdin.lock().lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (url, label) = match line.rsplit_once('\t') {
            Some((u, l)) => (u.trim(), l.trim()),
            None => continue,
        };
        let v = huma::guard::extract_features(url).vector();
        let cells: Vec<String> = v.iter().map(|x| format!("{x:.5}")).collect();
        writeln!(out, "{},{}", cells.join(","), label).unwrap();
    }
}
