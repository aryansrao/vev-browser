//! Manual check of the online deep-scan sources. Reads keys from env and scans
//! the URL given as arg 1. Not a unit test (it hits the network).
//! Run: SB=.. VT=.. ABUSE=.. OTX=.. cargo run -p huma --example intel_check -- <url>
use huma::intel::{scan, IntelKeys};

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "https://example.com/".into());
    let keys = IntelKeys {
        safe_browsing: std::env::var("SB").ok(),
        virustotal: std::env::var("VT").ok(),
        abusech: std::env::var("ABUSE").ok(),
        otx: std::env::var("OTX").ok(),
        proxy: std::env::var("TOR").ok(),
    };
    let local = huma::guard::classify_adapted(&url).score;
    let r = scan(&url, &keys, local);
    println!("URL: {}\ndanger: {}%  malicious: {}", r.url, r.percent, r.malicious);
    for s in r.signals {
        let v = match s.verdict {
            huma::intel::Verdict::Malicious => "MALICIOUS",
            huma::intel::Verdict::Clean => "clean",
            huma::intel::Verdict::Unknown => "unknown",
        };
        println!("  {:<24} {:<10} {}", s.source, v, s.detail);
    }
}
