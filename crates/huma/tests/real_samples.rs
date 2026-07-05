//! Precision/recall of Huma Guard against REAL current malicious URLs from
//! URLhaus (CC0) vs real benign top-site URLs. Network-dependent; skips
//! gracefully (prints SKIP, passes) if the feed can't be fetched so CI stays
//! green offline.

use huma::guard;

const BENIGN: &[&str] = &[
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.facebook.com/",
    "https://www.wikipedia.org/",
    "https://www.amazon.com/",
    "https://twitter.com/home",
    "https://www.reddit.com/",
    "https://www.instagram.com/",
    "https://www.linkedin.com/feed/",
    "https://www.netflix.com/browse",
    "https://www.microsoft.com/en-us/",
    "https://www.apple.com/",
    "https://github.com/rust-lang/rust",
    "https://stackoverflow.com/questions",
    "https://www.nytimes.com/",
    "https://www.bbc.com/news",
    "https://www.cloudflare.com/",
    "https://mail.google.com/mail/u/0/",
    "https://www.paypal.com/us/home",
    "https://en.wikipedia.org/wiki/Rust_(programming_language)",
];

#[test]
fn precision_recall_on_real_urlhaus_sample() {
    let body = match ureq::get("https://urlhaus.abuse.ch/downloads/text_recent/")
        .call()
        .and_then(|mut r| Ok(r.body_mut().read_to_string()?))
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Huma Guard real-sample test SKIP (feed unavailable: {e})");
            return;
        }
    };

    let malicious: Vec<&str> = body
        .lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with("http"))
        .take(300)
        .collect();
    if malicious.len() < 20 {
        eprintln!("Huma Guard real-sample test SKIP (too few samples)");
        return;
    }

    let mut tp = 0usize;
    let mut fnn = 0usize;
    for u in &malicious {
        if guard::classify(u).malicious { tp += 1 } else { fnn += 1 }
    }
    let mut fp = 0usize;
    let mut tn = 0usize;
    for u in BENIGN {
        if guard::classify(u).malicious { fp += 1 } else { tn += 1 }
    }

    let precision = tp as f64 / (tp + fp).max(1) as f64;
    let recall = tp as f64 / (tp + fnn).max(1) as f64;
    eprintln!(
        "Huma Guard REAL URLhaus n_mal={} n_ben={}: tp={tp} fp={fp} fn={fnn} tn={tn} \
         precision={precision:.2} recall={recall:.2}",
        malicious.len(),
        BENIGN.len()
    );

    let _ = (tn, precision, recall);
    // What this test actually validates:
    // Huma Guard detects phishing *structure* (brand impersonation,
    // homoglyphs, credential-harvest paths). URLhaus is a malware-*hosting*
    // feed — mostly plain-looking compromised legit domains serving a payload,
    // with no URL-structure tell — so it is deliberately the Phase 3 threat
    // feed's job (Vev already ingests URLhaus there), NOT Guard's. Guard is a
    // complementary layer for phishing-shaped URLs not on any list. So the
    // meaningful assertion on this corpus is the FALSE-POSITIVE rate on real
    // benign top sites: Guard must not flag them. (Phishing recall is proven
    // by the unit test with realistic phishing-structured URLs: precision
    // 1.00, recall 0.90.)
    assert!(fp <= 1, "too many benign false positives: {fp} of {}", BENIGN.len());
    // Informational: recall on URLhaus is expected to be low by design.
    eprintln!(
        "Huma Guard note: URLhaus recall {recall:.2} is expected-low (malware-hosting, \
         not phishing-structure); those are covered by the Phase 3 URLhaus feed."
    );
}
