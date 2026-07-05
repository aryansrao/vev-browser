//! Huma Guard — on-device malicious-URL / phishing classifier.
//!
//! A gradient-boosted-style linear scorer over hand-engineered
//! character/structural URL features (the project spec explicitly allows a
//! gradient-boosted model with these exact features). This is deliberately
//! NOT a neural net: the features (entropy, homoglyph/punycode,
//! brand-impersonation, TLD reputation, structural anomalies) are
//! interpretable, the model is a few KB of weights, inference is
//! microseconds, and precision/recall are measurable. It runs before every
//! navigation as an extra layer alongside the Phase 3 filter lists + threat
//! feed, to catch structurally-suspicious URLs not on any list yet.
//!
//! The weights below were calibrated offline against phishing/benign samples;
//! `MODEL_VERSION` is bumped when they change (static model, updated only
//! through app releases — no runtime weight changes, per spec).

use std::collections::HashSet;

pub const MODEL_VERSION: u32 = 1;

/// TLDs disproportionately abused for phishing/malware (reputation feature).
const RISKY_TLDS: &[&str] = &[
    "zip", "mov", "xyz", "top", "gq", "ml", "cf", "ga", "tk", "work", "click",
    "link", "loan", "download", "review", "country", "kim", "science", "party",
    "gdn", "racing", "win", "bid", "stream", "cam", "rest", "quest", "cfd",
    "sbs", "lol", "icu", "cyou",
];

/// Brand tokens frequently impersonated in phishing hostnames.
const BRANDS: &[&str] = &[
    "paypal", "apple", "microsoft", "amazon", "google", "facebook", "netflix",
    "instagram", "whatsapp", "outlook", "office365", "icloud", "coinbase",
    "binance", "metamask", "wellsfargo", "chase", "bankofamerica", "dhl",
    "fedex", "usps", "irs", "gov", "steam", "discord", "roblox", "linkedin",
];

/// Words that signal credential-harvesting intent in the path/host.
const SUSPICIOUS_WORDS: &[&str] = &[
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "webscr", "password", "banking", "wallet", "recover", "unlock", "suspend",
    "billing", "invoice", "authenticate", "validation", "security-alert",
];

/// Common URL shorteners (obscure the real destination).
const SHORTENERS: &[&str] = &[
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct Verdict {
    /// 0.0 (benign) .. 1.0 (malicious) calibrated score.
    pub score: f64,
    /// True if score >= decision threshold.
    pub malicious: bool,
    /// Human-readable reasons that fired (for the UI warning).
    pub reasons: Vec<String>,
}

/// Decision threshold, tuned for high precision (avoid false positives that
/// would block legitimate sites).
pub const THRESHOLD: f64 = 0.60;

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    let n = n as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Does the host mix confusable scripts or use punycode (homoglyph attack)?
fn homoglyph_signal(host: &str) -> bool {
    if host.contains("xn--") {
        return true; // punycode — could be a homoglyph domain
    }
    // Digit-for-letter substitutions common in typosquats (paypa1, g00gle).
    let has_digit_in_word = host
        .split('.')
        .any(|label| label.chars().any(|c| c.is_ascii_digit()) && label.chars().any(|c| c.is_ascii_alphabetic()));
    // Non-ASCII in the host is a mild signal on its own.
    let non_ascii = host.chars().any(|c| !c.is_ascii());
    has_digit_in_word && non_ascii || host.chars().filter(|c| !c.is_ascii()).count() > 2
}

/// A brand token appears in a subdomain but is NOT the registrable domain
/// (e.g. `paypal.secure-login.ru` — paypal is not the real owner).
fn brand_impersonation(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    // Registrable domain heuristic: last two labels.
    let registrable = labels[labels.len() - 2];
    for brand in BRANDS {
        // Brand present somewhere in the host…
        if host.contains(brand)
            // …but the registrable label is not exactly the brand.
            && registrable != *brand
        {
            return Some((*brand).to_string());
        }
    }
    None
}

fn is_ip_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok()
}

/// The named feature vector extracted from a URL. Each entry is
/// (stable_feature_name, value); `value` is the same quantity the base model
/// weights, and it is what the self-adapting layer (see [`crate::adapt`])
/// learns an additive correction weight for. Stable names let the persisted
/// adapter survive across runs.
#[derive(Debug, Clone)]
pub struct Features {
    /// Base-model logit before any adaptation.
    pub base_z: f64,
    /// (name, value) pairs for every feature that fired.
    pub values: Vec<(&'static str, f64)>,
    pub reasons: Vec<String>,
    /// True if at least one *host-level* red flag fired (impersonation,
    /// homoglyph, IP host, risky TLD, very-high host entropy, shortener, `@`
    /// trick). Weak signals alone — a long URL, a couple of query words — must
    /// NOT flag a page: a normal long link on a legitimate domain (a Udemy
    /// course, a Google search) is not phishing. Phishing lives in the *host*.
    pub strong: bool,
}

/// Canonical, fixed feature order for the ML model. Rust (inference) and the
/// Python trainer must agree on this exactly — the trainer reads its features
/// from this same extractor (see scripts/train_guard), so parity is by
/// construction.
pub const FEATURE_NAMES: [&str; 13] = [
    "ip_host", "host_entropy", "subdomain_depth", "hyphens", "risky_tld",
    "homoglyph", "brand_impersonation", "at_trick", "cred_words", "shortener",
    "long_url", "pct_encoding", "nonstd_port",
];

impl Features {
    /// Dense fixed-length feature vector in `FEATURE_NAMES` order (0.0 for a
    /// feature that didn't fire). This is the model input.
    pub fn vector(&self) -> [f32; 13] {
        let mut v = [0.0f32; 13];
        for (name, value) in &self.values {
            if let Some(i) = FEATURE_NAMES.iter().position(|n| n == name) {
                v[i] = *value as f32;
            }
        }
        v
    }
}

/// Extract the interpretable feature vector + base logit. Pure, microsecond.
pub fn extract_features(raw_url: &str) -> Features {
    let mut reasons = Vec::new();
    let mut values: Vec<(&'static str, f64)> = Vec::new();
    let mut z = -2.2_f64; // bias so an ordinary URL scores well below threshold
    // Accumulate a feature's weighted contribution into z and record its raw
    // value under a stable name for the adapter.
    let mut feat = |name: &'static str, value: f64, weight: f64| {
        z += value * weight;
        values.push((name, value));
    };

    let parsed = url::Url::parse(raw_url).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = parsed.as_ref().map(|u| u.path().to_string()).unwrap_or_default();
    let full = raw_url.to_ascii_lowercase();

    if is_ip_host(&host) {
        feat("ip_host", 1.0, 2.0);
        reasons.push("host is a raw IP address".into());
    }

    let host_entropy = shannon_entropy(&host);
    if host_entropy > 4.0 {
        feat("host_entropy", host_entropy - 4.0, 1.1);
        reasons.push(format!("high host entropy ({host_entropy:.1})"));
    }

    let dots = host.matches('.').count();
    if dots >= 4 {
        feat("subdomain_depth", dots as f64 - 3.0, 0.6);
        reasons.push(format!("{dots} subdomain levels"));
    }

    let hyphens = host.matches('-').count();
    if hyphens >= 2 {
        feat("hyphens", hyphens as f64, 0.35);
        reasons.push(format!("{hyphens} hyphens in host"));
    }

    if let Some(tld) = host.rsplit('.').next() {
        if RISKY_TLDS.contains(&tld) {
            feat("risky_tld", 1.0, 1.3);
            reasons.push(format!("low-reputation TLD .{tld}"));
        }
    }

    if homoglyph_signal(&host) {
        feat("homoglyph", 1.0, 1.6);
        reasons.push("homoglyph/punycode host".into());
    }

    if let Some(brand) = brand_impersonation(&host) {
        feat("brand_impersonation", 1.0, 2.1);
        reasons.push(format!("impersonates brand '{brand}'"));
    }

    if raw_url.contains('@') && parsed.as_ref().map(|u| !u.username().is_empty()).unwrap_or(false) {
        feat("at_trick", 1.0, 1.8);
        reasons.push("'@' authority trick".into());
    }

    let word_hits: HashSet<&str> = SUSPICIOUS_WORDS
        .iter()
        .filter(|w| full.contains(*w))
        .copied()
        .collect();
    if !word_hits.is_empty() {
        feat("cred_words", word_hits.len() as f64, 0.55);
        reasons.push(format!("credential-harvest terms: {}", to_list(&word_hits)));
    }

    if SHORTENERS.contains(&host.as_str()) {
        feat("shortener", 1.0, 0.7);
        reasons.push("URL shortener".into());
    }

    // Long URLs are common on legitimate sites (course pages, search results,
    // signed links), so this is a weak, hard-capped signal — never enough to
    // flag on its own.
    if raw_url.len() > 160 {
        let v = (((raw_url.len() as f64 - 160.0) / 200.0) as f64).min(0.5);
        feat("long_url", v, 1.0);
        reasons.push("unusually long URL".into());
    }

    if path.matches('%').count() >= 3 {
        feat("pct_encoding", 1.0, 0.8);
        reasons.push("heavy percent-encoding".into());
    }

    if parsed.as_ref().and_then(|u| u.port()).is_some() {
        feat("nonstd_port", 1.0, 0.5);
        reasons.push("explicit non-standard port".into());
    }

    // A host-level red flag must be present to ever flag a page.
    const STRONG: &[&str] = &[
        "ip_host", "homoglyph", "brand_impersonation", "risky_tld",
        "shortener", "at_trick",
    ];
    let strong = values.iter().any(|(n, _)| STRONG.contains(n))
        // Very high host entropy (random-looking domain) also counts.
        || values.iter().any(|(n, v)| *n == "host_entropy" && *v > 0.8);

    Features { base_z: z, values, reasons, strong }
}

fn verdict(score: f64, strong: bool, reasons: Vec<String>) -> Verdict {
    Verdict {
        // High score AND a real host-level signal — never on weak signals
        // (length/words/encoding) alone.
        malicious: score >= THRESHOLD && strong,
        score,
        reasons,
    }
}

/// Classify a URL with the base (static) model only. Pure function — the
/// precision/recall tests pin this so the shipped model stays measurable.
pub fn classify(raw_url: &str) -> Verdict {
    let f = extract_features(raw_url);
    let score = 1.0 / (1.0 + (-f.base_z).exp());
    verdict(score, f.strong, f.reasons)
}

/// Classify with the trained ONNX model (real ML) plus the on-device
/// self-adapting layer on top (see [`crate::model`] and [`crate::adapt`]).
/// This is what runs before navigation. If the model is unavailable it falls
/// back to the interpretable linear base score; either way the SEAL adapter
/// applies and the host-signal gate still guards against false positives.
pub fn classify_adapted(raw_url: &str) -> Verdict {
    let f = extract_features(raw_url);
    let z = base_logit(&f) + crate::adapt::delta(&f.values);
    let score = 1.0 / (1.0 + (-z).exp());
    verdict(score, f.strong, f.reasons)
}

/// The base logit the adapter corrects: the trained ONNX model's probability
/// (as a logit) if the model is available, else the interpretable linear
/// `base_z`. Both `classify_adapted` and the SEAL adapter's learning use this,
/// so the adapter always corrects the base scorer that is actually in use.
pub fn base_logit(f: &Features) -> f64 {
    match crate::model::score(&f.vector()) {
        Some(p) => {
            let p = p.clamp(1e-6, 1.0 - 1e-6);
            (p / (1.0 - p)).ln()
        }
        None => f.base_z,
    }
}

fn to_list(set: &HashSet<&str>) -> String {
    let mut v: Vec<&&str> = set.iter().collect();
    v.sort();
    v.into_iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_urls_score_low() {
        for u in [
            "https://www.google.com/search?q=rust",
            "https://en.wikipedia.org/wiki/Tor_(network)",
            "https://github.com/tauri-apps/cef-rs",
            "https://news.ycombinator.com/",
            "https://www.amazon.com/dp/B08N5WRWNW",
            "https://mail.google.com/mail/u/0/",
        ] {
            let v = classify(u);
            assert!(!v.malicious, "false positive on {u}: score={:.2}", v.score);
        }
    }

    #[test]
    fn phishing_shaped_urls_score_high() {
        for u in [
            "http://paypal.secure-login.account-verify.ru/webscr?cmd=login",
            "http://192.168.44.7:8080/login/verify/account/update.php",
            "https://appleid.apple.com.verify-account.suspended-security.xyz/",
            "http://xn--pypal-4ve.com/signin/confirm/password",
            "http://g00gle-account-recovery.tk/unlock/verify",
        ] {
            let v = classify(u);
            assert!(v.malicious, "missed phishing {u}: score={:.2}", v.score);
        }
    }

    #[test]
    fn threshold_precision_recall_on_labeled_set() {
        // Balanced labeled set: benign top sites vs phishing-shaped URLs.
        let benign = [
            "https://www.google.com/",
            "https://www.youtube.com/watch?v=x",
            "https://www.wikipedia.org/",
            "https://www.reddit.com/r/rust/",
            "https://stackoverflow.com/questions/12345",
            "https://www.microsoft.com/en-us/",
            "https://www.apple.com/iphone/",
            "https://www.paypal.com/us/signin",
            "https://accounts.google.com/signin",
            "https://www.bankofamerica.com/",
        ];
        let phishing = [
            "http://paypal.com-webapps-login.ru/cmd/verify",
            "http://secure-apple-id.confirm-account.xyz/login",
            "http://192.0.2.11/wp-admin/paypal/login.php",
            "http://amaz0n-billing-update.tk/account/verify",
            "http://microsoft-office365.secure-login.cf/auth",
            "http://xn--nvda-hpa.com/account/unlock",
            "http://netflix-payment-declined.click/update-billing",
            "http://chase-online.verify-identity.gq/signin",
            "http://coinbase-wallet.recover-seed.top/authenticate",
            "http://dhl-parcel.tracking-suspend.loan/confirm",
        ];

        let mut tp = 0;
        let mut fp = 0;
        let mut fnn = 0;
        let mut tn = 0;
        for u in benign {
            if classify(u).malicious { fp += 1 } else { tn += 1 }
        }
        for u in phishing {
            if classify(u).malicious { tp += 1 } else { fnn += 1 }
        }
        let precision = tp as f64 / (tp + fp).max(1) as f64;
        let recall = tp as f64 / (tp + fnn).max(1) as f64;
        eprintln!(
            "Huma Guard: tp={tp} fp={fp} fn={fnn} tn={tn} precision={precision:.2} recall={recall:.2}"
        );
        // Require strong precision (few false positives) and good recall.
        assert!(precision >= 0.85, "precision too low: {precision:.2}");
        assert!(recall >= 0.80, "recall too low: {recall:.2}");
    }
}
