//! Huma deep scan — multi-source online threat intelligence.
//!
//! This is the **opt-in, on-demand** layer that verifies a URL against several
//! independent threat feeds and combines them, alongside the local ML model,
//! into a single "how dangerous is this" percentage. It is deliberately *not*
//! automatic: querying these services sends the URL off the device, which
//! would break Vev's privacy promise if it ran on every navigation. The
//! everyday Guard (local model + locally-downloaded blocklists) stays fully
//! on-device; deep scan is what you reach for on a grey-area link.
//!
//! Sources (each runs concurrently, with a short timeout; any failure yields
//! an "unknown" that simply doesn't vote):
//!   - Google Safe Browsing (threatMatches lookup)
//!   - VirusTotal (70+ engine consensus)
//!   - abuse.ch URLhaus (malware URLs) and ThreatFox (IOCs)
//!   - AlienVault OTX (community pulses)
//!   - the local Huma model, as one more voter
//!
//! Keys come from the user's local config and never touch the repo.

use serde::Serialize;
use std::time::Duration;

#[derive(Default, Clone)]
pub struct IntelKeys {
    pub safe_browsing: Option<String>,
    pub virustotal: Option<String>,
    pub abusech: Option<String>,
    pub otx: Option<String>,
    /// Full proxy URL for a private route — `socks5://host:port` (the
    /// embedded Tor bridge) or `http(s)://host:port` (a custom proxy such as
    /// Mullvad). When set, every scan request routes through it so the
    /// reputation services see the proxy's exit IP, not the user's real one.
    pub proxy: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Malicious,
    Clean,
    Unknown,
}

#[derive(Clone, Serialize)]
pub struct Signal {
    pub source: String,
    pub verdict: Verdict,
    pub detail: String,
    /// Authority weight of this source when it returns a definite verdict.
    pub weight: f64,
}

impl Signal {
    fn unknown(source: &str) -> Self {
        Signal { source: source.into(), verdict: Verdict::Unknown, detail: "no data".into(), weight: 0.0 }
    }
    fn mal(source: &str, weight: f64, detail: impl Into<String>) -> Self {
        Signal { source: source.into(), verdict: Verdict::Malicious, detail: detail.into(), weight }
    }
    fn clean(source: &str, weight: f64) -> Self {
        Signal { source: source.into(), verdict: Verdict::Clean, detail: "no detections".into(), weight }
    }

    /// A malicious vote from a caller-provided source (e.g. the sandbox's
    /// rendered-content analysis) to combine with the online signals.
    pub fn source_malicious(source: &str, weight: f64, detail: impl Into<String>) -> Self {
        Self::mal(source, weight, detail)
    }

    /// A clean vote from a caller-provided source.
    pub fn source_clean(source: &str, weight: f64) -> Self {
        Self::clean(source, weight)
    }
}

#[derive(Serialize)]
pub struct IntelReport {
    pub url: String,
    /// 0..=100 combined danger score.
    pub percent: u8,
    pub malicious: bool,
    pub signals: Vec<Signal>,
    /// True if the scan was routed through Tor (IP not exposed to the sources).
    pub tor: bool,
}

/// `proxy` is a full proxy URL (`socks5://host:port` or `http://host:port`),
/// or None for a direct connection. Callers pass a private route (Tor or a
/// configured custom proxy) so a scan never exposes the user's real IP.
fn agent(proxy: Option<&str>) -> ureq::Agent {
    let mut cfg = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(12)));
    if let Some(url) = proxy {
        if let Ok(p) = ureq::Proxy::new(url) {
            cfg = cfg.proxy(Some(p));
        }
    }
    ureq::Agent::new_with_config(cfg.build())
}

fn host_of(url: &str) -> String {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default()
}

// ---- Google Safe Browsing (URL never stored; lookup by threatMatches) ----
fn google_safe_browsing(url: &str, key: &str, proxy: Option<&str>) -> Signal {
    let body = serde_json::json!({
        "client": {"clientId": "vev-browser", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    });
    let endpoint = format!("https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}");
    match agent(proxy).post(&endpoint).header("content-type", "application/json").send(body.to_string()) {
        Ok(mut r) => {
            let txt = r.body_mut().read_to_string().unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
            match v.get("matches").and_then(|m| m.as_array()) {
                Some(m) if !m.is_empty() => {
                    let t = m[0].get("threatType").and_then(|x| x.as_str()).unwrap_or("threat");
                    Signal::mal("Google Safe Browsing", 3.0, format!("listed: {t}"))
                }
                _ => Signal::clean("Google Safe Browsing", 2.0),
            }
        }
        Err(_) => Signal::unknown("Google Safe Browsing"),
    }
}

// ---- VirusTotal v3 (engine consensus) ----
fn virustotal(url: &str, key: &str, proxy: Option<&str>) -> Signal {
    use base64::Engine;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());
    let endpoint = format!("https://www.virustotal.com/api/v3/urls/{id}");
    match agent(proxy).get(&endpoint).header("x-apikey", key).call() {
        Ok(mut r) => {
            let txt = r.body_mut().read_to_string().unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
            let stats = &v["data"]["attributes"]["last_analysis_stats"];
            let mal = stats["malicious"].as_u64().unwrap_or(0);
            let susp = stats["suspicious"].as_u64().unwrap_or(0);
            if mal + susp >= 2 {
                Signal::mal("VirusTotal", 2.5, format!("{mal} malicious / {susp} suspicious engines"))
            } else if v.get("data").is_some() {
                Signal::clean("VirusTotal", 1.5)
            } else {
                Signal::unknown("VirusTotal")
            }
        }
        Err(_) => Signal::unknown("VirusTotal"),
    }
}

// ---- abuse.ch URLhaus (malware URLs) ----
fn urlhaus(url: &str, key: &str, proxy: Option<&str>) -> Signal {
    match agent(proxy).post("https://urlhaus-api.abuse.ch/v1/url/")
        .header("Auth-Key", key)
        .header("content-type", "application/x-www-form-urlencoded")
        .send(format!("url={}", urlencode(url)))
    {
        Ok(mut r) => {
            let txt = r.body_mut().read_to_string().unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
            match v.get("query_status").and_then(|x| x.as_str()) {
                Some("ok") => {
                    let threat = v.get("threat").and_then(|x| x.as_str()).unwrap_or("malware");
                    Signal::mal("URLhaus", 2.5, format!("known {threat}"))
                }
                Some("no_results") => Signal::clean("URLhaus", 1.0),
                _ => Signal::unknown("URLhaus"),
            }
        }
        Err(_) => Signal::unknown("URLhaus"),
    }
}

// ---- abuse.ch ThreatFox (IOCs / C2) ----
fn threatfox(url: &str, key: &str, proxy: Option<&str>) -> Signal {
    let host = host_of(url);
    let body = serde_json::json!({"query": "search_ioc", "search_term": host});
    match agent(proxy).post("https://threatfox-api.abuse.ch/api/v1/")
        .header("Auth-Key", key)
        .header("content-type", "application/json")
        .send(body.to_string())
    {
        Ok(mut r) => {
            let txt = r.body_mut().read_to_string().unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
            match v.get("query_status").and_then(|x| x.as_str()) {
                Some("ok") => Signal::mal("ThreatFox", 1.3, "known malware IOC"),
                Some("no_result") | Some("illegal_search_term") => Signal::clean("ThreatFox", 0.8),
                _ => Signal::unknown("ThreatFox"),
            }
        }
        Err(_) => Signal::unknown("ThreatFox"),
    }
}

// ---- AlienVault OTX (community pulses) ----
fn otx(url: &str, key: &str, proxy: Option<&str>) -> Signal {
    let endpoint = format!("https://otx.alienvault.com/api/v1/indicators/url/{}/general", urlencode(url));
    match agent(proxy).get(&endpoint).header("X-OTX-API-KEY", key).call() {
        Ok(mut r) => {
            let txt = r.body_mut().read_to_string().unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
            let count = v["pulse_info"]["count"].as_u64().unwrap_or(0);
            if count >= 2 {
                Signal::mal("AlienVault OTX", 1.5, format!("{count} threat pulses"))
            } else {
                Signal::clean("AlienVault OTX", 0.8)
            }
        }
        Err(_) => Signal::unknown("AlienVault OTX"),
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Combine signals (plus the local model's probability) into a percentage.
/// A definite Malicious from a high-authority source dominates; clean votes
/// pull it down; unknowns don't vote.
pub fn aggregate(url: &str, local_prob: f64, mut signals: Vec<Signal>) -> IntelReport {
    // The local model is one more voter.
    let local = if local_prob >= 0.6 {
        Signal::mal("Huma model", 1.5 + local_prob, format!("{}% (on-device)", (local_prob * 100.0) as u32))
    } else {
        Signal::clean("Huma model", 1.0)
    };
    signals.insert(0, local);

    let mut mal_w = 0.0;
    let mut clean_w = 0.0;
    for s in &signals {
        match s.verdict {
            Verdict::Malicious => mal_w += s.weight,
            Verdict::Clean => clean_w += s.weight,
            Verdict::Unknown => {}
        }
    }
    // Weighted danger fraction, with a mild prior toward clean so a single
    // weak hit isn't automatically "high".
    let percent = if mal_w + clean_w <= 0.0 {
        (local_prob * 100.0) as u8
    } else {
        ((mal_w / (mal_w + clean_w + 0.5)) * 100.0).round().clamp(0.0, 100.0) as u8
    };
    // Malicious if a high-authority source flagged it, or several agree.
    let mal_hits = signals.iter().filter(|s| s.verdict == Verdict::Malicious).count();
    let strong = signals.iter().any(|s| s.verdict == Verdict::Malicious && s.weight >= 2.5);
    let malicious = strong || mal_hits >= 2 || percent >= 60;
    // A definite hit from a high-authority feed reads as clearly dangerous
    // regardless of how many clean votes there are.
    let percent = if strong { percent.max(88) } else { percent };

    IntelReport { url: url.to_string(), percent, malicious, signals, tor: false }
}

/// Run every configured source concurrently and return the raw signals,
/// without aggregating — for callers (like the pre-open sandbox) that add
/// their own voters before calling [`aggregate`]. Blocking.
pub fn scan_signals(url: &str, keys: &IntelKeys) -> Vec<Signal> {
    let mut handles: Vec<std::thread::JoinHandle<Signal>> = Vec::new();
    let u = url.to_string();

    let proxy = keys.proxy.clone();
    macro_rules! spawn_if {
        ($key:expr, $f:ident) => {
            if let Some(k) = $key.clone() {
                let u = u.clone();
                let px = proxy.clone();
                handles.push(std::thread::spawn(move || $f(&u, &k, px.as_deref())));
            }
        };
    }
    spawn_if!(keys.safe_browsing, google_safe_browsing);
    spawn_if!(keys.virustotal, virustotal);
    spawn_if!(keys.abusech, urlhaus);
    spawn_if!(keys.abusech, threatfox);
    spawn_if!(keys.otx, otx);

    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

/// Run every configured source concurrently and aggregate. `local_prob` is the
/// on-device model's phishing probability for the URL.
pub fn scan(url: &str, keys: &IntelKeys, local_prob: f64) -> IntelReport {
    let signals = scan_signals(url, keys);
    let mut report = aggregate(url, local_prob, signals);
    report.tor = keys.proxy.is_some();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_source_makes_it_malicious() {
        let r = aggregate("https://evil.example/", 0.4, vec![
            Signal::mal("Google Safe Browsing", 3.0, "listed"),
            Signal::clean("AlienVault OTX", 0.8),
        ]);
        assert!(r.malicious);
        assert!(r.percent >= 60, "percent {}", r.percent);
    }

    #[test]
    fn all_clean_is_low() {
        let r = aggregate("https://good.example/", 0.1, vec![
            Signal::clean("Google Safe Browsing", 2.0),
            Signal::clean("VirusTotal", 1.5),
            Signal::clean("URLhaus", 1.0),
        ]);
        assert!(!r.malicious);
        assert!(r.percent < 30, "percent {}", r.percent);
    }

    #[test]
    fn two_weak_hits_agree() {
        let r = aggregate("https://x.example/", 0.5, vec![
            Signal::mal("ThreatFox", 1.3, "ioc"),
            Signal::mal("AlienVault OTX", 1.5, "pulses"),
            Signal::clean("VirusTotal", 1.5),
        ]);
        assert!(r.malicious, "two malicious sources should flag");
    }

    #[test]
    fn unknowns_dont_vote() {
        let r = aggregate("https://x.example/", 0.2, vec![
            Signal::unknown("VirusTotal"),
            Signal::unknown("URLhaus"),
            Signal::clean("Google Safe Browsing", 2.0),
        ]);
        assert!(!r.malicious);
    }
}
