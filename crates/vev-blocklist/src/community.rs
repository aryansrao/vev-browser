//! Vev community phishing feed.
//!
//! A globally-maintained, crowd-confirmed list of phishing hosts, seeded by
//! Vev's on-device AI (Huma Guard) and confirmed by real users. The list is a
//! public JSON file (default: a Vev GitHub repo, fetched at runtime like the
//! URLhaus threat feed — never bundled), so anyone can audit it and a GitHub
//! Action can maintain it with no server. Each host carries a **percentage**
//! (share of reports that confirmed it is phishing) and a report count, so the
//! browser can show "community-confirmed phishing: 92% (40 reports)".
//!
//! Format (`flagged.json`):
//! ```json
//! { "version": 1,
//!   "hosts": {
//!     "secure-paypal.account-verify.tk": { "percent": 92, "reports": 40 }
//!   } }
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Default public feed location. Users/forks can override via config; the repo
/// is maintained by a GitHub Action that aggregates reports into flagged.json.
pub const DEFAULT_FEED_URL: &str =
    "https://raw.githubusercontent.com/aryansrao/community-phishing-feed/main/flagged.json";

#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize)]
pub struct HostFlag {
    /// Share of community reports that confirmed phishing, 0..=100.
    pub percent: u8,
    /// Number of reports backing the entry.
    pub reports: u32,
}

#[derive(Deserialize)]
struct FeedFile {
    #[serde(default)]
    hosts: HashMap<String, HostFlag>,
}

#[derive(Default)]
pub struct CommunityFeed {
    hosts: HashMap<String, HostFlag>,
}

fn parse(text: &str) -> HashMap<String, HostFlag> {
    serde_json::from_str::<FeedFile>(text)
        .map(|f| {
            f.hosts
                .into_iter()
                .map(|(h, v)| (h.to_ascii_lowercase(), v))
                .filter(|(_, v)| v.percent <= 100)
                .collect()
        })
        .unwrap_or_default()
}

impl CommunityFeed {
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Look up a host (or its parent domains) in the feed.
    pub fn lookup(&self, host: &str) -> Option<HostFlag> {
        let host = host.to_ascii_lowercase();
        if let Some(f) = self.hosts.get(&host) {
            return Some(*f);
        }
        // Also match a parent domain entry (e.g. feed lists "evil.tk", request
        // is "login.evil.tk").
        let mut rest = host.as_str();
        while let Some(idx) = rest.find('.') {
            rest = &rest[idx + 1..];
            if let Some(f) = self.hosts.get(rest) {
                return Some(*f);
            }
        }
        None
    }

    pub fn load_cache(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self { hosts: parse(&text) },
            Err(_) => Self::default(),
        }
    }

    pub fn save_cache(&self, path: &Path, raw: &str) -> Result<(), String> {
        std::fs::write(path, raw).map_err(|e| format!("write {path:?}: {e}"))
    }

    /// Fetch the feed JSON from `url`. Blocking; returns (feed, raw_json).
    pub fn fetch(url: &str) -> Result<(Self, String), String> {
        let body = ureq::get(url)
            .config()
            .timeout_global(Some(Duration::from_secs(20)))
            .build()
            .call()
            .map_err(|e| format!("community feed fetch: {e}"))?
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("community feed read: {e}"))?;
        Ok((Self { hosts: parse(&body) }, body))
    }

    pub fn from_text(text: &str) -> Self {
        Self { hosts: parse(text) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_looks_up_with_parent_match() {
        let f = CommunityFeed::from_text(
            r#"{ "version":1, "hosts": {
                 "evil.tk": { "percent": 92, "reports": 40 },
                 "bad.example.com": { "percent": 100, "reports": 5 }
               } }"#,
        );
        assert_eq!(f.len(), 2);
        assert_eq!(f.lookup("evil.tk").unwrap().percent, 92);
        // Subdomain matches the parent entry.
        assert_eq!(f.lookup("login.evil.tk").unwrap().reports, 40);
        // Case-insensitive.
        assert_eq!(f.lookup("BAD.EXAMPLE.COM").unwrap().percent, 100);
        assert!(f.lookup("safe.example.org").is_none());
    }

    #[test]
    fn rejects_bad_percent_and_bad_json() {
        assert!(CommunityFeed::from_text("not json").is_empty());
        let f = CommunityFeed::from_text(
            r#"{ "hosts": { "x.tk": { "percent": 250, "reports": 1 } } }"#,
        );
        assert!(f.is_empty(), "percent >100 must be rejected");
    }
}
