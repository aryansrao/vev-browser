//! Vev blocklist engine: layered ad/tracker/threat blocking.
//!
//! Layer 1 — network filtering via adblock-rust (EasyList/EasyPrivacy syntax)
//! Layer 2 — cosmetic filtering (element-hiding CSS injected at the CEF layer)
//! Layer 3 — live threat feed (URLhaus, CC0) for phishing/malware hosts
//! Layer 4 — user allow/blocklist, which overrides the automatic layers
//!
//! Pure logic + I/O for list management; no CEF dependency, so the matching
//! is unit-testable directly.

use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use adblock::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

mod community;
mod threat;
pub use community::{CommunityFeed, HostFlag, DEFAULT_FEED_URL};
pub use threat::ThreatFeed;

/// Supplementary list shipped in the binary so blocking works offline.
const SUPPLEMENTARY: &str = include_str!("lists/vev-supplementary.txt");

/// YouTube ad-skip scriptlet (network blocking can't remove in-player ads).
pub const YOUTUBE_SCRIPT: &str = include_str!("youtube.js");

/// True if `url` is a YouTube page that should get the ad-skip scriptlet.
pub fn is_youtube(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .map(|h| {
            h == "youtube.com"
                || h.ends_with(".youtube.com")
                || h == "youtu.be"
                || h.ends_with(".youtube-nocookie.com")
        })
        .unwrap_or(false)
}

/// Filenames of optional full lists loaded from the app data `blocklists`
/// dir when present (fetched/refreshed on the update schedule).
const OPTIONAL_LISTS: &[&str] = &["easylist.txt", "easyprivacy.txt"];

/// The user's personal allow/blocklist, persisted as JSON.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserRules {
    /// Domains the user always allows (override automatic blocking).
    pub allow: Vec<String>,
    /// Domains the user always blocks.
    pub block: Vec<String>,
}

impl UserRules {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("user-rules.json: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("read {path:?}: {e}")),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let j = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, j).map_err(|e| format!("write {path:?}: {e}"))
    }
}

pub struct BlockDecision {
    pub blocked: bool,
    /// "network" | "user" | "threat" — which layer decided, for logging.
    pub reason: &'static str,
}

pub struct Blocklist {
    engine: Engine,
    // Behind a lock so the "Allow"/"Block" actions take effect immediately on
    // the running engine, not only after a restart (the on-disk user-rules
    // file is updated too, for persistence).
    user_allow: RwLock<HashSet<String>>,
    user_block: RwLock<HashSet<String>>,
    threat: RwLock<ThreatFeed>,
    community: RwLock<CommunityFeed>,
    community_url: RwLock<String>,
    data_dir: PathBuf,
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(|h| h.to_string())
}

/// Does `host` equal `pattern` or a subdomain of it?
fn host_matches(host: &str, pattern: &str) -> bool {
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

impl Blocklist {
    /// Build the engine from the bundled supplementary list plus any full
    /// lists present in `data_dir/blocklists`, and load user rules + the
    /// cached threat feed from `data_dir`.
    pub fn load(data_dir: &Path) -> Self {
        let mut filter_set = FilterSet::new(false);
        let opts = ParseOptions::default();
        filter_set.add_filter_list(SUPPLEMENTARY, opts.clone());

        let lists_dir = data_dir.join("blocklists");
        let mut loaded_lists = vec!["vev-supplementary".to_string()];
        for name in OPTIONAL_LISTS {
            let p = lists_dir.join(name);
            if let Ok(text) = std::fs::read_to_string(&p) {
                filter_set.add_filter_list(&text, opts.clone());
                loaded_lists.push((*name).to_string());
            }
        }
        eprintln!("vev-blocklist: network lists loaded: {}", loaded_lists.join(", "));

        let engine = Engine::from_filter_set(filter_set, true);

        let user = UserRules::load(&data_dir.join("user-rules.json")).unwrap_or_default();
        let threat = ThreatFeed::load_cache(data_dir);
        eprintln!(
            "vev-blocklist: user allow={} block={}, threat hosts={}",
            user.allow.len(),
            user.block.len(),
            threat.len()
        );

        let community = CommunityFeed::load_cache(&data_dir.join("community-feed.json"));
        eprintln!("vev-blocklist: community feed hosts={}", community.len());

        Self {
            engine,
            user_allow: RwLock::new(user.allow.into_iter().collect()),
            user_block: RwLock::new(user.block.into_iter().collect()),
            threat: RwLock::new(threat),
            community: RwLock::new(community),
            community_url: RwLock::new(DEFAULT_FEED_URL.to_string()),
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// Override the community feed URL (from config).
    pub fn set_community_url(&self, url: String) {
        if let Ok(mut u) = self.community_url.write() {
            *u = url;
        }
    }

    /// Community-confirmed phishing status for a URL's host, if listed.
    pub fn community_flag(&self, url: &str) -> Option<HostFlag> {
        let host = host_of(url)?;
        self.community.read().ok()?.lookup(&host)
    }

    /// Refresh the community feed from the network and swap it in. Blocking;
    /// runs off the UI thread on the same schedule as the threat feed.
    pub fn refresh_community_feed(&self) -> Result<usize, String> {
        let url = self
            .community_url
            .read()
            .map(|u| u.clone())
            .unwrap_or_else(|_| DEFAULT_FEED_URL.to_string());
        let (feed, raw) = CommunityFeed::fetch(&url)?;
        let n = feed.len();
        let _ = feed.save_cache(&self.data_dir.join("community-feed.json"), &raw);
        if let Ok(mut c) = self.community.write() {
            *c = feed;
        }
        Ok(n)
    }

    /// Decide whether a resource request should be blocked. `request_type`
    /// is CEF's resource type mapped to adblock's vocabulary
    /// (script/image/stylesheet/sub_frame/xmlhttprequest/other).
    pub fn check(&self, url: &str, source_url: &str, request_type: &str) -> BlockDecision {
        let host = host_of(url).unwrap_or_default();

        // User rules win over everything.
        if let Ok(allow) = self.user_allow.read() {
            if allow.iter().any(|p| host_matches(&host, p)) {
                return BlockDecision { blocked: false, reason: "user" };
            }
        }
        if let Ok(block) = self.user_block.read() {
            if block.iter().any(|p| host_matches(&host, p)) {
                return BlockDecision { blocked: true, reason: "user" };
            }
        }

        // Network filter list.
        if let Ok(req) = Request::new(url, source_url, request_type) {
            let r = self.engine.check_network_request(&req);
            if r.matched {
                return BlockDecision { blocked: true, reason: "network" };
            }
        }

        BlockDecision { blocked: false, reason: "allow" }
    }

    /// Full-page threat check (phishing/malware host on the live feed).
    /// Applied to top-level navigations only.
    pub fn is_threat(&self, url: &str) -> bool {
        let Some(host) = host_of(url) else { return false };
        self.threat
            .read()
            .map(|t| t.contains(&host))
            .unwrap_or(false)
    }

    /// Element-hiding CSS for a page URL (cosmetic filtering), to be injected
    /// into the document by the CEF layer.
    pub fn cosmetic_css(&self, url: &str) -> String {
        let res = self.engine.url_cosmetic_resources(url);
        if res.hide_selectors.is_empty() {
            return String::new();
        }
        let mut selectors: Vec<&String> = res.hide_selectors.iter().collect();
        selectors.sort();
        format!(
            "{}{{display:none !important}}",
            selectors
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    pub fn add_user_block(&self, host: String) -> Result<(), String> {
        if let Ok(mut b) = self.user_block.write() {
            b.insert(host.clone());
        }
        if let Ok(mut a) = self.user_allow.write() {
            a.remove(&host);
        }
        self.mutate_user(|u| {
            u.allow.retain(|h| h != &host);
            if !u.block.contains(&host) {
                u.block.push(host.clone());
            }
        })
    }

    pub fn add_user_allow(&self, host: String) -> Result<(), String> {
        // Update the running engine immediately (was the "Allow doesn't work"
        // bug — only the on-disk file was updated before), then persist.
        if let Ok(mut a) = self.user_allow.write() {
            a.insert(host.clone());
        }
        if let Ok(mut b) = self.user_block.write() {
            b.remove(&host);
        }
        self.mutate_user(|u| {
            u.block.retain(|h| h != &host);
            if !u.allow.contains(&host) {
                u.allow.push(host.clone());
            }
        })
    }

    fn mutate_user(&self, f: impl FnOnce(&mut UserRules)) -> Result<(), String> {
        // Re-read from disk, apply, persist. User rules change rarely, so the
        // extra read is cheaper than holding another lock across the process.
        let path = self.data_dir.join("user-rules.json");
        let mut rules = UserRules::load(&path)?;
        f(&mut rules);
        rules.save(&path)
    }

    /// Seed the in-memory threat feed with a host (used by the verification
    /// self-test so the threat path is deterministic without depending on
    /// the live feed's current contents).
    pub fn seed_threat_host(&self, host: &str) {
        if let Ok(mut guard) = self.threat.write() {
            guard.insert_host(host);
        }
    }

    /// Refresh the threat feeds from the network and swap them in. Blocking;
    /// callers run this off the UI thread on a schedule. Individual source
    /// failures are tolerated (logged in the per-source summary); errors only
    /// when every source fails.
    pub fn refresh_threat_feed(&self) -> Result<usize, String> {
        let (fresh, summary) = ThreatFeed::fetch()?;
        eprintln!("vev-blocklist: threat sources: {}", summary.join(", "));
        let n = fresh.len();
        fresh.save_cache(&self.data_dir)?;
        if let Ok(mut guard) = self.threat.write() {
            *guard = fresh;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(dir: &Path) -> Blocklist {
        Blocklist::load(dir)
    }

    #[test]
    fn blocks_known_tracker_allows_first_party() {
        let dir = std::env::temp_dir().join(format!("vevbl{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bl = engine(&dir);

        // A known tracker script loaded from a first-party page is blocked.
        let d = bl.check(
            "https://www.google-analytics.com/analytics.js",
            "https://news.example.com/",
            "script",
        );
        assert!(d.blocked, "tracker should be blocked");
        assert_eq!(d.reason, "network");

        // First-party resource is not blocked.
        let d = bl.check(
            "https://news.example.com/app.js",
            "https://news.example.com/",
            "script",
        );
        assert!(!d.blocked, "first-party resource should pass");
    }

    #[test]
    fn user_rules_override() {
        let dir = std::env::temp_dir().join(format!("vevbl-user{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bl = engine(&dir);

        // User block on a normally-allowed host.
        bl.add_user_block("cdn.example.com".into()).unwrap();
        // Rebuild to pick up persisted rules.
        let bl = engine(&dir);
        let d = bl.check(
            "https://cdn.example.com/x.js",
            "https://site.example/",
            "script",
        );
        assert!(d.blocked && d.reason == "user");

        // User allow overrides a tracker match.
        bl.add_user_allow("google-analytics.com".into()).unwrap();
        let bl = engine(&dir);
        let d = bl.check(
            "https://www.google-analytics.com/analytics.js",
            "https://site.example/",
            "script",
        );
        assert!(!d.blocked && d.reason == "user");
    }

    #[test]
    fn host_matching_is_subdomain_aware() {
        assert!(host_matches("a.b.example.com", "example.com"));
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("notexample.com", "example.com"));
        assert!(!host_matches("example.com.evil.com", "example.com"));
    }
}
