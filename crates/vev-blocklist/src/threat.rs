//! Live threat feeds: phishing/malware hostnames plus botnet C2 IPs.
//!
//! Every source here is a **full downloadable feed** fetched on a schedule
//! and checked locally — no URL, host, or hash ever leaves the machine
//! (unlike lookup APIs such as Google Safe Browsing v4). Sources were chosen
//! for licenses that permit redistribution/local caching in a third-party
//! product:
//!
//! - URLhaus host file (abuse.ch, CC0)
//! - Feodo Tracker botnet C2 IPs (abuse.ch, CC0)
//! - OpenPhish community feed (free feed)
//! - Phishing.Database active domains (MIT)
//! - PhishTank verified-online phish URLs (free feed, no key)
//! - Spamhaus DROP hijacked/criminal netblocks (free use)
//!
//! Deliberately absent: CISA KEV (catalogs exploited CVEs, not hosts, so it
//! cannot feed a navigation blocklist), HaGeZi TIF (smallest variant is a
//! 33 MB download — too heavy for a 6-hourly refresh on user machines), and
//! the abuse.ch SSL Blacklist IP list (deprecated upstream 2025-01-03).
//!
//! A refresh tolerates individual source failures — whatever fetched merges
//! in; the refresh only errors when *every* source fails.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

enum Kind {
    /// Host file ("0.0.0.0 evil.example") or bare domain-per-line list.
    Hosts,
    /// One URL per line; the host is extracted.
    Urls,
    /// PhishTank CSV: phish_id,url,... ; the URL column's host is extracted.
    PhishTankCsv,
    /// One IPv4 per line.
    Ips,
    /// Spamhaus DROP: "1.2.3.0/24 ; SBL123" CIDR-per-line.
    Cidrs,
}

const SOURCES: &[(&str, &str, Kind)] = &[
    (
        "urlhaus",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        Kind::Hosts,
    ),
    (
        "openphish",
        "https://openphish.com/feed.txt",
        Kind::Urls,
    ),
    (
        "phishing-database",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        Kind::Hosts,
    ),
    (
        "phishtank",
        "https://data.phishtank.com/data/online-valid.csv",
        Kind::PhishTankCsv,
    ),
    (
        "feodo-tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        Kind::Ips,
    ),
    (
        "spamhaus-drop",
        "https://www.spamhaus.org/drop/drop.txt",
        Kind::Cidrs,
    ),
];

/// Merged hostnames cache (one per line).
const HOSTS_CACHE: &str = "threatfeed.txt";
/// Merged IP/CIDR cache (one per line, bare IPs and `a.b.c.d/nn` ranges).
const IPS_CACHE: &str = "threatfeed-ips.txt";

#[derive(Default)]
pub struct ThreatFeed {
    hosts: HashSet<String>,
    ips: HashSet<Ipv4Addr>,
    /// CIDR ranges as (network address bits, prefix length).
    ranges: Vec<(u32, u8)>,
}

fn parse_hostfile(text: &str, set: &mut HashSet<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Hostfile format: "0.0.0.0 evil.example" or bare "evil.example".
        let host = line.split_whitespace().last().unwrap_or(line);
        if host == "0.0.0.0" || host == "127.0.0.1" || host == "localhost" {
            continue;
        }
        set.insert(host.to_ascii_lowercase());
    }
}

fn parse_url_lines(text: &str, set: &mut HashSet<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(host) = url::Url::parse(line).ok().and_then(|u| u.host_str().map(String::from)) {
            set.insert(host.to_ascii_lowercase());
        }
    }
}

/// Extract the second CSV column (the URL), tolerating quoted fields.
fn phishtank_url(line: &str) -> Option<&str> {
    let rest = &line[line.find(',')? + 1..];
    if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()
    } else {
        rest.split(',').next()
    }
}

fn parse_phishtank_csv(text: &str, set: &mut HashSet<String>) {
    for line in text.lines().skip(1) {
        if let Some(host) = phishtank_url(line)
            .and_then(|u| url::Url::parse(u.trim()).ok())
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        {
            set.insert(host);
        }
    }
}

fn parse_ip_lines(text: &str, set: &mut HashSet<Ipv4Addr>) {
    for line in text.lines() {
        let line = line.trim();
        if let Ok(ip) = line.parse::<Ipv4Addr>() {
            set.insert(ip);
        }
    }
}

fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (net, prefix) = s.split_once('/')?;
    let net: Ipv4Addr = net.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    (prefix <= 32).then(|| (u32::from(net), prefix))
}

fn parse_drop(text: &str, ranges: &mut Vec<(u32, u8)>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        // DROP format: "1.2.3.0/24 ; SBL123".
        let cidr = line.split(';').next().unwrap_or(line).trim();
        if let Some(r) = parse_cidr(cidr) {
            ranges.push(r);
        }
    }
}

fn in_range(ip: Ipv4Addr, (net, prefix): (u32, u8)) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (u32::from(ip) & mask) == (net & mask)
}

/// Generous body cap: Phishing.Database ACTIVE is ~11 MB and growing; ureq's
/// default limit is 10 MB.
const BODY_LIMIT: u64 = 64 * 1024 * 1024;

fn http_get(url: &str) -> Result<String, String> {
    ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .call()
        .map_err(|e| format!("fetch: {e}"))?
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_string()
        .map_err(|e| format!("read: {e}"))
}

impl ThreatFeed {
    pub fn len(&self) -> usize {
        self.hosts.len() + self.ips.len() + self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True if `host` (a hostname or an IPv4 literal) is on any feed.
    pub fn contains(&self, host: &str) -> bool {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return self.ips.contains(&ip) || self.ranges.iter().any(|&r| in_range(ip, r));
        }
        self.hosts.contains(&host.to_ascii_lowercase())
    }

    pub fn insert_host(&mut self, host: &str) {
        self.hosts.insert(host.to_ascii_lowercase());
    }

    fn merge(&mut self, kind: &Kind, text: &str) -> usize {
        let before = self.len();
        match kind {
            Kind::Hosts => parse_hostfile(text, &mut self.hosts),
            Kind::Urls => parse_url_lines(text, &mut self.hosts),
            Kind::PhishTankCsv => parse_phishtank_csv(text, &mut self.hosts),
            Kind::Ips => parse_ip_lines(text, &mut self.ips),
            Kind::Cidrs => parse_drop(text, &mut self.ranges),
        }
        self.len() - before
    }

    /// Load the cached feeds from `data_dir` (empty if not yet fetched).
    pub fn load_cache(data_dir: &Path) -> Self {
        let mut feed = Self::default();
        if let Ok(text) = std::fs::read_to_string(data_dir.join(HOSTS_CACHE)) {
            parse_hostfile(&text, &mut feed.hosts);
        }
        if let Ok(text) = std::fs::read_to_string(data_dir.join(IPS_CACHE)) {
            for line in text.lines() {
                let line = line.trim();
                if line.contains('/') {
                    if let Some(r) = parse_cidr(line) {
                        feed.ranges.push(r);
                    }
                } else if let Ok(ip) = line.parse::<Ipv4Addr>() {
                    feed.ips.insert(ip);
                }
            }
        }
        feed
    }

    pub fn save_cache(&self, data_dir: &Path) -> Result<(), String> {
        let hosts: String = {
            let mut v: Vec<&String> = self.hosts.iter().collect();
            v.sort();
            v.into_iter().cloned().collect::<Vec<_>>().join("\n")
        };
        std::fs::write(data_dir.join(HOSTS_CACHE), hosts)
            .map_err(|e| format!("write {HOSTS_CACHE}: {e}"))?;

        let mut ips: Vec<String> = self.ips.iter().map(|ip| ip.to_string()).collect();
        ips.sort();
        for &(net, prefix) in &self.ranges {
            ips.push(format!("{}/{prefix}", Ipv4Addr::from(net)));
        }
        std::fs::write(data_dir.join(IPS_CACHE), ips.join("\n"))
            .map_err(|e| format!("write {IPS_CACHE}: {e}"))
    }

    /// Fetch all feeds from the network. Blocking. Individual source failures
    /// are tolerated and reported in the per-source summary; errors only when
    /// every source fails.
    pub fn fetch() -> Result<(Self, Vec<String>), String> {
        let mut feed = Self::default();
        let mut summary = Vec::with_capacity(SOURCES.len());
        let mut any_ok = false;
        for (name, url, kind) in SOURCES {
            match http_get(url) {
                Ok(text) => {
                    let n = feed.merge(kind, &text);
                    any_ok = true;
                    summary.push(format!("{name}: +{n}"));
                }
                Err(e) => summary.push(format!("{name}: FAILED ({e})")),
            }
        }
        if any_ok {
            Ok((feed, summary))
        } else {
            Err(format!("all threat feeds failed: {}", summary.join("; ")))
        }
    }

    /// Construct directly from host-file text (used to seed a known-bad host
    /// in tests and verification).
    pub fn from_text(text: &str) -> Self {
        let mut feed = Self::default();
        parse_hostfile(text, &mut feed.hosts);
        feed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hostfile_forms_and_skips_noise() {
        let f = ThreatFeed::from_text(
            "# comment\n0.0.0.0 evil.example\nbad.test\n0.0.0.0 localhost\n\n",
        );
        assert!(f.contains("evil.example"));
        assert!(f.contains("BAD.TEST")); // case-insensitive
        assert!(!f.contains("localhost"));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn parses_url_feed_to_hosts() {
        let mut f = ThreatFeed::default();
        f.merge(
            &Kind::Urls,
            "https://phish.example/login\nhttp://also-bad.test/x?y=1\n# note\n",
        );
        assert!(f.contains("phish.example"));
        assert!(f.contains("also-bad.test"));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn parses_phishtank_csv() {
        let mut f = ThreatFeed::default();
        f.merge(
            &Kind::PhishTankCsv,
            "phish_id,url,phish_detail_url\n\
             1,\"http://quoted.example/a,b\",detail\n\
             2,http://plain.example/c,detail\n",
        );
        assert!(f.contains("quoted.example"));
        assert!(f.contains("plain.example"));
    }

    #[test]
    fn matches_c2_ips_and_drop_ranges() {
        let mut f = ThreatFeed::default();
        f.merge(&Kind::Ips, "# c2\n192.0.2.44\nnot-an-ip\n");
        f.merge(&Kind::Cidrs, "; DROP\n198.51.100.0/24 ; SBL999\n");
        assert!(f.contains("192.0.2.44"));
        assert!(!f.contains("192.0.2.45"));
        assert!(f.contains("198.51.100.7")); // inside the /24
        assert!(!f.contains("198.51.101.7")); // outside
    }

    /// Live-network check that every source URL still resolves and parses to
    /// a non-trivial count. Run explicitly: cargo test -p vev-blocklist -- --ignored
    #[test]
    #[ignore = "network"]
    fn live_fetch_all_sources() {
        let (feed, summary) = ThreatFeed::fetch().expect("all sources failed");
        eprintln!("live fetch: {}", summary.join("\n            "));
        // PhishTank rate-limits aggressively (429) when polled more than a
        // few times per hour; that's expected on repeated test runs.
        assert!(
            !summary
                .iter()
                .any(|s| s.contains("FAILED") && !s.contains("status: 429")),
            "some sources failed: {summary:?}"
        );
        assert!(feed.len() > 10_000, "suspiciously small merge: {}", feed.len());
    }

    #[test]
    fn cache_roundtrip_preserves_hosts_ips_and_ranges() {
        let dir = std::env::temp_dir().join(format!("vevtf{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = ThreatFeed::from_text("evil.example\n");
        f.merge(&Kind::Ips, "192.0.2.44\n");
        f.merge(&Kind::Cidrs, "198.51.100.0/24 ; SBL999\n");
        f.save_cache(&dir).unwrap();

        let g = ThreatFeed::load_cache(&dir);
        assert!(g.contains("evil.example"));
        assert!(g.contains("192.0.2.44"));
        assert!(g.contains("198.51.100.200"));
        assert_eq!(g.len(), f.len());
    }
}
