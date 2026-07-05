//! Vev network hardening policy: DNS-over-HTTPS resolver selection,
//! HTTPS-only upgrade decisions, and the Chromium feature/preference set the
//! shell applies at startup. Pure logic — independently testable, no CEF.

use serde::Deserialize;
use std::path::Path;

/// A DoH resolver Vev is willing to use by default. The allowlist is
/// hardcoded by design; users can override via config (see
/// [`NetworkConfig`]), which requires an explicit opt-in flag for resolvers
/// outside this list.
pub struct DohResolver {
    pub name: &'static str,
    pub template: &'static str,
}

/// Hardcoded resolver allowlist. First entry is the default.
pub const RESOLVER_ALLOWLIST: &[DohResolver] = &[
    DohResolver {
        name: "quad9",
        template: "https://dns.quad9.net/dns-query",
    },
    DohResolver {
        name: "cloudflare",
        template: "https://cloudflare-dns.com/dns-query",
    },
    DohResolver {
        name: "mullvad",
        template: "https://dns.mullvad.net/dns-query",
    },
];

/// Chromium features enabled at startup (comma-joined into
/// --enable-features).
///
/// - EncryptedClientHello: ECH via HTTPS DNS records (requires secure DNS)
/// - ThirdPartyStoragePartitioning: partition storage/cache/communication
///   APIs by top-level site (CHIPS-style first-party isolation)
/// - TrackingProtection3pcd: enables Chromium's third-party-cookie
///   deprecation path, i.e. block 3p cookies by default
pub const ENABLED_FEATURES: &[&str] = &[
    "EncryptedClientHello",
    "ThirdPartyStoragePartitioning",
    "TrackingProtection3pcd",
];

/// Command-line switches applied before CEF context init. Chromium exposes
/// DoH configuration only via switches / managed prefs — plain
/// SetPreference on `dns_over_https.*` is silently refused (verified at
/// runtime: set returns 0 with can_set=1 and an empty error), so switches
/// are the correct mechanism. Returned as (name, Option<value>).
pub fn command_line_switches(policy: &NetworkPolicy) -> Vec<(String, Option<String>)> {
    vec![
        // DoH secure mode: resolve only over HTTPS, never fall back to
        // plaintext port-53 DNS.
        ("dns-over-https-mode".into(), Some("secure".into())),
        (
            "dns-over-https-templates".into(),
            Some(policy.doh_template.clone()),
        ),
        // Force third-party-cookie blocking regardless of the origin trial /
        // rollout state.
        ("test-third-party-cookie-phaseout".into(), None),
    ]
}

/// User override, read from `network.json` in the app data dir:
/// `{ "doh_resolver": "cloudflare" }` picks from the allowlist by name;
/// `{ "doh_template": "https://...", "allow_custom_resolver": true }`
/// sets a custom endpoint (both fields required — the explicit flag is the
/// user's acknowledgement that Vev cannot vouch for the endpoint).
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub doh_resolver: Option<String>,
    pub doh_template: Option<String>,
    #[serde(default)]
    pub allow_custom_resolver: bool,
}

pub struct NetworkPolicy {
    /// DoH template to configure ("secure" mode — no insecure fallback).
    pub doh_template: String,
    /// Resolver source, for logging/UI.
    pub doh_source: String,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            doh_template: RESOLVER_ALLOWLIST[0].template.into(),
            doh_source: RESOLVER_ALLOWLIST[0].name.into(),
        }
    }
}

impl NetworkPolicy {
    /// Load policy, applying a user override file if present and valid.
    /// Invalid overrides are rejected (returned as Err) rather than
    /// silently ignored, so the shell can surface the problem.
    pub fn load(config_path: &Path) -> Result<Self, String> {
        let bytes = match std::fs::read(config_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(format!("read {config_path:?}: {e}")),
        };
        let cfg: NetworkConfig = serde_json::from_slice(&bytes)
            .map_err(|e| format!("network.json invalid: {e}"))?;
        Self::from_config(cfg)
    }

    pub fn from_config(cfg: NetworkConfig) -> Result<Self, String> {
        if let Some(name) = &cfg.doh_resolver {
            let r = RESOLVER_ALLOWLIST
                .iter()
                .find(|r| r.name == name.as_str())
                .ok_or_else(|| format!("unknown doh_resolver {name:?}"))?;
            return Ok(Self {
                doh_template: r.template.into(),
                doh_source: r.name.into(),
            });
        }
        if let Some(template) = &cfg.doh_template {
            if !cfg.allow_custom_resolver {
                return Err(
                    "custom doh_template requires allow_custom_resolver: true".into(),
                );
            }
            let parsed = url::Url::parse(template)
                .map_err(|e| format!("doh_template invalid: {e}"))?;
            if parsed.scheme() != "https" {
                return Err("doh_template must be https".into());
            }
            return Ok(Self {
                doh_template: template.clone(),
                doh_source: "custom".into(),
            });
        }
        Ok(Self::default())
    }
}

/// Hosts exempt from HTTPS-only upgrading (local development and
/// non-routable targets where TLS is not meaningful).
fn is_upgrade_exempt(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback() || match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }
    false
}

/// HTTPS-only mode: return the upgraded URL if `input` is a plain-HTTP
/// navigation that should be rewritten, None if it can pass through.
pub fn https_upgrade(input: &str) -> Option<String> {
    let mut parsed = url::Url::parse(input).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    let host = parsed.host_str()?;
    if is_upgrade_exempt(host) {
        return None;
    }
    // http default port 80 must not survive the scheme swap as :80.
    if parsed.port() == Some(80) {
        let _ = parsed.set_port(None);
    }
    parsed.set_scheme("https").ok()?;
    Some(parsed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_plain_http() {
        assert_eq!(
            https_upgrade("http://example.com/x?y=1"),
            Some("https://example.com/x?y=1".into())
        );
    }

    #[test]
    fn strips_default_port() {
        assert_eq!(
            https_upgrade("http://example.com:80/"),
            Some("https://example.com/".into())
        );
    }

    #[test]
    fn keeps_custom_port() {
        assert_eq!(
            https_upgrade("http://example.com:8080/"),
            Some("https://example.com:8080/".into())
        );
    }

    #[test]
    fn passes_https_and_exempt_hosts() {
        assert_eq!(https_upgrade("https://example.com/"), None);
        assert_eq!(https_upgrade("http://localhost:3000/"), None);
        assert_eq!(https_upgrade("http://127.0.0.1/"), None);
        assert_eq!(https_upgrade("http://192.168.1.10/"), None);
        assert_eq!(https_upgrade("http://dev.localhost/"), None);
        assert_eq!(https_upgrade("about:blank"), None);
    }

    #[test]
    fn default_policy_is_first_allowlist_entry() {
        let p = NetworkPolicy::default();
        assert_eq!(p.doh_template, RESOLVER_ALLOWLIST[0].template);
    }

    #[test]
    fn named_override_must_be_allowlisted() {
        let ok = NetworkPolicy::from_config(NetworkConfig {
            doh_resolver: Some("cloudflare".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ok.doh_source, "cloudflare");
        assert!(NetworkPolicy::from_config(NetworkConfig {
            doh_resolver: Some("evil".into()),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn custom_template_requires_flag_and_https() {
        assert!(NetworkPolicy::from_config(NetworkConfig {
            doh_template: Some("https://doh.example/dns-query".into()),
            allow_custom_resolver: false,
            ..Default::default()
        })
        .is_err());
        assert!(NetworkPolicy::from_config(NetworkConfig {
            doh_template: Some("http://doh.example/dns-query".into()),
            allow_custom_resolver: true,
            ..Default::default()
        })
        .is_err());
        assert!(NetworkPolicy::from_config(NetworkConfig {
            doh_template: Some("https://doh.example/dns-query".into()),
            allow_custom_resolver: true,
            ..Default::default()
        })
        .is_ok());
    }
}
