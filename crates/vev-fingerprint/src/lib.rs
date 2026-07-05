//! Fingerprint resistance policy: the fixed reference profile Vev presents to
//! every site, and the spoofing script that enforces it in the page.
//!
//! The defensible model (per the project spec) is **uniform fixed output**
//! across all installs *on the same OS* — matching Tor Browser's per-platform
//! buckets — not per-session randomization, which is itself distinguishable.
//! The profile must not claim a different OS: Chromium derives the
//! Sec-CH-UA-* request headers from the real OS and they cannot be
//! overridden, so a cross-OS lie (Windows UA on macOS) contradicts the
//! headers and trips bot checks (Cloudflare Turnstile loops forever on it).

/// The spoofing-script template; platform tokens are filled by `spoof_js()`.
const SPOOF_JS_TEMPLATE: &str = include_str!("spoof.js");

/// The spoofing script, injected before page scripts on every frame, with
/// the per-OS platform values filled in.
pub fn spoof_js() -> &'static str {
    static FILLED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FILLED.get_or_init(|| {
        SPOOF_JS_TEMPLATE
            .replace("__VEV_NAV_PLATFORM__", NAV_PLATFORM)
            .replace("__VEV_UACH_PLATFORM__", UACH_PLATFORM)
            .replace("__VEV_UACH_PLATFORM_VERSION__", UACH_PLATFORM_VERSION)
    })
}

/// Fixed User-Agent presented to all sites: a common, current Chrome string
/// for THIS OS, so Vev blends into the largest population while staying
/// consistent with the client-hint headers Chromium emits (see module docs).
#[cfg(target_os = "macos")]
pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";
#[cfg(target_os = "windows")]
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";
#[cfg(target_os = "linux")]
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

/// navigator.platform per OS.
#[cfg(target_os = "macos")]
const NAV_PLATFORM: &str = "MacIntel";
#[cfg(target_os = "windows")]
const NAV_PLATFORM: &str = "Win32";
#[cfg(target_os = "linux")]
const NAV_PLATFORM: &str = "Linux x86_64";

/// userAgentData.platform per OS (must equal the Sec-CH-UA-Platform header).
#[cfg(target_os = "macos")]
const UACH_PLATFORM: &str = "macOS";
#[cfg(target_os = "windows")]
const UACH_PLATFORM: &str = "Windows";
#[cfg(target_os = "linux")]
const UACH_PLATFORM: &str = "Linux";

/// A fixed, plausible platformVersion for the high-entropy surface.
#[cfg(target_os = "macos")]
const UACH_PLATFORM_VERSION: &str = "13.0.0";
#[cfg(target_os = "windows")]
const UACH_PLATFORM_VERSION: &str = "10.0.0";
#[cfg(target_os = "linux")]
const UACH_PLATFORM_VERSION: &str = "";

/// Fixed Accept-Language.
pub const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

/// Fixed UI language passed to Chromium (`--lang`).
pub const LANG: &str = "en-US";

/// Timezone forced via the process `TZ` environment variable before CEF
/// starts, so the C library and V8 both report UTC.
pub const TIMEZONE: &str = "UTC";

/// The reference profile, exposed for verification/tests.
pub struct ReferenceProfile {
    pub user_agent: &'static str,
    pub platform: &'static str,
    pub language: &'static str,
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub timezone: &'static str,
    pub screen: (u32, u32),
}

pub const REFERENCE: ReferenceProfile = ReferenceProfile {
    user_agent: USER_AGENT,
    platform: NAV_PLATFORM,
    language: "en-US",
    hardware_concurrency: 2,
    device_memory: 8,
    timezone: "UTC",
    screen: (1920, 1080),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spoof_script_is_present_and_idempotent_guarded() {
        let js = spoof_js();
        assert!(js.contains("__vevFp"));
        assert!(js.contains("hardwareConcurrency"));
        assert!(js.contains("UNMASKED_VENDOR") || js.contains("37445"));
    }

    #[test]
    fn reference_profile_matches_script_constants() {
        // The script and the Rust reference must agree on the fixed values;
        // a mismatch would make verification lie.
        let js = spoof_js();
        assert!(js.contains("return 2;")); // hardwareConcurrency
        assert!(js.contains("return 8;")); // deviceMemory
        assert!(js.contains("1920"));
        assert!(js.contains("userAgentData")); // must spoof UA-CH platform
        assert!(js.contains("patchWorker")); // must extend into workers
        assert_eq!(REFERENCE.hardware_concurrency, 2);
        assert_eq!(REFERENCE.device_memory, 8);
        assert_eq!(REFERENCE.screen, (1920, 1080));
        // No unfilled platform tokens may survive.
        assert!(!js.contains("__VEV_"));
        assert!(js.contains(NAV_PLATFORM));
        assert!(js.contains(UACH_PLATFORM));
        // The UA must describe the same platform family as the CH surface.
        #[cfg(target_os = "macos")]
        assert!(USER_AGENT.contains("Macintosh"));
        #[cfg(target_os = "windows")]
        assert!(USER_AGENT.contains("Windows"));
        #[cfg(target_os = "linux")]
        assert!(USER_AGENT.contains("Linux"));
    }
}
