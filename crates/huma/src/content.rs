//! Huma content-phishing analyzer — looks at what the page actually SAYS, not
//! just its URL. This is the "read the content" layer: after a page loads we
//! extract its title + visible text and score it for the tell of a phishing
//! page — it dresses up as a known brand, the domain isn't that brand's, and
//! it's asking for a password / card / identity.
//!
//! The decisive signal is **brand impersonation with a domain mismatch**: a
//! real login page (paypal.com asking for your PayPal password) is fine
//! because the domain owns the brand; a page that presents itself as PayPal on
//! `secure-paypal.example.tk` is not. Credential-ask and urgency language
//! raise the score but never flag on their own, so ordinary login pages and
//! pages that merely mention a company don't trip it.

/// A brand and the registrable domains that legitimately own it.
struct Brand {
    token: &'static str,
    owners: &'static [&'static str],
}

const BRANDS: &[Brand] = &[
    Brand { token: "paypal", owners: &["paypal.com"] },
    Brand { token: "apple", owners: &["apple.com", "icloud.com"] },
    Brand { token: "icloud", owners: &["apple.com", "icloud.com"] },
    Brand { token: "microsoft", owners: &["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"] },
    Brand { token: "outlook", owners: &["microsoft.com", "live.com", "outlook.com"] },
    Brand { token: "office365", owners: &["microsoft.com", "office.com", "office365.com"] },
    Brand { token: "google", owners: &["google.com", "gmail.com", "youtube.com"] },
    Brand { token: "gmail", owners: &["google.com", "gmail.com"] },
    Brand { token: "amazon", owners: &["amazon.com"] },
    Brand { token: "facebook", owners: &["facebook.com", "meta.com"] },
    Brand { token: "instagram", owners: &["instagram.com", "facebook.com"] },
    Brand { token: "netflix", owners: &["netflix.com"] },
    Brand { token: "whatsapp", owners: &["whatsapp.com"] },
    Brand { token: "coinbase", owners: &["coinbase.com"] },
    Brand { token: "binance", owners: &["binance.com"] },
    Brand { token: "metamask", owners: &["metamask.io"] },
    Brand { token: "wells fargo", owners: &["wellsfargo.com"] },
    Brand { token: "chase", owners: &["chase.com"] },
    Brand { token: "bank of america", owners: &["bankofamerica.com"] },
    Brand { token: "dhl", owners: &["dhl.com"] },
    Brand { token: "fedex", owners: &["fedex.com"] },
    Brand { token: "usps", owners: &["usps.com"] },
    Brand { token: "linkedin", owners: &["linkedin.com"] },
    Brand { token: "steam", owners: &["steampowered.com", "steamcommunity.com", "valvesoftware.com"] },
    Brand { token: "discord", owners: &["discord.com", "discordapp.com"] },
    Brand { token: "roblox", owners: &["roblox.com"] },
];

/// Phrases that indicate the page is trying to harvest credentials/identity.
const CREDENTIAL_PHRASES: &[&str] = &[
    "enter your password", "your password", "sign in to", "log in to",
    "verify your account", "confirm your identity", "confirm your account",
    "update your billing", "billing information", "credit card number",
    "card number", "social security", "one-time password", "otp code",
    "verification code", "re-enter your", "unlock your account",
    "update your payment", "confirm your password",
];

/// Urgency / threat language typical of phishing.
const URGENCY_PHRASES: &[&str] = &[
    "account has been suspended", "account was suspended", "unusual activity",
    "unusual sign-in", "verify within", "will be locked", "account locked",
    "account is locked", "limited access", "suspended your account",
    "immediate action", "within 24 hours", "avoid suspension",
    "your account will be", "detected suspicious",
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentVerdict {
    pub score: f64,
    pub malicious: bool,
    pub reasons: Vec<String>,
    /// The brand the page impersonates, if any (for the warning text).
    pub impersonated: Option<String>,
}

/// Registrable domain = last two labels of the host (good enough for the
/// common `.com`/`.org` case; two-level ccTLDs like `.co.uk` fall back to the
/// last two labels, which only makes the check stricter, never looser here).
fn registrable(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    let n = labels.len();
    if n >= 2 {
        format!("{}.{}", labels[n - 2], labels[n - 1])
    } else {
        host.to_string()
    }
}

fn owner_regdoms(b: &Brand) -> Vec<String> {
    b.owners.iter().map(|d| registrable(d)).collect()
}

fn count_occurrences(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    hay.matches(needle).count()
}

/// Analyze a loaded page. `text` is the visible body text (may be large; only
/// a prefix is scanned). Returns a content-phishing verdict.
pub fn analyze(url: &str, title: &str, text: &str) -> ContentVerdict {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default();
    let regdom = registrable(&host);
    let title_l = title.to_ascii_lowercase();
    // Bound the scan for speed on huge pages.
    let text_l: String = text.chars().take(20_000).collect::<String>().to_ascii_lowercase();

    let mut z = -3.0_f64;
    let mut reasons = Vec::new();
    let mut impersonated = None;

    // Brand impersonation with a domain mismatch — the decisive signal.
    let mut brand_mismatch = false;
    for b in BRANDS {
        let in_title = title_l.contains(b.token);
        let mentions = count_occurrences(&text_l, b.token);
        let present = in_title || mentions >= 2;
        if !present {
            continue;
        }
        let owners = owner_regdoms(b);
        let owned = owners.iter().any(|d| regdom == *d || host.ends_with(&format!(".{d}")));
        if owned {
            // Legitimately the brand's own site — a positive signal it's real.
            z -= 0.5;
            continue;
        }
        // Brand shown prominently but domain isn't the brand's.
        brand_mismatch = true;
        impersonated = Some(b.token.to_string());
        z += 3.0;
        // Title impersonation is stronger than body mentions.
        if in_title {
            z += 0.8;
        }
        reasons.push(format!(
            "page presents itself as “{}” but the domain is {}",
            b.token, if host.is_empty() { "unknown" } else { &host }
        ));
        break;
    }

    // Credential / identity harvesting language.
    let cred_hits: Vec<&str> = CREDENTIAL_PHRASES
        .iter()
        .filter(|p| text_l.contains(**p) || title_l.contains(**p))
        .copied()
        .collect();
    if !cred_hits.is_empty() {
        z += 1.4_f64.min(0.5 + 0.3 * cred_hits.len() as f64);
        reasons.push("asks for your password / payment / identity".into());
    }

    // Urgency / threat language.
    let urgency_hits = URGENCY_PHRASES.iter().filter(|p| text_l.contains(**p)).count();
    if urgency_hits > 0 {
        z += (0.6 * urgency_hits as f64).min(1.4);
        reasons.push("uses account-threat / urgency language".into());
    }

    let score = 1.0 / (1.0 + (-z).exp());
    // Only flag when the page impersonates a brand on the wrong domain. Text
    // signals sharpen the score but never flag a legitimate login page.
    let malicious = brand_mismatch && score >= 0.6;
    ContentVerdict { score, malicious, reasons, impersonated }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_login_page_not_flagged() {
        // PayPal's own login page on paypal.com — brand + credentials, but the
        // domain owns the brand, so it must NOT be flagged.
        let v = analyze(
            "https://www.paypal.com/signin",
            "Log in to your PayPal account",
            "Enter your password to sign in to your PayPal account. Forgot password?",
        );
        assert!(!v.malicious, "real PayPal login flagged: {v:?}");
    }

    #[test]
    fn brand_mismatch_phishing_flagged() {
        let v = analyze(
            "https://secure-paypal.account-verify.tk/login",
            "PayPal - Confirm your identity",
            "Your PayPal account has been suspended due to unusual activity. \
             Enter your password and confirm your identity to unlock your account.",
        );
        assert!(v.malicious, "phishing not flagged: {v:?}");
        assert_eq!(v.impersonated.as_deref(), Some("paypal"));
    }

    #[test]
    fn ordinary_page_mentioning_brand_not_flagged() {
        // A blog post that mentions Google once — not impersonation.
        let v = analyze(
            "https://someblog.example.com/post",
            "My thoughts on search engines",
            "I switched from Google to a privacy search engine last year and here is why.",
        );
        assert!(!v.malicious, "benign brand mention flagged: {v:?}");
    }

    #[test]
    fn generic_login_no_brand_not_flagged() {
        let v = analyze(
            "https://myapp.example.net/login",
            "Sign in",
            "Enter your password to sign in to your account.",
        );
        assert!(!v.malicious, "generic login flagged: {v:?}");
    }
}
