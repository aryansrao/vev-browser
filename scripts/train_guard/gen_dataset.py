#!/usr/bin/env python3
"""Generate a labeled URL dataset for the Huma Guard model.

Benign = real, popular domains with realistic (often long) paths and genuine
login pages on their own domain. Phishing = the structural patterns real
phishing uses — brand on the wrong domain, homoglyph/punycode hosts, IP-literal
hosts, risky TLDs with credential words, and `@` authority tricks. Emits
`url<TAB>label` lines; features are then extracted by the shared Rust extractor
(dump_features) so training and inference see identical inputs.
"""
import random

random.seed(1729)

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "amazon.com",
    "reddit.com", "stackoverflow.com", "apple.com", "microsoft.com",
    "netflix.com", "linkedin.com", "nytimes.com", "bbc.co.uk", "cloudflare.com",
    "mozilla.org", "python.org", "rust-lang.org", "medium.com", "dropbox.com",
    "spotify.com", "twitch.tv", "instagram.com", "paypal.com", "coinbase.com",
    "udemy.com", "coursera.org", "khanacademy.org", "wordpress.com",
]
BENIGN_PATHS = [
    "/", "/about", "/search?q=how+to+learn+rust+programming+quickly",
    "/watch?v=8KFQx-mc2Ao", "/course/the-complete-web-development-bootcamp-2024/learn/lecture/29394856",
    "/questions/12345/how-do-i-parse-json-in-python", "/user/profile/settings",
    "/products/B0ABCDEF12/ref=sr_1_3?keywords=usb+c+cable&qid=1700000000",
    "/signin", "/login", "/account/security", "/help/contact",
    "/docs/api/reference/v2/authentication", "/r/programming/comments/xyz/title",
]
# Legit login subdomains on their own brand.
BENIGN_LOGIN = [
    "accounts.google.com/signin", "login.microsoftonline.com/",
    "signin.aws.amazon.com/", "github.com/login", "www.paypal.com/signin",
    "id.apple.com/", "www.dropbox.com/login",
]

BRANDS = ["paypal", "apple", "microsoft", "amazon", "google", "netflix",
          "coinbase", "binance", "wellsfargo", "chase", "dhl", "usps",
          "instagram", "outlook", "office365", "icloud"]
RISKY_TLDS = ["tk", "ml", "cf", "gq", "ga", "xyz", "top", "icu", "cyou",
              "sbs", "cfd", "click", "link", "work", "loan", "rest", "quest"]
CRED = ["login", "signin", "verify", "secure", "account", "update", "confirm",
        "webscr", "unlock", "billing", "authenticate", "validation"]


def rand_sub(n):
    parts = []
    for _ in range(n):
        parts.append(random.choice(["secure", "login", "account", "verify",
                                     "signin", "auth", "www", "my", "id",
                                     "update", "confirm", "webscr"]))
    return ".".join(parts)


def gen_benign():
    out = []
    for d in BENIGN_DOMAINS:
        for _ in range(6):
            p = random.choice(BENIGN_PATHS)
            sub = random.choice(["www.", "", ""])
            out.append(f"https://{sub}{d}{p}")
    for l in BENIGN_LOGIN:
        for _ in range(4):
            out.append(f"https://{l}")
    return out


def gen_phishing():
    out = []
    for _ in range(120):
        brand = random.choice(BRANDS)
        tld = random.choice(RISKY_TLDS)
        cred = random.choice(CRED)
        style = random.randint(0, 5)
        if style == 0:  # brand + wrong TLD
            out.append(f"https://{brand}-{cred}.{rand_sub(1)}.{tld}/{cred}")
        elif style == 1:  # brand as subdomain of unrelated risky host
            out.append(f"https://{brand}.{rand_sub(2)}.{tld}/{cred}/webscr")
        elif style == 2:  # IP host
            ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            out.append(f"http://{ip}/{brand}/{cred}")
        elif style == 3:  # punycode / homoglyph
            out.append(f"https://xn--{brand}-verify.{tld}/{cred}")
        elif style == 4:  # @ authority trick
            out.append(f"https://{brand}.com@{rand_sub(1)}.{tld}/{cred}")
        else:  # long obfuscated risky
            junk = "%2F".join(["confirm", "identity", "billing", brand, cred])
            out.append(f"https://{rand_sub(3)}.{tld}/{cred}?redir={junk}&token=" + "a" * 80)
    # A few brand-impersonation on plain but non-owner .com domains.
    for _ in range(30):
        brand = random.choice(BRANDS)
        out.append(f"https://{brand}-{random.choice(CRED)}-support.com/{random.choice(CRED)}")
    return out


def main():
    rows = [(u, 0) for u in gen_benign()] + [(u, 1) for u in gen_phishing()]
    random.shuffle(rows)
    for u, l in rows:
        print(f"{u}\t{l}")


if __name__ == "__main__":
    main()
