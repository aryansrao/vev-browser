//! Fuzz the URL-facing entry points with adversarial/random input and assert
//! they never panic (Phase 10 hardening). A tiny xorshift PRNG keeps this
//! dependency-free and deterministic.

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// Bytes biased toward URL-significant characters so we hit parser edge cases.
fn random_urlish(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] = b"htps:/.?&=@%#[]:0123456789abcxyz-_ \t\n\0\x7f\xffAZ";
    let mut s = Vec::with_capacity(len);
    for _ in 0..len {
        s.push(ALPHABET[(rng.byte() as usize) % ALPHABET.len()]);
    }
    String::from_utf8_lossy(&s).into_owned()
}

#[test]
fn https_upgrade_never_panics_on_garbage() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for i in 0..50_000 {
        let len = (rng.byte() as usize % 120) + 1;
        let input = random_urlish(&mut rng, len);
        // Must not panic for any input.
        let _ = vev_network::https_upgrade(&input);
        if i % 3 == 0 {
            // Also exercise scheme-prefixed variants.
            let _ = vev_network::https_upgrade(&format!("http://{input}"));
            let _ = vev_network::https_upgrade(&format!("https://{input}/{input}"));
        }
    }
}

#[test]
fn known_tricky_inputs() {
    for s in [
        "",
        "http://",
        "http://:80",
        "http://[::1]",
        "http://[::1]:8080/x",
        "http://user:pass@host:80/path?q=1#frag",
        "http://xn--n3h.example/\u{0}\u{7f}",
        "http://a.b.c.d.e.f.g.h/../../../etc/passwd",
        "http://\u{202e}evil.example/",
        "https://\u{feff}zero.width/",
        "ftp://host/file",
        "javascript:alert(1)",
        "data:text/html,<h1>x</h1>",
    ] {
        let _ = vev_network::https_upgrade(s);
    }
}
