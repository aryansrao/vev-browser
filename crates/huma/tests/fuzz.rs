//! Fuzz the Huma Guard classifier: adversarial/random URLs must never panic
//! and must always return a finite score in [0,1] (Phase 10 hardening).

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
}

#[test]
fn classify_never_panics_and_score_bounded() {
    const A: &[u8] = b"htps:/.?&=@%#[]:0123456789abcpayloginverf.-_ \t\0\xffAZ";
    let mut rng = Rng(0xDEADBEEFCAFEBABE);
    for _ in 0..50_000 {
        let len = (rng.next() as usize % 140) + 1;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(A[(rng.next() as usize) % A.len()]);
        }
        let s = String::from_utf8_lossy(&bytes).into_owned();
        let v = huma::guard::classify(&s);
        assert!(
            v.score.is_finite() && (0.0..=1.0).contains(&v.score),
            "score out of range for {s:?}: {}",
            v.score
        );
    }
}
