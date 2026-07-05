//! Huma self-adapting layer — a small, honest, on-device analog of SEAL
//! (Self-Adapting Language Models, Zweiger et al. 2025).
//!
//! SEAL's core idea: a model turns each new experience into a *self-edit* — a
//! directive it applies to its own weights via a gradient update — and keeps
//! the edits that improve behavior. We do exactly that at the scale of the
//! Guard's interpretable logistic model: every real browsing *outcome* becomes
//! a self-edit (one online logistic-regression step) applied to a persisted
//! per-feature **adapter** that sits on top of the static base model. The base
//! model never changes (its precision/recall stay measurable); the adapter is
//! an additive correction the browser learns from what actually happens on
//! this device.
//!
//! Outcomes that drive edits:
//!   - The user overrides a phishing warning ("Allow anyway") → the URL's
//!     features were a false positive → push their score DOWN.
//!   - A visited host later turns up on the live threat feed → confirmed
//!     malicious → push that structure's score UP.
//!
//! Properties, by construction:
//!   - **On-device only.** State lives in `huma-adapt.json`; nothing is ever
//!     uploaded (there is no network path out of this module).
//!   - **Bounded.** Every weight is clipped to `WEIGHT_CAP`, so no single
//!     stream of feedback can run the model away from its calibrated base.
//!   - **Interpretable.** Adapter weights are keyed by the same human-readable
//!     feature names the Guard uses, so an adaptation is inspectable.
//!   - **Reversible.** Deleting the JSON restores the shipped base behavior.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// Online-learning step size. Small so many consistent outcomes are needed to
/// move a weight meaningfully — a single click can't swing the model.
const LEARNING_RATE: f64 = 0.15;

/// Absolute cap on any adapter weight (and the bias). Keeps the learned
/// correction a nudge on top of the base model, never a takeover.
const WEIGHT_CAP: f64 = 1.5;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Adapter {
    /// Additive per-feature correction weights (keyed by Guard feature name).
    weights: BTreeMap<String, f64>,
    /// Additive bias correction.
    bias: f64,
    /// Number of self-edits applied (for diagnostics/UI).
    updates: u64,
}

struct State {
    adapter: Adapter,
    path: Option<PathBuf>,
}

static STATE: RwLock<Option<State>> = RwLock::new(None);

/// Load the persisted adapter from `path` (or start empty). Call once at
/// startup. Safe to call before use — a missing/corrupt file yields the base
/// (zero) adapter, which behaves exactly like the un-adapted model.
pub fn init(path: PathBuf) {
    let adapter = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Adapter>(&b).ok())
        .unwrap_or_default();
    *STATE.write().unwrap() = Some(State { adapter, path: Some(path) });
}

fn clip(x: f64) -> f64 {
    x.clamp(-WEIGHT_CAP, WEIGHT_CAP)
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// The adapter's additive contribution to the logit for a feature vector.
/// Zero when uninitialized or freshly created.
pub fn delta(features: &[(&'static str, f64)]) -> f64 {
    let guard = STATE.read().unwrap();
    let Some(state) = guard.as_ref() else { return 0.0 };
    let a = &state.adapter;
    let mut d = a.bias;
    for (name, value) in features {
        if let Some(w) = a.weights.get(*name) {
            d += w * value;
        }
    }
    d
}

/// Apply one self-edit: an online logistic-regression step toward `label`
/// (1.0 = malicious, 0.0 = benign) for `features`, given the base model's
/// logit `base_z`. Bounded and persisted. No-op if uninitialized.
pub fn record(base_z: f64, features: &[(&'static str, f64)], label: f64) {
    let mut guard = STATE.write().unwrap();
    let Some(state) = guard.as_mut() else { return };
    let a = &mut state.adapter;

    // Prediction under the current (base + adapter) model.
    let mut d = a.bias;
    for (name, value) in features {
        d += a.weights.get(*name).copied().unwrap_or(0.0) * value;
    }
    let p = sigmoid(base_z + d);
    // Gradient of logistic loss wrt the logit = (p - label). Descend it.
    let grad = p - label;
    for (name, value) in features {
        let w = a.weights.entry((*name).to_string()).or_insert(0.0);
        *w = clip(*w - LEARNING_RATE * grad * value);
    }
    a.bias = clip(a.bias - LEARNING_RATE * grad);
    a.updates += 1;

    // Persist (best-effort; adaptation must never block navigation).
    if let Some(path) = state.path.clone() {
        let bytes = serde_json::to_vec_pretty(&state.adapter).unwrap_or_default();
        let _ = std::fs::write(path, bytes);
    }
}

/// Convenience: record an outcome directly from a URL. Learns against the base
/// scorer actually in use (the ONNX model if available), so the correction is
/// applied consistently at classify time.
pub fn record_url(raw_url: &str, malicious: bool) {
    let f = crate::guard::extract_features(raw_url);
    let base = crate::guard::base_logit(&f);
    record(base, &f.values, if malicious { 1.0 } else { 0.0 });
}

/// Number of self-edits applied so far (for the UI / diagnostics).
pub fn update_count() -> u64 {
    STATE
        .read()
        .unwrap()
        .as_ref()
        .map(|s| s.adapter.updates)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard;

    // The adapter is a process-global; serialize the tests that mutate it so
    // they don't race on shared state under the parallel test runner. Recover
    // a poisoned lock so one failing test doesn't cascade into the others.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fresh(tmp: &str) {
        let path = std::env::temp_dir().join(tmp);
        let _ = std::fs::remove_file(&path);
        init(path);
    }

    #[test]
    fn benign_feedback_lowers_future_score() {
        let _g = lock();
        fresh("huma-adapt-benign.json");
        // A structurally-suspicious URL the model flags.
        let url = "https://secure-login.paypal.account-verify.tk/confirm";
        let before = guard::classify_adapted(url).score; // fresh adapter = ML base
        assert!(before > 0.5, "test URL should start suspicious: {before}");
        // The user overrides it as safe, repeatedly (a real recurring site).
        for _ in 0..60 {
            record_url(url, false);
        }
        let after = guard::classify_adapted(url).score;
        assert!(
            after < before - 0.1,
            "benign feedback should lower the score: {before} -> {after}"
        );
    }

    #[test]
    fn malicious_feedback_raises_and_is_bounded() {
        let _g = lock();
        fresh("huma-adapt-mal.json");
        // A borderline URL the model scores low.
        let url = "https://cdn.example-updates.com/app/login";
        let before = guard::classify_adapted(url).score;
        for _ in 0..200 {
            record_url(url, true);
        }
        let after = guard::classify_adapted(url).score;
        assert!(after > before, "malicious feedback should raise: {before} -> {after}");
        // Bounded: even under heavy one-sided feedback the score stays a
        // probability and doesn't explode.
        assert!(after <= 1.0 && after.is_finite());
    }

    #[test]
    fn zero_adapter_is_stable() {
        let _g = lock();
        fresh("huma-adapt-zero.json");
        let url = "https://www.wikipedia.org/";
        // With no recorded outcomes the adapter delta is zero, so repeated
        // classification is identical (the base scorer alone).
        let a = guard::classify_adapted(url).score;
        let b = guard::classify_adapted(url).score;
        assert!((a - b).abs() < 1e-12);
    }

    #[test]
    fn persists_across_reload() {
        let _g = lock();
        let path = std::env::temp_dir().join("huma-adapt-persist.json");
        let _ = std::fs::remove_file(&path);
        init(path.clone());
        let url = "https://login.secure-bank-update.xyz/verify";
        for _ in 0..30 {
            record_url(url, false);
        }
        let learned = update_count();
        assert!(learned >= 30);
        // Reload from disk and confirm the adaptation survived.
        init(path);
        assert_eq!(update_count(), learned);
    }
}
