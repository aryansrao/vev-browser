//! Huma Predict — per-user navigation-pattern model for predictive prefetch.
//!
//! Learns a first-order Markov chain over the *sites* the user visits (by
//! registrable host), entirely from local history. Given the current site it
//! predicts the most likely next site; when confidence clears a threshold the
//! shell warms DNS/TCP/TLS for that destination. Nothing is uploaded.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum probability AND minimum observation count before we act on a
/// prediction — avoids prefetching on thin/low-confidence patterns (a spec
/// verification requirement).
pub const MIN_CONFIDENCE: f64 = 0.55;
pub const MIN_OBSERVATIONS: u32 = 3;

#[derive(Default, Serialize, Deserialize)]
pub struct NavModel {
    /// from_host -> (to_host -> count)
    transitions: HashMap<String, HashMap<String, u32>>,
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(|h| h.to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct Prediction {
    pub next_host: String,
    pub confidence: f64,
    pub observations: u32,
}

impl NavModel {
    pub fn load(path: &std::path::Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let j = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        std::fs::write(path, j).map_err(|e| format!("write {path:?}: {e}"))
    }

    /// Record that the user navigated from `from` to `to` (raw URLs).
    pub fn record(&mut self, from: &str, to: &str) {
        let (Some(f), Some(t)) = (host_of(from), host_of(to)) else {
            return;
        };
        if f == t {
            return; // ignore same-site navigation
        }
        *self
            .transitions
            .entry(f)
            .or_default()
            .entry(t)
            .or_insert(0) += 1;
    }

    /// Predict the most likely next site from `current`, if confident enough.
    pub fn predict(&self, current: &str) -> Option<Prediction> {
        let host = host_of(current)?;
        let row = self.transitions.get(&host)?;
        let total: u32 = row.values().sum();
        if total < MIN_OBSERVATIONS {
            return None;
        }
        let (next, &count) = row.iter().max_by_key(|(_, &c)| c)?;
        let confidence = count as f64 / total as f64;
        if confidence < MIN_CONFIDENCE {
            return None;
        }
        Some(Prediction {
            next_host: next.clone(),
            confidence,
            observations: total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_and_predicts_strong_pattern() {
        let mut m = NavModel::default();
        // After news.example the user goes to mail.example 4/5 times.
        for _ in 0..4 {
            m.record("https://news.example/", "https://mail.example/inbox");
        }
        m.record("https://news.example/", "https://other.example/");

        let p = m.predict("https://news.example/article").expect("prediction");
        assert_eq!(p.next_host, "mail.example");
        assert!(p.confidence >= 0.75, "confidence {}", p.confidence);
        assert_eq!(p.observations, 5);
    }

    #[test]
    fn no_prediction_below_confidence_or_observations() {
        let mut m = NavModel::default();
        // Only 2 observations total -> below MIN_OBSERVATIONS.
        m.record("https://a.example/", "https://b.example/");
        m.record("https://a.example/", "https://c.example/");
        assert!(m.predict("https://a.example/").is_none());

        // Enough observations but a coin-flip split -> below MIN_CONFIDENCE.
        let mut m2 = NavModel::default();
        for _ in 0..3 {
            m2.record("https://x.example/", "https://y.example/");
            m2.record("https://x.example/", "https://z.example/");
        }
        assert!(m2.predict("https://x.example/").is_none());
    }
}
