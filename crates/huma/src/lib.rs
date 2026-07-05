//! Huma — Vev's on-device AI layer. All features run locally with no calls to
//! external model providers.
//!
//! - [`guard`]  — malicious-URL / phishing classifier (runs before navigation)
//! - [`read`]   — reader-mode extraction + extractive summarization
//! - [`predict`] — per-user navigation-pattern prefetch model

pub mod adapt;
pub mod content;
pub mod guard;
pub mod intel;
pub mod model;
pub mod predict;
pub mod read;
