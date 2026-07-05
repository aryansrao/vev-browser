//! On-device ONNX inference for the Huma Guard model.
//!
//! A small MLP (13 engineered URL features → 16 → 1, ReLU + sigmoid) trained
//! offline (`scripts/train_guard`) and bundled in-binary. tract runs it — pure
//! Rust, no ONNXRuntime/GPU — in microseconds. Features come from the same
//! `guard::extract_features` the trainer used, so train/serve are identical.
//!
//! This is the real machine-learning scorer; the interpretable linear `base_z`
//! in `guard` remains as a fallback if the model ever fails to load, and the
//! SEAL adapter (`crate::adapt`) still layers on top of whichever base is used.

use std::sync::OnceLock;
use tract_onnx::prelude::*;

/// The trained model, bundled at build time.
const MODEL_BYTES: &[u8] = include_bytes!("model.onnx");

type Runnable = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

static MODEL: OnceLock<Option<Runnable>> = OnceLock::new();

fn build() -> Option<Runnable> {
    let mut cursor = std::io::Cursor::new(MODEL_BYTES);
    match (|| -> TractResult<Runnable> {
        tract_onnx::onnx()
            .model_for_read(&mut cursor)?
            .with_input_fact(0, f32::fact([1, 13]).into())?
            .into_optimized()?
            .into_runnable()
    })() {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!("huma-model: ONNX load failed, using linear fallback: {e}");
            None
        }
    }
}

fn model() -> Option<&'static Runnable> {
    MODEL.get_or_init(build).as_ref()
}

/// Run the trained model on a 13-feature vector, returning the phishing
/// probability in [0,1]. `None` if the model is unavailable (caller falls
/// back to the linear base score).
pub fn score(features: &[f32; 13]) -> Option<f64> {
    let m = model()?;
    let input = tract_ndarray::Array2::from_shape_vec((1, 13), features.to_vec()).ok()?;
    let out = m.run(tvec!(input.into_tensor().into())).ok()?;
    let view = out[0].to_array_view::<f32>().ok()?;
    let p = *view.iter().next()? as f64;
    Some(p.clamp(0.0, 1.0))
}

/// True if the ONNX model loaded (for diagnostics / the About page).
pub fn available() -> bool {
    model().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard;

    #[test]
    fn model_loads_and_separates_phishing_from_benign() {
        assert!(available(), "bundled ONNX model must load");
        let phishing = guard::extract_features(
            "https://paypal-verify.secure-login.tk/webscr?confirm=1",
        )
        .vector();
        let benign = guard::extract_features("https://www.wikipedia.org/").vector();
        let ps = score(&phishing).expect("score");
        let bs = score(&benign).expect("score");
        assert!(ps > bs, "phishing {ps} should score above benign {bs}");
        assert!(ps > 0.5, "phishing should score high: {ps}");
        assert!(bs < 0.5, "benign should score low: {bs}");
    }
}
