//! Incognito session state: privacy toggles that apply to every private tab
//! in every private window for the lifetime of the app run (never persisted
//! — a fresh run starts from the hardened defaults).

use serde::{Deserialize, Serialize};
use std::sync::RwLock;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct IncognitoSettings {
    /// Remove RTCPeerConnection/DataChannel and stub media enumeration in
    /// private tabs (on top of the global WebRTC IP-handling policy).
    pub block_webrtc: bool,
    /// Inject the uniform fixed fingerprint profile into private tabs.
    pub fingerprint_spoof: bool,
    /// Run the ad/tracker cosmetic + scriptlet layers in private tabs.
    /// (Network-layer blocking is global and always on.)
    pub page_shields: bool,
}

impl Default for IncognitoSettings {
    fn default() -> Self {
        Self {
            block_webrtc: true,
            fingerprint_spoof: true,
            page_shields: true,
        }
    }
}

static SETTINGS: RwLock<IncognitoSettings> = RwLock::new(IncognitoSettings {
    block_webrtc: true,
    fingerprint_spoof: true,
    page_shields: true,
});

pub fn get() -> IncognitoSettings {
    *SETTINGS.read().unwrap()
}

pub fn set(s: IncognitoSettings) {
    *SETTINGS.write().unwrap() = s;
}

/// Script injected at document_start into private tabs when `block_webrtc`
/// is on. Removes the WebRTC surface entirely so no ICE candidate (local or
/// public) can ever be gathered, and stubs device enumeration.
pub const WEBRTC_KILL_JS: &str = r#"
(function () {
  "use strict";
  if (window.__vevRtcKilled) return;
  window.__vevRtcKilled = true;
  const gone = undefined;
  try { Object.defineProperty(window, "RTCPeerConnection", { get: () => gone, configurable: true }); } catch (e) {}
  try { Object.defineProperty(window, "webkitRTCPeerConnection", { get: () => gone, configurable: true }); } catch (e) {}
  try { Object.defineProperty(window, "RTCDataChannel", { get: () => gone, configurable: true }); } catch (e) {}
  try { Object.defineProperty(window, "RTCIceCandidate", { get: () => gone, configurable: true }); } catch (e) {}
  try { Object.defineProperty(window, "RTCSessionDescription", { get: () => gone, configurable: true }); } catch (e) {}
  try {
    if (navigator.mediaDevices) {
      navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
      navigator.mediaDevices.getUserMedia = () =>
        Promise.reject(new DOMException("Permission denied", "NotAllowedError"));
      navigator.mediaDevices.getDisplayMedia = () =>
        Promise.reject(new DOMException("Permission denied", "NotAllowedError"));
    }
  } catch (e) {}
})();
"#;
