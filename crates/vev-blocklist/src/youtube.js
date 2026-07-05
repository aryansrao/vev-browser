// YouTube ad neutralization, v2. Injected at document_start on youtube.com
// frames (main + embedded players).
//
// Primary strategy (the one Brave/uBO-style blockers use): strip the ad
// inventory out of the player responses BEFORE the player reads them, so
// ads are never scheduled and the main video starts immediately. Three
// interception points cover all delivery paths:
//   1. window.ytInitialPlayerResponse (embedded in the watch-page HTML)
//   2. fetch() of /youtubei/v1/player and /youtubei/v1/next (SPA navigation)
//   3. JSON.parse (XHR fallback paths)
//
// Fallback strategy (only if an ad still slips through): click the Skip
// button, and seek ONLY while the player itself reports the ad state
// (.ad-showing on .html5-video-player) — and only the <video> inside that
// player. The v1 scriptlet seeked document.querySelector("video") on a
// 300 ms interval whenever .ad-showing was present; when a network-blocked
// ad request left the player stuck in ad state, that seeked the MAIN video
// to its end and broke playback (user-reported). v2 never touches a video
// outside a confirmed, debounced ad state.
(function () {
  "use strict";
  if (window.__vevYtAds2) return;
  window.__vevYtAds2 = true;

  var AD_KEYS = [
    "adPlacements",
    "adSlots",
    "playerAds",
    "adBreakHeartbeatParams",
  ];

  function prune(obj) {
    try {
      if (!obj || typeof obj !== "object") return obj;
      for (var i = 0; i < AD_KEYS.length; i++) {
        if (AD_KEYS[i] in obj) delete obj[AD_KEYS[i]];
      }
      // /youtubei/v1/next nests a playerResponse in some shapes.
      if (obj.playerResponse) prune(obj.playerResponse);
    } catch (e) {}
    return obj;
  }

  // 1. ytInitialPlayerResponse: trap the property so whatever the page
  //    assigns is pruned before player code reads it.
  try {
    var _ipr = window.ytInitialPlayerResponse;
    Object.defineProperty(window, "ytInitialPlayerResponse", {
      configurable: true,
      get: function () {
        return _ipr;
      },
      set: function (v) {
        _ipr = prune(v);
      },
    });
    if (_ipr) _ipr = prune(_ipr);
  } catch (e) {}

  // 2. fetch(): prune innertube player/next responses.
  try {
    var origFetch = window.fetch;
    window.fetch = function (input) {
      var url = "";
      try {
        url = typeof input === "string" ? input : (input && input.url) || "";
      } catch (e) {}
      var p = origFetch.apply(this, arguments);
      if (
        url.indexOf("/youtubei/v1/player") === -1 &&
        url.indexOf("/youtubei/v1/next") === -1
      ) {
        return p;
      }
      return p.then(function (res) {
        return res
          .clone()
          .json()
          .then(function (data) {
            // No ad inventory to strip → hand back the ORIGINAL response
            // untouched. Rebuilding it needlessly risks breaking playback.
            var had = false;
            for (var i = 0; i < AD_KEYS.length; i++) {
              if (data && AD_KEYS[i] in data) had = true;
            }
            if (data && data.playerResponse) had = true;
            if (!had) return res;
            prune(data);
            // Rebuild headers WITHOUT content-length / content-encoding: the
            // pruned JSON has a different length than the original compressed
            // body, and keeping the stale length/encoding made Chromium treat
            // the player response as corrupt ("Video unavailable").
            var hdrs = new Headers();
            res.headers.forEach(function (value, key) {
              var k = key.toLowerCase();
              if (k === "content-length" || k === "content-encoding") return;
              hdrs.append(key, value);
            });
            return new Response(JSON.stringify(data), {
              status: res.status,
              statusText: res.statusText,
              headers: hdrs,
            });
          })
          .catch(function () {
            return res;
          });
      });
    };
  } catch (e) {}

  // 3. JSON.parse fallback (covers XHR-based delivery).
  try {
    var origParse = JSON.parse;
    JSON.parse = function () {
      var o = origParse.apply(this, arguments);
      try {
        if (o && typeof o === "object" && (o.adPlacements || o.adSlots || o.playerAds)) {
          prune(o);
        }
      } catch (e) {}
      return o;
    };
  } catch (e) {}

  // ---- DOM fallback: skip clicks + cosmetic hiding, ad-state gated ----
  // Reliably removes any ad the response-pruning missed. Every action is
  // gated on the player's own `.ad-showing` state and only ever touches the
  // <video> inside an ad-showing player (which IS the ad stream) — so the
  // main video is never seeked or broken.
  function onTick() {
    try {
      var player = document.querySelector(".html5-video-player");
      if (!player || !player.classList.contains("ad-showing")) return;

      // 1. Click any visible Skip control the instant it appears.
      var skip = document.querySelector(
        ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button, .ytp-ad-skip-button-modern .ytp-ad-skip-button"
      );
      if (skip) skip.click();

      // 2. Fast-forward the ad stream to its end. Ads are short; the >5min
      //    guard is only a paranoia check that this is not somehow the main
      //    feature — during .ad-showing the <video> is the ad.
      var v = player.querySelector("video");
      if (v && v.duration && isFinite(v.duration) && v.duration < 300) {
        v.muted = true;
        try { v.currentTime = v.duration; } catch (e) {}
        v.play && v.play();
      }

      // 3. Close overlay/banner ads.
      var overlayClose = document.querySelector(
        ".ytp-ad-overlay-close-button, .ytp-ad-overlay-close-container"
      );
      if (overlayClose) overlayClose.click();
    } catch (e) {}
  }

  function hideStaticSlots() {
    try {
      var hide = [
        "#player-ads",
        "#masthead-ad",
        "ytd-display-ad-renderer",
        "ytd-promoted-video-renderer",
        "ytd-in-feed-ad-layout-renderer",
        "ytd-ad-slot-renderer",
      ];
      var css = hide.join(",") + "{display:none!important}";
      var s = document.createElement("style");
      s.setAttribute("data-vev", "yt");
      s.textContent = css;
      (document.head || document.documentElement).appendChild(s);
    } catch (e) {}
  }

  function start() {
    hideStaticSlots();
    // Fast tick so an ad that slips past the response-pruning is skipped
    // near-instantly. Cheap: it early-returns unless the player is ad-showing.
    setInterval(onTick, 120);
    // Also react immediately to the player toggling into ad state.
    try {
      new MutationObserver(onTick).observe(document.documentElement, {
        attributes: true,
        subtree: true,
        attributeFilter: ["class"],
      });
    } catch (e) {}
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
