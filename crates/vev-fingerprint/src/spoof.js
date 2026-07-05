// Vev fingerprint resistance — uniform fixed output across all installs
// (Tor Browser model, not randomization). Injected before page scripts run.
//
// Every value here is a FIXED CONSTANT identical on every Vev install, so the
// fingerprint has no per-user entropy. The overrides live in `apply()` so the
// SAME code can be re-run inside Web Workers / Shared Workers (which otherwise
// see the real machine — a real leak CreepJS exploits): apply() is guarded so
// it is safe in a context with no window/document/screen, and the Worker /
// SharedWorker constructors are patched to prepend it to the worker script.
(function () {
  "use strict";
  if (typeof self !== "undefined" && self.__vevFp) return;
  if (typeof self !== "undefined") self.__vevFp = true;

  function apply() {
    var hasWindow = typeof window !== "undefined";
    var hasDocument = typeof document !== "undefined";
    var hasScreen = typeof screen !== "undefined";
    var nav = typeof navigator !== "undefined" ? navigator : null;

    function def(obj, prop, getter) {
      try {
        Object.defineProperty(obj, prop, { get: getter, configurable: true });
      } catch (e) {}
    }

    // --- navigator entropy -> fixed reference profile (main + worker) ---
    if (nav) {
      def(nav, "hardwareConcurrency", function () { return 2; });
      def(nav, "deviceMemory", function () { return 8; });
      def(nav, "maxTouchPoints", function () { return 0; });
      def(nav, "platform", function () { return "__VEV_NAV_PLATFORM__"; });
      def(nav, "vendor", function () { return "Google Inc."; });
      def(nav, "language", function () { return "en-US"; });
      def(nav, "languages", function () { return Object.freeze(["en-US", "en"]); });
      def(nav, "webdriver", function () { return false; });
      def(nav, "doNotTrack", function () { return "1"; });
      def(nav, "plugins", function () { return Object.freeze([]); });
      def(nav, "mimeTypes", function () { return Object.freeze([]); });

      // navigator.userAgentData — a top leak: JS values must agree with the
      // Sec-CH-UA-* headers Chromium derives from the REAL OS (bot checks
      // like Cloudflare Turnstile hard-fail on a platform mismatch), so the
      // whole surface is pinned to the per-OS profile baked in at build.
      try {
        var BRANDS = Object.freeze([
          { brand: "Chromium", version: "149" },
          { brand: "Google Chrome", version: "149" },
          { brand: "Not?A_Brand", version: "24" },
        ]);
        var highEntropy = {
          architecture: "x86",
          bitness: "64",
          brands: BRANDS,
          fullVersionList: Object.freeze([
            { brand: "Chromium", version: "149.0.0.0" },
            { brand: "Google Chrome", version: "149.0.0.0" },
            { brand: "Not?A_Brand", version: "24.0.0.0" },
          ]),
          mobile: false,
          model: "",
          platform: "__VEV_UACH_PLATFORM__",
          platformVersion: "__VEV_UACH_PLATFORM_VERSION__",
          uaFullVersion: "149.0.0.0",
          wow64: false,
        };
        var uaData = {
          brands: BRANDS,
          mobile: false,
          platform: "__VEV_UACH_PLATFORM__",
          getHighEntropyValues: function () {
            return Promise.resolve(JSON.parse(JSON.stringify(highEntropy)));
          },
          toJSON: function () {
            return { brands: BRANDS, mobile: false, platform: "__VEV_UACH_PLATFORM__" };
          },
        };
        def(nav, "userAgentData", function () { return uaData; });
      } catch (e) {}
    }

    // --- screen -> fixed 1920x1080 (main only; guarded for workers) ---
    if (hasScreen) {
      var S = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 };
      for (var k in S) {
        (function (key) { def(screen, key, function () { return S[key]; }); })(k);
      }
    }
    if (hasWindow) {
      def(window, "devicePixelRatio", function () { return 1; });
      def(window, "outerWidth", function () { return 1920; });
      def(window, "outerHeight", function () { return 1080; });
      // Reduce a headless signal: expose a minimal window.chrome shim.
      try {
        if (!window.chrome) window.chrome = { runtime: {} };
      } catch (e) {}
    }

    // --- timezone / locale -> UTC / en-US ---
    try {
      var RTF = Intl.DateTimeFormat.prototype.resolvedOptions;
      Intl.DateTimeFormat.prototype.resolvedOptions = function () {
        var o = RTF.apply(this, arguments);
        o.timeZone = "UTC";
        o.locale = "en-US";
        return o;
      };
    } catch (e) {}
    try {
      Date.prototype.getTimezoneOffset = function () { return 0; };
    } catch (e) {}

    // --- Canvas: deterministic readback (main only) ---
    if (typeof HTMLCanvasElement !== "undefined") {
      try {
        var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function () {
          return origToDataURL.apply(this, arguments);
        };
      } catch (e) {}
    }
    if (typeof CanvasRenderingContext2D !== "undefined") {
      try {
        var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = function () {
          var data = origGetImageData.apply(this, arguments);
          var d = data.data;
          for (var i = 0; i < d.length; i += 4) {
            var p = (i / 4) | 0;
            d[i] = p & 0xff;
            d[i + 1] = (p >> 8) & 0xff;
            d[i + 2] = (p >> 16) & 0xff;
            d[i + 3] = 255;
          }
          return data;
        };
      } catch (e) {}
    }

    // --- WebGL: fixed vendor/renderer + deterministic readPixels. Covers
    // OffscreenCanvas WebGL in workers too (real Apple M1 GPU leaks there). ---
    function patchGL(proto) {
      if (!proto) return;
      try {
        var origGetParameter = proto.getParameter;
        proto.getParameter = function (p) {
          if (p === 37445) return "Google Inc. (Intel)"; // UNMASKED_VENDOR
          if (p === 37446) return "ANGLE (Intel, Mesa Intel(R) UHD Graphics, OpenGL 4.6)"; // UNMASKED_RENDERER
          if (p === 7936) return "WebKit"; // VENDOR
          if (p === 7937) return "WebKit WebGL"; // RENDERER
          if (p === 7938) return "WebGL 1.0"; // VERSION
          return origGetParameter.apply(this, arguments);
        };
        var origReadPixels = proto.readPixels;
        proto.readPixels = function (x, y, w, h, fmt, type, pixels) {
          origReadPixels.apply(this, arguments);
          if (pixels && pixels.length) {
            for (var i = 0; i < pixels.length; i++) pixels[i] = i & 0xff;
          }
        };
      } catch (e) {}
    }
    if (typeof WebGLRenderingContext !== "undefined") patchGL(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== "undefined") patchGL(WebGL2RenderingContext.prototype);

    // --- AudioContext: deterministic sample data ---
    if (typeof AnalyserNode !== "undefined") {
      try {
        var origFreq = AnalyserNode.prototype.getFloatFrequencyData;
        if (origFreq) {
          AnalyserNode.prototype.getFloatFrequencyData = function (arr) {
            origFreq.apply(this, arguments);
            for (var i = 0; i < arr.length; i++) arr[i] = -60 + (i % 10) * 0.001;
          };
        }
      } catch (e) {}
    }
    if (typeof AudioBuffer !== "undefined") {
      try {
        var origChannel = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function () {
          var data = origChannel.apply(this, arguments);
          for (var i = 0; i < data.length; i++) data[i] = Math.round(data[i] * 10000) / 10000;
          return data;
        };
      } catch (e) {}
    }

    // --- Fonts: fixed enumeration (main only) ---
    if (hasDocument && document.fonts && document.fonts.check) {
      try {
        var CURATED = ["Arial", "Courier New", "Georgia", "Times New Roman",
          "Trebuchet MS", "Verdana", "Tahoma", "Helvetica", "sans-serif",
          "serif", "monospace"];
        var origCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = function (font, text) {
          var m = /(?:\d+px\s+)?["']?([^"',]+)["']?/.exec(font || "");
          var family = m ? m[1].trim() : "";
          if (CURATED.indexOf(family) !== -1) return true;
          if (["sans-serif", "serif", "monospace"].indexOf(family) !== -1) return true;
          return origCheck(font, text);
        };
      } catch (e) {}
    }
  }

  apply();

  // --- Extend the spoof into Web Workers / Shared Workers ---
  // Workers run in a fresh global that never saw apply(), so they leak the
  // real GPU / core count / userAgentData. Prepend apply() (as source) to the
  // worker's script by rewriting the URL into a Blob that runs the spoof and
  // then imports the original script.
  try {
    var APPLY_SRC = "(" + apply.toString() + ")();";
    var patchWorker = function (Ctor) {
      if (typeof Ctor !== "function") return Ctor;
      var Patched = function (url, opts) {
        try {
          var abs = String(url);
          var head = "self.__vevFp=true;\n" + APPLY_SRC + "\n";
          var body;
          if (abs.indexOf("blob:") === 0 || abs.indexOf("data:") === 0) {
            // Fetch the worker source synchronously, prepend, re-blob.
            var xhr = new XMLHttpRequest();
            xhr.open("GET", abs, false);
            xhr.send(null);
            body = head + xhr.responseText;
          } else {
            var full = new URL(abs, (typeof location !== "undefined" && location.href) || "");
            body = head + "importScripts(" + JSON.stringify(full.href) + ");";
          }
          var blob = new Blob([body], { type: "application/javascript" });
          url = URL.createObjectURL(blob);
        } catch (e) {}
        return new Ctor(url, opts);
      };
      try {
        Patched.prototype = Ctor.prototype;
      } catch (e) {}
      return Patched;
    };
    if (typeof Worker !== "undefined") {
      // eslint-disable-next-line no-global-assign
      Worker = patchWorker(Worker);
      if (typeof self !== "undefined") self.Worker = Worker;
    }
    if (typeof SharedWorker !== "undefined") {
      SharedWorker = patchWorker(SharedWorker);
      if (typeof self !== "undefined") self.SharedWorker = SharedWorker;
    }
  } catch (e) {}
})();
