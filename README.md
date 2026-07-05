# Vev

**The private browser where privacy is the default.**

Vev is a desktop browser built from scratch: a Tauri 2 (Rust) shell embedding
Chromium Embedded Framework (CEF) as the real multi-process rendering engine,
with a Rust workspace for privacy, security, on-device AI, and downloading.
Fingerprint resistance, WebRTC leak protection, AI phishing detection,
ad/tracker blocking, always-separate private windows, and an encrypted vault
are **on by default** — not paid add-ons.

- Website & docs: <https://github.com/aryansrao/vev-website> (deploys to Vercel)
- Community phishing feed: <https://github.com/aryansrao/community-phishing-feed>

---

## Features

### Privacy & security
- **On-device AI (Huma).** A real trained ML model (small MLP → ONNX, run by
  `tract` in pure Rust) scores every navigation, reads page content to catch
  brand-impersonation phishing, and adapts to your Allow/Block choices locally
  (a SEAL-style self-adapting layer). Plus on-device page summarization (Huma
  Read) and navigation prefetch (Huma Predict). No model provider, no telemetry.
- **Fingerprint resistance.** One fixed device profile (canvas, WebGL, audio,
  fonts, timezone, platform), injected into the main frame **and** web/service
  workers. The profile is **per-OS** so the JS values agree with Chromium's
  `Sec-CH-UA-*` headers (a cross-OS lie breaks real sites like Cloudflare
  Turnstile) — uniform across every install on the same OS, Tor-Browser style.
- **WebRTC leak protection.** Candidates limited to the public interface (no
  LAN IP in ICE); private windows remove WebRTC entirely.
- **Ad & tracker blocking.** Network-layer blocking (adblock-rust) + a live
  threat feed (URLhaus, OpenPhish, PhishTank, Spamhaus, Feodo) + a
  **community-confirmed phishing feed** with a real percentage per host. The
  **Dynamic Island** shows what was blocked and lets you allow per-site.
- **Pop-up blocker.** Script-spawned pop-unders (the kind sketchy streaming and
  torrent sites fire) are blocked outright, Brave-style — only a popup from a
  genuine click becomes a tab. Popups to threat-feed hosts are always blocked.
- **Pre-open sandbox gate.** A suspicious link is fetched first **through a
  private proxy** (Tor, else your custom proxy) into memory and analyzed — your
  tab never touches it until it's cleared. Your IP is never exposed by the
  probe.
- **Multi-source deep scan.** On-demand verification of a link against Google
  Safe Browsing, VirusTotal, URLhaus, ThreatFox, and AlienVault OTX, combined
  with the local model into one danger percentage — routed through the same
  private proxy so the scanners see a proxy exit IP, never yours. Opt-in; the
  everyday Guard stays fully on-device. Keys live only in the local config.
- **Real private windows.** Private browsing always opens a separate window
  with one ephemeral in-memory session and session-wide privacy switches.
- **Encrypted vault.** History, bookmarks, passwords sealed with AES-256-GCM;
  the key never leaves the machine.
- **Network hardening.** DoH (secure, no plaintext fallback), ECH, HTTPS-only,
  third-party cookies blocked.

### Network routing
- **Browser-wide proxy picker.** Off / **Tor** (embedded Arti) / **custom
  SOCKS5 or HTTP proxy** (e.g. a Mullvad endpoint). Chosen on the
  private-window home page. Because CEF's Alloy runtime refuses per-context
  **and** runtime proxy changes, a proxy is a launch-time switch — the picker
  persists your choice and offers one-click *Apply & relaunch*. `--vev-tor-all`
  still works from a terminal.

### Downloads
- **Media downloader (yt-dlp + ffmpeg).** From any supported site (YouTube,
  and 1800+ more): pick format and quality, extract **MP3**, or **Play online**
  (streams instead of saving). yt-dlp/ffmpeg are used from your `PATH` if
  present, else fetched once into app-data — nothing bundled into the installer.
- **High-speed segmented downloads** (parallel range requests) with an
  IDM-style manager: live progress, pause/resume/cancel, show-in-folder, and
  a clear-from-list control.
- **Torrent client (librqbit).** `.torrent` files and `magnet:` links are
  auto-detected — including by content-sniffing the downloaded bytes, so a
  torrent served with a movie-title filename still routes to the engine instead
  of saving as a file. Pause/resume/remove, live progress, streaming download.

### Everything else
- Content-script **extensions**, the **command palette**, find-in-page, zoom,
  tab drag-reorder, ⌘L, search suggestions, and every keyboard shortcut you
  expect.

## Build & run

Requires Rust (stable), the CEF binary distribution in `~/.local/share/cef`,
and the `bundle-cef-app` helper (from a cef-rs checkout). Then:

```bash
make run      # build + bundle + launch
make test     # cargo test across the workspace
make bundle   # assemble the app bundle without launching
make autotest # in-app runtime self-test suite
make train    # retrain the Huma phishing model (ONNX)
make help     # list all targets
```

CEF needs the assembled `.app` bundle to spawn its helper processes, so a bare
`cargo run` cannot launch the browser — always use `make run`/`make bundle`.
First launch takes ~15 s to bring up CEF and the first tab.

### Platforms

**macOS (Apple Silicon)** is the verified, day-to-day build. **Windows** and
**Linux** are supported by a cross-platform window-embedding layer
(`src-tauri/src/platform.rs`): the CEF child view attaches via the native
handle for each OS (NSView on macOS, `HWND` on Windows, X11 window on Linux,
resolved through `raw-window-handle`), and view show/hide/detach use the
matching platform API. All three OSes compile in CI (CEF auto-downloaded), so
the platform code is build-verified; Windows and Linux still need on-hardware
runtime testing (Linux is X11-only — Wayland can't host a CEF native child).

Do **not** re-sign the macOS bundle with `codesign --deep` — it corrupts CEF's
nested signatures; rebuild via `make bundle`, which signs correctly.

## Architecture

- `src/` — the shell UI (chrome, omnibox, Dynamic Island, internal pages,
  download popup, online player), plain HTML/CSS/JS in the Tauri webview.
- `src-tauri/` — the Rust app: CEF lifecycle, tab manager, commands, downloads,
  media, sandbox, and the render-process helper (`vev_helper`) that injects
  fingerprint resistance into every V8 context.
- `crates/` — the workspace: `huma` (AI: guard/content/adapt/model/read/
  predict/intel), `vev-fingerprint`, `vev-network`, `vev-blocklist` (incl. the
  community feed), `vev-storage`, `vev-tor`, `vev-download`, `vev-media`
  (yt-dlp/ffmpeg), `vev-torrent`.
- `scripts/train_guard/` — the Huma model training pipeline (features come from
  the same Rust extractor used at inference, so train/serve are identical).

## Privacy model

Nothing about your browsing leaves your device by default. History, bookmarks,
and passwords are encrypted locally; the AI runs in-process with no model
provider; the only optional outbound privacy request — a community phishing
report — is **off by default**, manual, and sends just a hostname + the AI
score (never full URLs or history). Downloads save plainly to `~/Downloads`
(and torrents to `~/Downloads/vev-torrents`); they are not encrypted, and Vev
does not claim otherwise.

### Honest limitations

- A few fingerprint surfaces (CSS-media screen size, local font enumeration,
  residual headless signals) still need engine-level work — documented, not
  hidden.
- Proxy routing (Tor/custom) is **browser-wide and applied at launch**: the
  embedded engine refuses per-context and runtime proxy changes, so switching
  needs a relaunch. Per-tab/per-window proxying isn't possible.
- Extensions are the content-script subset; background pages / popups /
  `chrome.*` APIs aren't supported by the embedded engine (Vev says so up
  front).
- The media downloader needs yt-dlp for streaming sites and ffmpeg for
  MP3/format conversion (used from `PATH` or fetched once). YouTube can throttle
  yt-dlp to few formats without a po-token plugin.
- YouTube in-stream ads are best-effort (they're muxed with the video).
