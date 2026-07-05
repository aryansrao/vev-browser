#!/usr/bin/env node
// Phase 4 fingerprint-resistance verification over the DevTools protocol.
// Reads the values a fingerprinting suite would read, twice (fresh navigations),
// and asserts: (a) they match the fixed reference profile, (b) canvas/webgl/
// audio hashes are identical across the two loads (stable, no per-render
// entropy). Run while Vev is up: node scripts/verify-fingerprint.mjs
const CDP = "http://127.0.0.1:9223";
const report = (n, ok, d) => console.log(`FPTEST: ${ok ? "PASS" : "FAIL"} ${n} — ${d}`);

async function firstPage() {
  const t = await (await fetch(`${CDP}/json/list`)).json();
  return t.find((x) => x.type === "page").webSocketDebuggerUrl;
}
function connect(u) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(u);
    let id = 0;
    const pend = new Map();
    ws.onopen = () =>
      resolve({
        send: (m, p = {}) =>
          new Promise((res, rej) => {
            const i = ++id;
            pend.set(i, { res, rej });
            ws.send(JSON.stringify({ id: i, method: m, params: p }));
          }),
      });
    ws.onerror = reject;
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.id && pend.has(m.id)) {
        const { res, rej } = pend.get(m.id);
        pend.delete(m.id);
        m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
      }
    };
  });
}
const ev = (cdp, expr) =>
  cdp
    .send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })
    .then((r) => {
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result.value;
    });

const PROBE = `JSON.stringify((function(){
  function canvasHash(){
    const c=document.createElement('canvas');c.width=220;c.height=30;
    const x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';
    x.fillStyle='#f60';x.fillRect(0,0,120,20);x.fillStyle='#069';x.fillText('Vev\\u2764fp',2,2);
    return c.toDataURL();
  }
  function webglHash(){
    try{const g=document.createElement('canvas').getContext('webgl');
      const e=g.getExtension('WEBGL_debug_renderer_info');
      return [g.getParameter(e.UNMASKED_VENDOR_WEBGL),g.getParameter(e.UNMASKED_RENDERER_WEBGL)].join('|');
    }catch(e){return 'noWebGL'}
  }
  function audioHash(){
    try{const C=new (window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,4410,44100);
      const o=C.createOscillator();o.frequency.value=1000;
      const a=C.createAnalyser();o.connect(a);a.connect(C.destination);o.start(0);
      const buf=new Float32Array(a.frequencyBinCount);a.getFloatFrequencyData(buf);
      return buf.slice(0,8).join(',');
    }catch(e){return 'noAudio'}
  }
  return {
    ua: navigator.userAgent, platform: navigator.platform,
    lang: navigator.language, langs: navigator.languages.join(','),
    hc: navigator.hardwareConcurrency, mem: navigator.deviceMemory,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    tzoff: new Date().getTimezoneOffset(),
    screen: [screen.width,screen.height,screen.colorDepth].join('x'),
    canvas: canvasHash().slice(-40), webgl: webglHash(), audio: audioHash(),
  };
})())`;

const cdp = await connect(await firstPage());
await cdp.send("Page.enable");

async function probeAt(url) {
  await cdp.send("Page.navigate", { url });
  await new Promise((r) => setTimeout(r, 3500));
  return JSON.parse(await ev(cdp, PROBE));
}

const a = await probeAt("https://example.com/");
const b = await probeAt("https://example.org/"); // different origin, second load

// Per-OS profile: the UA/platform must match the host OS family (a cross-OS
// lie contradicts Chromium's Sec-CH-UA-Platform header and trips bot checks).
const PLATFORMS = { darwin: "MacIntel", win32: "Win32", linux: "Linux x86_64" };
const UA_RE = {
  darwin: /Macintosh.*Chrome\/149/,
  win32: /Windows NT 10\.0.*Chrome\/149/,
  linux: /X11; Linux.*Chrome\/149/,
};
report("platform_fixed", a.platform === PLATFORMS[process.platform], a.platform);
report("hardwareConcurrency_2", a.hc === 2, String(a.hc));
report("deviceMemory_8", a.mem === 8, String(a.mem));
report("language_en_us", a.lang === "en-US" && a.langs === "en-US,en", `${a.lang} / ${a.langs}`);
report("timezone_utc", a.tz === "UTC" && a.tzoff === 0, `${a.tz} off=${a.tzoff}`);
report("ua_fixed", UA_RE[process.platform].test(a.ua), a.ua.slice(0, 60));
report("screen_fixed", a.screen === "1920x1080x24", a.screen);
report("webgl_fixed", /Google Inc\. \(Intel\)/.test(a.webgl), a.webgl.slice(0, 40));

// Stability: the entropy-bearing readbacks must be identical across the two
// separate page loads (uniform fixed output, not per-render noise).
report("canvas_stable", a.canvas === b.canvas, `${a.canvas === b.canvas}`);
report("webgl_stable", a.webgl === b.webgl, `${a.webgl === b.webgl}`);
report("audio_stable", a.audio === b.audio, `${a.audio === b.audio}`);

console.log("FPTEST: DONE");
