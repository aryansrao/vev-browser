#!/usr/bin/env node
// Phase 2 network-hardening verification via the DevTools protocol.
// Run while Vev is up: node scripts/verify-network.mjs
// Checks: strict referrer policy, third-party cookie blocking, ECH.

const CDP = "http://127.0.0.1:9223";

function report(name, ok, detail) {
  console.log(`NETTEST: ${ok ? "PASS" : "FAIL"} ${name} — ${detail}`);
}

async function firstPage() {
  const res = await fetch(`${CDP}/json/list`);
  const targets = await res.json();
  const page = targets.find((t) => t.type === "page");
  if (!page) throw new Error("no page target");
  return page.webSocketDebuggerUrl;
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let id = 0;
    const pending = new Map();
    ws.onopen = () =>
      resolve({
        send(method, params = {}) {
          return new Promise((res, rej) => {
            const mid = ++id;
            pending.set(mid, { res, rej });
            ws.send(JSON.stringify({ id: mid, method, params }));
          });
        },
        close: () => ws.close(),
      });
    ws.onerror = reject;
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? rej(new Error(JSON.stringify(msg.error))) : res(msg.result);
      }
    };
  });
}

async function evalAsync(cdp, expression) {
  const r = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
  return r.result.value;
}

async function navigate(cdp, url) {
  await cdp.send("Page.enable");
  await cdp.send("Page.navigate", { url });
  await new Promise((r) => setTimeout(r, 4000));
}

const cdp = await connect(await firstPage());

// --- Referrer policy: cross-origin fetch must carry origin-only referer.
await navigate(cdp, "https://example.com/");
try {
  const headers = JSON.parse(
    await evalAsync(cdp, `fetch('https://httpbin.org/headers').then(r=>r.text())`)
  );
  const ref = headers.headers["Referer"] ?? "(none)";
  report(
    "strict_referrer",
    ref === "https://example.com/",
    `cross-origin Referer=${ref} (full URL would include a path)`
  );
} catch (e) {
  report("strict_referrer", false, String(e));
}

// --- Third-party cookies: SameSite=None;Secure cookie from another site
// must NOT be stored/sent from a cross-site context.
try {
  await evalAsync(
    cdp,
    `fetch('https://httpbin.org/response-headers?Set-Cookie=' +
       encodeURIComponent('vevtest=1; SameSite=None; Secure; Path=/'),
       {credentials:'include'}).then(r=>r.text())`
  );
  const cookies = JSON.parse(
    await evalAsync(
      cdp,
      `fetch('https://httpbin.org/cookies',{credentials:'include'}).then(r=>r.text())`
    )
  );
  const got = JSON.stringify(cookies.cookies ?? {});
  report("third_party_cookies_blocked", got === "{}", `3p cookie jar=${got}`);
} catch (e) {
  report("third_party_cookies_blocked", false, String(e));
}

// --- ECH: cloudflare trace reports sni=encrypted when ECH was used.
try {
  await navigate(cdp, "https://crypto.cloudflare.com/cdn-cgi/trace");
  const text = await evalAsync(cdp, "document.body.innerText");
  const sni = (text.match(/sni=(\S+)/) ?? [])[1] ?? "(missing)";
  report("ech", sni === "encrypted", `sni=${sni}`);
} catch (e) {
  report("ech", false, String(e));
}

// Leave the tab somewhere neutral.
await navigate(cdp, "https://example.com/");
cdp.close();
console.log("NETTEST: DONE");
