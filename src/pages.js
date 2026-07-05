// Vev internal pages. Each renderer fills the #page host (a real tab in the
// strip, shown by the shell while the tab's CEF view — if any — is hidden).
// Talks to the Rust backend only through tauri commands.
const PInvoke = window.__TAURI__.core.invoke;

function h(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}
function pEsc(s) {
  return String(s == null ? "" : s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
function hostOf(url) {
  try {
    return new URL(url).host || url;
  } catch (e) {
    return url;
  }
}
function faviconEl(url) {
  const host = hostOf(url);
  return `<span class="ic"><span class="fav" style="width:18px;height:18px;border-radius:5px;background:var(--violet-dim) center/cover no-repeat;background-image:url('https://${pEsc(
    host
  )}/favicon.ico')"></span></span>`;
}
function timeAgo(unix) {
  const s = Math.max(1, Math.floor(Date.now() / 1000 - unix));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return new Date(unix * 1000).toLocaleDateString();
}
function mb(n) {
  return (n / 1048576).toFixed(1);
}

// A toggle-switch row used across pages. onToggle(newState).
function switchRow(icon, title, sub, on, onToggle) {
  const row = h(
    `<div class="item"><span class="ic" data-icon="${icon}"></span>
     <div class="grow"><div class="t">${pEsc(title)}</div><div class="s">${pEsc(sub)}</div></div>
     <button class="switch${on ? " on" : ""}"></button></div>`
  );
  const sw = row.querySelector(".switch");
  sw.onclick = () => {
    const next = !sw.classList.contains("on");
    sw.classList.toggle("on", next);
    onToggle(next);
  };
  paintIcons(row);
  return row;
}

// The registry the shell calls: PAGES[name](host, ctx).
const PAGES = {};

// ---------- Settings ----------
PAGES["settings"] = async function (host, ctx) {
  const [cfg, engines, tor, ver] = await Promise.all([
    PInvoke("config_get").catch(() => ({})),
    PInvoke("search_engines").catch(() => []),
    PInvoke("tor_status").catch(() => "unavailable"),
    PInvoke("cef_version").catch(() => ({})),
  ]);
  const sections = [
    ["general", "settings", "General"],
    ["privacy", "shield", "Privacy & Security"],
    ["network", "www", "Network & Tor"],
    ["huma", "sparks", "Huma AI"],
    ["about", "info-circle", "About"],
  ];
  host.innerHTML = "";
  const wrap = h(`<div class="page-wrap"></div>`);
  wrap.appendChild(h(`<div class="page-title">Settings</div>`));
  wrap.appendChild(
    h(`<div class="page-sub">Vev keeps privacy defaults on. Change what you need — the rest stays hardened.</div>`)
  );
  const grid = h(`<div class="settings"></div>`);
  const rail = h(`<div class="rail"></div>`);
  const panel = h(`<div class="s-panel"></div>`);
  grid.appendChild(rail);
  grid.appendChild(panel);
  wrap.appendChild(grid);
  host.appendChild(wrap);

  let current = (ctx && ctx.section) || "general";
  const render = () => {
    rail.innerHTML = "";
    for (const [id, icon, label] of sections) {
      const b = h(
        `<button class="${id === current ? "on" : ""}"><span data-icon="${icon}"></span><span>${label}</span></button>`
      );
      b.onclick = () => {
        current = id;
        render();
      };
      paintIcons(b);
      rail.appendChild(b);
    }
    panel.innerHTML = "";
    panelFns[current]();
    paintIcons(panel);
  };

  const panelFns = {
    general() {
      panel.appendChild(h(`<div class="sec-h">Search engine</div>`));
      const opts = engines
        .map(
          ([name]) =>
            `<option value="${pEsc(name)}"${cfg.search_engine === name ? " selected" : ""}>${pEsc(name)}</option>`
        )
        .join("");
      const card = h(`<div class="card"></div>`);
      const engRow = h(
        `<div class="item"><span class="ic" data-icon="search"></span>
         <div class="grow"><div class="t">Default search</div><div class="s">Used by the address bar and start page</div></div>
         <select class="field" id="s-engine" style="width:190px">${opts}</select></div>`
      );
      card.appendChild(engRow);
      const homeRow = h(
        `<div class="item"><span class="ic" data-icon="home"></span>
         <div class="grow"><div class="t">Home &amp; new tab</div><div class="s">Blank = Vev start page. Or paste a URL / local .html path.</div></div>
         <input class="field" id="s-home" style="width:230px" placeholder="Vev start page" value="${pEsc(cfg.home_url || "")}"></div>`
      );
      card.appendChild(homeRow);
      panel.appendChild(card);
      const save = h(`<button class="btn accent" style="margin-top:16px"><span data-icon="floppy"></span>Save changes</button>`);
      save.onclick = async () => {
        await PInvoke("config_set", {
          searchEngine: panel.querySelector("#s-engine").value,
          homeUrl: panel.querySelector("#s-home").value.trim() || null,
          humaGuard: cfg.huma_guard !== false,
        }).catch((e) => ctx.toast("Couldn't save: " + e));
        ctx.toast("Settings saved.");
      };
      panel.appendChild(save);
    },
    privacy() {
      panel.appendChild(h(`<div class="sec-h">Always on</div>`));
      const card = h(`<div class="card"></div>`);
      const onRow = (icon, t, s) =>
        h(
          `<div class="item"><span class="ic" data-icon="${icon}"></span>
           <div class="grow"><div class="t">${t}</div><div class="s">${s}</div></div><span class="tag on">On</span></div>`
        );
      card.appendChild(onRow("mask-square", "Fingerprint resistance", "Uniform fixed profile — canvas, WebGL, audio, fonts, timezone"));
      card.appendChild(onRow("lock", "WebRTC IP protection", "Candidates limited to the public interface; no LAN IP leak"));
      card.appendChild(onRow("shield-check", "Network hardening", "DoH (secure), ECH, HTTPS-only, third-party cookies blocked"));
      card.appendChild(onRow("key", "Encrypted vault", "History, bookmarks, passwords sealed with AES-256-GCM"));
      panel.appendChild(card);
      panel.appendChild(
        h(`<div class="note"><b>Private windows</b> add a session-wide WebRTC kill switch and open in a separate window — set those on the private-window home page.</div>`)
      );
    },
    network() {
      panel.appendChild(h(`<div class="sec-h">Connection</div>`));
      const card = h(`<div class="card"></div>`);
      card.appendChild(
        h(`<div class="item"><span class="ic" data-icon="www"></span>
           <div class="grow"><div class="t">DNS over HTTPS</div><div class="s">Secure mode, no plaintext fallback</div></div><span class="tag on">On</span></div>`)
      );
      const proxyActive = cfg.proxy_active_mode || "off";
      card.appendChild(
        h(`<div class="item"><span class="ic" data-icon="network"></span>
           <div class="grow"><div class="t">Browser-wide proxy</div><div class="s">Off / Tor / custom SOCKS5 (e.g. Mullvad) — pick it on the private-window home page (⌘⇧N)</div></div>
           <span class="tag ${proxyActive === "off" ? "off" : "on"}">${pEsc(proxyActive)}</span></div>`)
      );
      panel.appendChild(card);
      panel.appendChild(
        h(`<div class="note">Proxying is <b>browser-wide</b> (the embedded engine refuses per-window and runtime proxy changes, so per-tab routing would silently leak). The picker lives on the private-window home page and applies on relaunch; --vev-tor-all still works from a terminal.</div>`)
      );
    },
    huma() {
      panel.appendChild(h(`<div class="sec-h">On-device AI — nothing leaves your machine</div>`));
      const card = h(`<div class="card"></div>`);
      card.appendChild(
        switchRow("shield-alert", "Huma Guard", "Trained ML model (ONNX) + reads page content; adapts on-device from your Allow/Block choices", cfg.huma_guard !== false, async (on) => {
          cfg.huma_guard = on;
          await PInvoke("config_set", {
            searchEngine: cfg.search_engine || null,
            homeUrl: cfg.home_url || null,
            humaGuard: on,
          }).catch(() => {});
          ctx.toast(on ? "Huma Guard on." : "Huma Guard off.");
        })
      );
      card.appendChild(
        h(`<div class="item"><span class="ic" data-icon="book"></span>
           <div class="grow"><div class="t">Huma Read</div><div class="s">Summarize any page — extractive, faithful, no hallucination</div></div><span class="tag on">On</span></div>`)
      );
      card.appendChild(
        h(`<div class="item"><span class="ic" data-icon="flash"></span>
           <div class="grow"><div class="t">Huma Predict</div><div class="s">Learns your navigation locally and pre-warms the likely next site</div></div><span class="tag on">On</span></div>`)
      );
      panel.appendChild(card);

      panel.appendChild(h(`<div class="sec-h">Community phishing feed</div>`));
      const cfeed = h(`<div class="card"></div>`);
      cfeed.appendChild(
        h(`<div class="item"><span class="ic" data-icon="shield"></span>
           <div class="grow"><div class="t">Show community-confirmed flags</div><div class="s">Fetches the public feed and shows a confirmed-phishing percentage</div></div><span class="tag on">On</span></div>`)
      );
      cfeed.appendChild(
        switchRow(
          "shield-check",
          "Share my reports",
          "When you click Report, submit the plaintext host + AI score to the community feed. Off = reports only train your local Guard.",
          cfg.community_reporting === true,
          async (on) => {
            cfg.community_reporting = on;
            await PInvoke("config_set", {
              searchEngine: cfg.search_engine || null,
              homeUrl: cfg.home_url || null,
              humaGuard: cfg.huma_guard !== false,
              communityReporting: on,
            }).catch(() => {});
            ctx.toast(on ? "Sharing reports with the community feed." : "Reports stay on this device.");
          }
        )
      );
      panel.appendChild(cfeed);
      panel.appendChild(
        h(`<div class="note">Reporting needs a feed endpoint (<b>report_endpoint</b> in config.json — the Vev report API). Until one is set, Report only trains your on-device Guard.</div>`)
      );
    },
    about() {
      panel.appendChild(h(`<div class="sec-h">About Vev</div>`));
      const card = h(`<div class="card"></div>`);
      const line = (t, s) => h(`<div class="item"><div class="grow"><div class="t">${t}</div></div><span class="reveal">${pEsc(s)}</span></div>`);
      card.appendChild(line("Vev", ver.vev || "0.1.0"));
      card.appendChild(line("Engine (CEF)", ver.cef || "149.0.6"));
      card.appendChild(line("Chromium", ver.chromium || "149.0.7827.201"));
      card.appendChild(line("Huma Guard model", ver.huma_model || "linear"));
      panel.appendChild(card);
      panel.appendChild(h(`<div class="note">A browser where fingerprint resistance, threat blocking, network hardening, and on-device AI are defaults — not paid add-ons.</div>`));
    },
  };
  render();
};

// ---------- History ----------
PAGES["history"] = async function (host, ctx) {
  const render = async (filter) => {
    let items = await PInvoke("history_list", { limit: 500 }).catch(() => []);
    if (filter) {
      const q = filter.toLowerCase();
      items = items.filter((i) => (i.url + " " + (i.title || "")).toLowerCase().includes(q));
    }
    host.innerHTML = "";
    const wrap = h(`<div class="page-wrap"></div>`);
    wrap.appendChild(h(`<div class="page-title">History</div>`));
    wrap.appendChild(h(`<div class="page-sub">Stored encrypted on this device only. Nothing is synced.</div>`));
    const bar = h(`<div class="toolbar-row"></div>`);
    const search = h(`<input class="field" placeholder="Search history" value="${pEsc(filter || "")}">`);
    search.oninput = () => render(search.value);
    const clear = h(`<button class="btn danger"><span data-icon="trash"></span>Clear all</button>`);
    clear.onclick = async () => {
      await PInvoke("history_clear").catch(() => {});
      ctx.toast("History cleared.");
      render("");
    };
    bar.appendChild(search);
    bar.appendChild(clear);
    wrap.appendChild(bar);
    if (!items.length) {
      wrap.appendChild(h(`<div class="empty"><span data-icon="history"></span>Nothing here yet. Pages you visit will show up here.</div>`));
    } else {
      const card = h(`<div class="card"></div>`);
      for (const it of items) {
        const row = h(
          `<div class="item link">${faviconEl(it.url)}
           <div class="grow"><div class="t">${pEsc(it.title || it.url)}</div><div class="s">${pEsc(it.url)} · ${timeAgo(it.visited_unix)}</div></div>
           <button class="btn sm" title="Remove"><span data-icon="xmark"></span></button></div>`
        );
        row.querySelector(".grow").onclick = () => ctx.navigate(it.url);
        row.querySelector("button").onclick = async (e) => {
          e.stopPropagation();
          await PInvoke("history_delete", { url: it.url }).catch(() => {});
          render(search.value);
        };
        card.appendChild(row);
      }
      wrap.appendChild(card);
    }
    host.appendChild(wrap);
    paintIcons(wrap);
    setTimeout(() => search.focus(), 30);
  };
  render("");
};

// ---------- Bookmarks ----------
PAGES["bookmarks"] = async function (host, ctx) {
  const render = async (filter) => {
    let items = await PInvoke("bookmarks_list").catch(() => []);
    ctx.setBookmarks && ctx.setBookmarks(items);
    if (filter) {
      const q = filter.toLowerCase();
      items = items.filter((i) => (i.url + " " + (i.title || "")).toLowerCase().includes(q));
    }
    host.innerHTML = "";
    const wrap = h(`<div class="page-wrap"></div>`);
    wrap.appendChild(h(`<div class="page-title">Bookmarks</div>`));
    wrap.appendChild(h(`<div class="page-sub">Saved pages, sealed in your encrypted vault.</div>`));
    const bar = h(`<div class="toolbar-row"></div>`);
    const search = h(`<input class="field" placeholder="Search bookmarks" value="${pEsc(filter || "")}">`);
    search.oninput = () => render(search.value);
    bar.appendChild(search);
    wrap.appendChild(bar);
    if (!items.length) {
      wrap.appendChild(h(`<div class="empty"><span data-icon="star"></span>No bookmarks yet. Tap the star in the toolbar to save a page.</div>`));
    } else {
      const card = h(`<div class="card"></div>`);
      for (const b of items) {
        const row = h(
          `<div class="item link">${faviconEl(b.url)}
           <div class="grow"><div class="t">${pEsc(b.title || b.url)}</div><div class="s">${pEsc(b.url)}</div></div>
           <button class="btn sm danger">Remove</button></div>`
        );
        row.querySelector(".grow").onclick = () => ctx.navigate(b.url);
        row.querySelector("button").onclick = async (e) => {
          e.stopPropagation();
          await PInvoke("bookmarks_remove", { url: b.url }).catch(() => {});
          render(search.value);
        };
        card.appendChild(row);
      }
      wrap.appendChild(card);
    }
    host.appendChild(wrap);
    paintIcons(wrap);
  };
  render("");
};

// ---------- Downloads & torrents ----------
PAGES["downloads"] = async function (host, ctx) {
  const draw = async () => {
    const [downloads, torrents] = await Promise.all([
      PInvoke("downloads_list").catch(() => []),
      PInvoke("torrent_list").catch(() => []),
    ]);
    host.innerHTML = "";
    const wrap = h(`<div class="page-wrap"></div>`);
    wrap.appendChild(h(`<div class="page-title">Downloads</div>`));
    wrap.appendChild(h(`<div class="page-sub">Files, high-speed segmented downloads, and torrents.</div>`));

    const addRow = h(`<div class="toolbar-row"></div>`);
    const magnet = h(`<input class="field" placeholder="Paste a magnet: link or .torrent URL">`);
    const add = h(`<button class="btn accent"><span data-icon="magnet"></span>Add torrent</button>`);
    add.onclick = async () => {
      const v = magnet.value.trim();
      if (!v) return;
      try {
        await PInvoke("torrent_add", { magnet: v });
        magnet.value = "";
        ctx.toast("Torrent added.");
        draw();
      } catch (e) {
        ctx.toast("Torrent: " + e);
      }
    };
    addRow.appendChild(magnet);
    addRow.appendChild(add);
    wrap.appendChild(addRow);

    if (!downloads.length && !torrents.length) {
      wrap.appendChild(h(`<div class="empty"><span data-icon="download"></span>No downloads yet.</div>`));
    } else {
      const card = h(`<div class="card"></div>`);
      for (const t of torrents) {
        const paused = /paus/i.test(t.state);
        const row = h(
          `<div class="item"><span class="ic" data-icon="magnet"></span>
           <div class="grow"><div class="t">${pEsc(t.name)}</div>
           <div class="s">${t.percent}% · ${mb(t.progress_bytes)}/${mb(t.total_bytes)} MB · ↓${t.down_mbps.toFixed(2)} MiB/s · ${pEsc(t.state)}</div>
           <div class="progress"><i style="width:${t.percent}%"></i></div></div>
           <div class="row-actions"></div></div>`
        );
        const acts = row.querySelector(".row-actions");
        if (!t.finished) {
          const [act, ic, label] = paused ? ["resume", "play", "Resume"] : ["pause", "pause", "Pause"];
          const pb = h(`<button class="btn sm" title="${label}"><span data-icon="${ic}"></span></button>`);
          pb.onclick = () => PInvoke("torrent_control", { id: t.id, action: act }).then(draw).catch((e) => ctx.toast(String(e)));
          acts.appendChild(pb);
        }
        const rm = h(`<button class="btn sm danger" title="Remove torrent (keeps downloaded files)"><span data-icon="trash"></span></button>`);
        rm.onclick = async () => {
          await PInvoke("torrent_control", { id: t.id, action: "remove" }).catch((e) => ctx.toast(String(e)));
          ctx.toast("Removed. Downloaded files kept in the torrents folder.");
          draw();
        };
        acts.appendChild(rm);
        card.appendChild(row);
      }
      for (const d of downloads) {
        const done = d.state === "complete";
        const failed = d.state === "canceled";
        // Finished rows read "12.4 MB · downloaded 3m ago", not "100% · 0.0/0.0".
        let sub;
        if (done) {
          const when = d.completed_unix ? " · downloaded " + timeAgo(d.completed_unix) : "";
          sub = `${d.total > 0 ? mb(d.total) + " MB" : "done"}${when}`;
        } else if (failed) {
          sub = "canceled";
        } else {
          const speed = d.speed > 0 ? ` · ${mb(d.speed)} MB/s` : "";
          const of = d.total > 0 ? `${mb(d.received)}/${mb(d.total)} MB` : `${mb(d.received)} MB`;
          sub = `${d.percent}% · ${of}${speed}`;
        }
        const bar = done || failed ? "" : `<div class="progress"><i style="width:${d.percent}%"></i></div>`;
        const row = h(
          `<div class="item"><span class="ic" data-icon="${done ? "check-circle" : "download"}"></span>
           <div class="grow"><div class="t">${pEsc(d.file_name)}</div>
           <div class="s">${sub}</div>${bar}</div>
           <div class="row-actions"></div></div>`
        );
        const acts = row.querySelector(".row-actions");
        if (d.state === "in_progress" || d.state === "paused") {
          // yt-dlp/segmented workers only support cancel (ids >= 1_000_000);
          // CEF downloads support pause/resume too.
          const isManual = d.id >= 1000000;
          const controls = isManual
            ? [["cancel", "xmark", "Cancel"]]
            : [["pause", "pause", "Pause"], ["resume", "play", "Resume"], ["cancel", "xmark", "Cancel"]];
          for (const [act, ic, label] of controls) {
            const b = h(`<button class="btn sm" title="${label}"><span data-icon="${ic}"></span></button>`);
            b.onclick = () => PInvoke("download_control", { id: d.id, action: act }).then(draw);
            acts.appendChild(b);
          }
        }
        if (done && d.full_path) {
          const sf = h(`<button class="btn sm" title="Show in folder"><span data-icon="folder"></span>Show</button>`);
          sf.onclick = () => PInvoke("reveal_in_folder", { path: d.full_path }).catch((e) => ctx.toast(String(e)));
          acts.appendChild(sf);
        }
        if (done && d.is_media && d.full_path) {
          const w = h(`<button class="btn sm accent"><span data-icon="play"></span>Watch</button>`);
          w.onclick = () => {
            window.__vevPlayerUrl = "file://" + d.full_path;
            window.__vevPlayerTitle = d.file_name;
            window.__vevPlayerSource = d.url;
            openInternal("player");
          };
          acts.appendChild(w);
        }
        // Clear the row from the list (any state) — removes the entry, keeps
        // the file. Fixes stuck/old downloads that couldn't be dismissed.
        const clear = h(`<button class="btn sm" title="Remove from list"><span data-icon="trash"></span></button>`);
        clear.onclick = () => PInvoke("download_remove", { id: d.id }).then(draw).catch((e) => ctx.toast(String(e)));
        acts.appendChild(clear);
        card.appendChild(row);
      }
      wrap.appendChild(card);
    }
    host.appendChild(wrap);
    paintIcons(wrap);
  };
  draw();
  return { refresh: draw };
};

// ---------- Passwords ----------
PAGES["passwords"] = async function (host, ctx) {
  const render = async () => {
    const items = await PInvoke("passwords_all").catch(() => []);
    host.innerHTML = "";
    const wrap = h(`<div class="page-wrap"></div>`);
    wrap.appendChild(h(`<div class="page-title">Passwords</div>`));
    wrap.appendChild(h(`<div class="page-sub">Saved locally, AES-256-GCM encrypted. Never synced, never sent anywhere.</div>`));

    wrap.appendChild(h(`<div class="sec-h">Add a login</div>`));
    const card = h(`<div class="card"></div>`);
    card.appendChild(h(`<div class="item"><span class="ic" data-icon="www"></span><input class="field" id="p-origin" placeholder="https://site.com"></div>`));
    card.appendChild(h(`<div class="item"><span class="ic" data-icon="glasses"></span><input class="field" id="p-user" placeholder="Username or email"></div>`));
    card.appendChild(h(`<div class="item"><span class="ic" data-icon="key"></span><input class="field" id="p-pass" type="password" placeholder="Password"></div>`));
    const saveRow = h(`<div class="item"><button class="btn accent"><span data-icon="floppy"></span>Save encrypted</button></div>`);
    saveRow.querySelector("button").onclick = async () => {
      const origin = card.querySelector("#p-origin").value.trim();
      const username = card.querySelector("#p-user").value.trim();
      const password = card.querySelector("#p-pass").value;
      if (!origin || !username) return ctx.toast("Enter a site and username.");
      try {
        await PInvoke("passwords_save", { origin, username, password });
        ctx.toast("Saved.");
        render();
      } catch (e) {
        ctx.toast("Save failed: " + e);
      }
    };
    card.appendChild(saveRow);
    wrap.appendChild(card);

    wrap.appendChild(h(`<div class="sec-h">Saved logins</div>`));
    if (!items.length) {
      wrap.appendChild(h(`<div class="empty"><span data-icon="key"></span>No saved passwords yet.</div>`));
    } else {
      const list = h(`<div class="card"></div>`);
      for (const p of items) {
        const row = h(
          `<div class="item"><span class="ic" data-icon="key"></span>
           <div class="grow"><div class="t">${pEsc(p.username)}</div><div class="s">${pEsc(p.origin)}</div></div>
           <span class="reveal" style="min-width:90px">••••••••</span>
           <div class="row-actions">
             <button class="btn sm reveal-btn"><span data-icon="eye"></span></button>
             <button class="btn sm danger">Delete</button></div></div>`
        );
        const rev = row.querySelector(".reveal");
        row.querySelector(".reveal-btn").onclick = () => {
          rev.textContent = rev.textContent.startsWith("•") ? p.password : "••••••••";
        };
        row.querySelector(".danger").onclick = async () => {
          await PInvoke("passwords_delete", { origin: p.origin, username: p.username }).catch(() => {});
          render();
        };
        list.appendChild(row);
      }
      wrap.appendChild(list);
    }
    host.appendChild(wrap);
    paintIcons(wrap);
  };
  render();
};

// ---------- Extensions ----------
PAGES["extensions"] = async function (host, ctx) {
  const render = async () => {
    const items = await PInvoke("extensions_list").catch(() => []);
    host.innerHTML = "";
    const wrap = h(`<div class="page-wrap"></div>`);
    wrap.appendChild(h(`<div class="page-title">Extensions</div>`));
    wrap.appendChild(h(`<div class="page-sub">Load unpacked extensions that use content scripts (CSS/JS injected into pages).</div>`));

    const bar = h(`<div class="toolbar-row"></div>`);
    const path = h(`<input class="field" placeholder="Path to an unpacked extension folder (with manifest.json)">`);
    const install = h(`<button class="btn accent"><span data-icon="plus"></span>Load</button>`);
    install.onclick = async () => {
      const p = path.value.trim();
      if (!p) return;
      try {
        await PInvoke("extensions_install", { path: p });
        path.value = "";
        ctx.toast("Extension loaded.");
        render();
      } catch (e) {
        ctx.toast(String(e));
      }
    };
    bar.appendChild(path);
    bar.appendChild(install);
    wrap.appendChild(bar);

    if (!items.length) {
      wrap.appendChild(h(`<div class="empty"><span data-icon="puzzle"></span>No extensions loaded. Point Vev at an unpacked folder above.</div>`));
    } else {
      const card = h(`<div class="card"></div>`);
      for (const e of items) {
        const row = h(
          `<div class="item"><span class="ic" data-icon="puzzle"></span>
           <div class="grow"><div class="t">${pEsc(e.name)} <span class="tag info" style="margin-left:6px">MV${e.manifest_version || "?"}</span></div>
           <div class="s">v${pEsc(e.version || "?")} · ${e.content_script_count} content script(s) · ${pEsc(e.description || "")}</div></div>
           <div class="row-actions">
             <button class="switch${e.enabled ? " on" : ""}"></button>
             <button class="btn sm danger">Remove</button></div></div>`
        );
        const sw = row.querySelector(".switch");
        sw.onclick = async () => {
          const next = !sw.classList.contains("on");
          sw.classList.toggle("on", next);
          await PInvoke("extensions_toggle", { id: e.id, enabled: next }).catch(() => {});
          ctx.toast(next ? "Enabled — reload pages to apply." : "Disabled.");
        };
        row.querySelector(".danger").onclick = async () => {
          await PInvoke("extensions_uninstall", { id: e.id }).catch(() => {});
          render();
        };
        card.appendChild(row);
      }
      wrap.appendChild(card);
    }
    wrap.appendChild(
      h(`<div class="note"><b>What runs:</b> content-script extensions — the CSS/JS-into-pages kind (dark themes, restylers, userscript-style helpers). <b>What doesn't:</b> background pages, popups, and chrome.* APIs, which the embedded engine (CEF) has no runtime for. Vev tells you up front instead of failing silently.</div>`)
    );
    host.appendChild(wrap);
    paintIcons(wrap);
  };
  render();
};

// ---------- Private browsing home ----------
PAGES["private-home"] = async function (host, ctx) {
  const [s, proxy] = await Promise.all([
    PInvoke("incognito_settings_get").catch(() => ({
      block_webrtc: true,
      fingerprint_spoof: true,
      page_shields: true,
    })),
    PInvoke("proxy_status").catch(() => ({
      active_mode: "off",
      desired_mode: "off",
      custom_url: "",
      tor_status: "unavailable",
    })),
  ]);
  host.innerHTML = "";
  const wrap = h(`<div class="inc-home"></div>`);
  wrap.appendChild(h(`<div class="inc-badge" data-icon="privacy"></div>`));
  wrap.appendChild(h(`<h1>You're browsing privately</h1>`));
  wrap.appendChild(
    h(`<p>This is a separate private window. Nothing here is written to disk — no history, cookies, or cache survive when the last private window closes. These privacy controls apply to every tab and window in this private session.</p>`)
  );
  const search = h(
    `<div class="inc-search"><span data-icon="search"></span><input placeholder="Search privately" autofocus></div>`
  );
  const input = search.querySelector("input");
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && input.value.trim()) ctx.navigate(input.value.trim());
  });
  wrap.appendChild(search);

  const toggles = h(`<div class="inc-toggles"></div>`);
  toggles.appendChild(h(`<div class="lead">Privacy for this session</div>`));
  const card = h(`<div class="card"></div>`);
  const push = async () => {
    await PInvoke("incognito_settings_set", { settings: s }).catch(() => {});
  };
  card.appendChild(
    switchRow("lock", "Block WebRTC", "Removes WebRTC entirely so no IP can leak through it", s.block_webrtc, (v) => {
      s.block_webrtc = v;
      push();
    })
  );
  card.appendChild(
    switchRow("mask-square", "Fingerprint resistance", "Uniform fixed device profile on every private page", s.fingerprint_spoof, (v) => {
      s.fingerprint_spoof = v;
      push();
    })
  );
  card.appendChild(
    switchRow("shield", "Ad & tracker shields", "Cosmetic filtering + scriptlets on private pages", s.page_shields, (v) => {
      s.page_shields = v;
      push();
    })
  );
  toggles.appendChild(card);
  toggles.appendChild(h(`<div class="note">Changes take effect on the next page you load. Reload an open tab to apply them there.</div>`));

  // Network privacy: browser-wide proxy picker (Off / Tor / custom SOCKS or
  // HTTP proxy, e.g. Mullvad). The embedded engine can't proxy a single
  // window and refuses runtime proxy changes, so this is browser-wide and
  // applied on relaunch. `desired` is what's saved; `active_mode` is what
  // this run is actually using — they differ until a relaunch.
  let desired = proxy.desired_mode || "off";
  let customUrl = proxy.custom_url || "";
  const active = proxy.active_mode || "off";
  toggles.appendChild(h(`<div class="lead" style="margin-top:26px">Network privacy</div>`));
  const proxyCard = h(`<div class="card"></div>`);

  // Live status of this run.
  const statusLabel = {
    off: "Direct connection",
    tor: "Routing through Tor",
    custom: "Routing through a custom proxy",
  }[active];
  proxyCard.appendChild(
    h(`<div class="item"><span class="ic" data-icon="network"></span>
       <div class="grow"><div class="t">This session</div>
       <div class="s">${pEsc(statusLabel)}${
         active === "tor" ? " · " + pEsc(proxy.tor_status) : ""
       }</div></div>
       <span class="tag ${active === "off" ? "off" : "on"}">${pEsc(active)}</span></div>`)
  );

  // Three-way mode selector.
  const modes = [
    ["off", "Off", "Direct connection — fastest, no proxy."],
    ["tor", "Tor", "Everything (DNS included) through the built-in Tor. Slow; some sites (YouTube, Cloudflare) block Tor exits."],
    ["custom", "Custom proxy", "Your own SOCKS5/HTTP proxy — e.g. Mullvad, a VPN's SOCKS endpoint. One stable exit IP, fast, not usually blocked."],
  ];
  const seg = h(`<div class="item" style="flex-direction:column;align-items:stretch;gap:10px"></div>`);
  const pick = h(`<div style="display:flex;gap:8px"></div>`);
  const customWrap = h(
    `<div style="display:${desired === "custom" ? "flex" : "none"};gap:8px">
       <input class="field" id="proxy-url" placeholder="socks5://10.64.0.1:1080  (or http://host:port)" value="${pEsc(customUrl)}">
     </div>`
  );
  const applyRow = h(
    `<div style="display:flex;align-items:center;gap:12px">
       <div class="s" id="proxy-hint" style="flex:1;color:var(--ink-3)"></div>
       <button class="btn accent" id="proxy-apply"><span data-icon="restart"></span>Apply &amp; relaunch</button>
     </div>`
  );
  const drawPick = () => {
    pick.innerHTML = "";
    for (const [id, label, sub] of modes) {
      const b = h(
        `<button class="btn${id === desired ? " accent" : ""}" style="flex:1;flex-direction:column;height:auto;padding:10px 12px;align-items:flex-start;gap:3px" title="${pEsc(sub)}">
           <span style="font-weight:600">${label}</span>
           <span style="font-size:11px;font-weight:400;opacity:.8;text-align:left;white-space:normal;line-height:1.35">${sub}</span>
         </button>`
      );
      b.onclick = () => {
        desired = id;
        customWrap.style.display = id === "custom" ? "flex" : "none";
        drawPick();
        updateHint();
      };
      pick.appendChild(b);
    }
    paintIcons(pick);
  };
  const updateHint = () => {
    const hint = applyRow.querySelector("#proxy-hint");
    const btn = applyRow.querySelector("#proxy-apply");
    const changed = desired !== active || (desired === "custom" && customWrap.querySelector("#proxy-url").value.trim() !== customUrl);
    if (desired === "tor" && proxy.tor_status !== "ready") {
      hint.textContent = "Tor is " + proxy.tor_status + "; it'll connect after relaunch.";
    } else if (!changed) {
      hint.textContent = "Already active this session.";
    } else {
      hint.textContent = "Saved settings apply after a relaunch (private tabs won't be restored).";
    }
    btn.style.opacity = changed ? "1" : ".5";
  };
  seg.appendChild(pick);
  seg.appendChild(customWrap);
  seg.appendChild(applyRow);
  proxyCard.appendChild(seg);
  toggles.appendChild(proxyCard);

  applyRow.querySelector("#proxy-apply").onclick = async () => {
    const url = customWrap.querySelector("#proxy-url").value.trim();
    try {
      await PInvoke("proxy_set", { mode: desired, url: desired === "custom" ? url : null });
    } catch (e) {
      ctx.toast(String(e));
      return;
    }
    ctx.toast("Relaunching to apply…");
    setTimeout(() => PInvoke("proxy_relaunch").catch(() => {}), 400);
  };
  customWrap.querySelector("#proxy-url").addEventListener("input", updateHint);
  drawPick();
  updateHint();

  toggles.appendChild(
    h(`<div class="note">Proxying is <b>browser-wide</b>: the embedded engine (CEF) won't route a single window and refuses live proxy changes, so a switch here needs a relaunch — pretending otherwise would leak your real IP. <b>Tor</b> is free and maximally private but slow and widely blocked. A <b>custom SOCKS5/HTTP proxy</b> (Mullvad, another VPN's proxy endpoint) gives one fast, stable exit IP that sites accept. Deep-scan and the pre-open sandbox already route through the built-in Tor regardless, so they never expose your IP.</div>`)
  );

  wrap.appendChild(toggles);
  host.appendChild(wrap);
  paintIcons(wrap);
  setTimeout(() => input.focus(), 40);
};

// ---------- Online player (Play online) ----------
// A shell-rendered <video> player. Rendering here (not a CEF navigation)
// means the resolved media URL never hits the phishing/threat navigation
// gate — playing a video the user asked for is intent, not a page visit.
// The stream URL is handed over via window.__vevPlayerUrl before the tab opens.
PAGES["player"] = async function (host, ctx) {
  const url = window.__vevPlayerUrl || "";
  const title = window.__vevPlayerTitle || "Now playing";
  host.innerHTML = "";
  const wrap = h(`<div class="player-wrap"></div>`);
  if (!url) {
    wrap.appendChild(h(`<div class="empty"><span data-icon="play"></span>Nothing to play. Use Download media → Play online.</div>`));
  } else {
    const bar = h(
      `<div class="player-bar"><div class="player-title">${pEsc(title)}</div>
       <button class="btn sm player-open">${""}Open source page</button></div>`
    );
    bar.querySelector(".player-open").textContent = "Open source page";
    bar.querySelector(".player-open").onclick = () => window.__vevPlayerSource && ctx.navigate(window.__vevPlayerSource);
    wrap.appendChild(bar);
    const video = h(
      `<video class="player-video" controls autoplay playsinline src="${pEsc(url)}"></video>`
    );
    video.onerror = () => {
      wrap.appendChild(
        h(`<div class="note">This stream wouldn't play inline (some sites hand back short-lived or segmented URLs). Try downloading it instead.</div>`)
      );
    };
    wrap.appendChild(video);
  }
  host.appendChild(wrap);
  paintIcons(wrap);
};

window.VevPages = PAGES;
