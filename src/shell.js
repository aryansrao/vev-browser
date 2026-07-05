// Vev shell — top chrome (tab strip + toolbar + omnibox), internal-page
// routing, command palette, menu, find bar, keyboard shortcuts. Talks to the
// Rust backend only through tauri commands/events.
const { invoke } = window.__TAURI__.core;
// Window-scoped listener. The backend emits per-window state with
// emit_to(<this window's label>); the global `event.listen` registers for
// target "Any" which does NOT receive targeted emits. It also received every
// broadcast — with two windows open, each shell rendered whichever window's
// tab list arrived last (a private window opening "turned the normal window
// private"). Window-targeted listeners get both targeted and broadcast events.
const __WIN = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();
const listen = (event, handler) => __WIN.listen(event, handler);
const el = (id) => document.getElementById(id);

const IS_PRIVATE = new URLSearchParams(location.search).get("private") === "1";
if (IS_PRIVATE) document.documentElement.classList.add("private");

// ---- State ----
let tabs = [];
let bookmarks = [];
let suggestTimer = null;

function activeTab() {
  return tabs.find((t) => t.active);
}
function isBlank(url) {
  return (
    !url ||
    url === "about:blank" ||
    url.startsWith("data:") ||
    url.startsWith("vev://") ||
    url.includes("/startpage/index.html")
  );
}
function editableUrl(t) {
  // Internal pages show their vev:// address (downloads, extensions, …);
  // real pages show their URL; the start page / blank shows placeholder.
  if (t && t.internal) return "vev://" + t.internal;
  return t && t.url && !isBlank(t.url) ? t.url : "";
}
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// ---- Tab strip ----
const tabEls = new Map();
let dragId = null;

function buildTabEl(t) {
  const tab = document.createElement("div");
  tab.className = "tab";
  tab.draggable = true;
  tab.innerHTML = `<span class="fav"></span><span class="title"></span>`;
  const close = document.createElement("button");
  close.className = "close";
  close.innerHTML = iconSvg("xmark");
  close.title = "Close tab";
  close.onclick = (e) => {
    e.stopPropagation();
    invoke("tabs_close", { id: t.id });
  };
  tab.appendChild(close);
  tab.onclick = () => invoke("tabs_activate", { id: t.id });
  // Middle-click closes.
  tab.onauxclick = (e) => {
    if (e.button === 1) {
      e.preventDefault();
      invoke("tabs_close", { id: t.id });
    }
  };
  // Drag-to-reorder.
  tab.ondragstart = () => {
    dragId = t.id;
    tab.classList.add("dragging");
  };
  tab.ondragend = () => {
    dragId = null;
    tab.classList.remove("dragging");
  };
  tab.ondragover = (e) => e.preventDefault();
  tab.ondrop = (e) => {
    e.preventDefault();
    if (dragId == null || dragId === t.id) return;
    const target = tabs.findIndex((x) => x.id === t.id);
    if (target >= 0) invoke("tabs_move", { id: dragId, index: target });
  };
  return tab;
}

const INTERNAL_ICON = {
  settings: "settings",
  history: "history",
  bookmarks: "star",
  downloads: "download",
  passwords: "key",
  extensions: "puzzle",
  "private-home": "privacy",
  player: "play",
};

function updateTabEl(tab, t) {
  tab.className =
    "tab" +
    (t.active ? " active" : "") +
    (t.crashed ? " crashed" : "") +
    (t.is_tor ? " tor" : "") +
    (t.is_private ? " private" : "");
  const fav = tab.querySelector(".fav");
  if (t.loading) {
    fav.className = "fav spinner";
    fav.style.backgroundImage = "";
    fav.innerHTML = "";
  } else if (t.internal) {
    fav.className = "fav";
    fav.style.backgroundImage = "";
    fav.innerHTML = iconSvg(INTERNAL_ICON[t.internal] || "page");
  } else if (t.favicon && !t.is_private && !t.is_tor) {
    fav.className = "fav";
    fav.style.backgroundImage = `url("${t.favicon}")`;
    fav.innerHTML = "";
  } else {
    fav.className = "fav";
    fav.style.backgroundImage = "";
    fav.innerHTML = iconSvg(t.is_tor ? "privacy" : t.is_private ? "privacy" : "globe");
  }
  const title = tab.querySelector(".title");
  title.textContent = t.crashed
    ? "Didn't load — " + (t.title || t.url)
    : t.title || t.url || "New Tab";
}

function renderTabs() {
  const box = el("tabs");
  const seen = new Set();
  let prev = null;
  for (const t of tabs) {
    seen.add(t.id);
    let tab = tabEls.get(t.id);
    if (!tab) {
      tab = buildTabEl(t);
      tabEls.set(t.id, tab);
      box.appendChild(tab);
    }
    updateTabEl(tab, t);
    if (prev ? prev.nextSibling !== tab : box.firstChild !== tab) {
      box.insertBefore(tab, prev ? prev.nextSibling : box.firstChild);
    }
    prev = tab;
  }
  for (const [id, elm] of [...tabEls]) {
    if (!seen.has(id)) {
      elm.remove();
      tabEls.delete(id);
    }
  }
  syncToolbar();
  routeActivePage();
}

// ---- Toolbar / omnibox sync ----
let addrFocused = false;

function syncToolbar() {
  const a = activeTab();
  el("back").disabled = !a || !a.can_back;
  el("forward").disabled = !a || !a.can_forward;
  // Reload turns into stop while loading.
  const reload = el("reload");
  reload.dataset.painted = "";
  reload.innerHTML = "";
  reload.dataset.icon = a && a.loading ? "xmark" : "refresh";
  paintIcons(reload);
  reload.title = a && a.loading ? "Stop" : "Reload (⌘R)";

  if (!addrFocused) {
    const input = el("address");
    input.value = editableUrl(a);
  }
  // Security chip.
  const chip = el("sec-chip");
  chip.dataset.painted = "";
  chip.innerHTML = "";
  let icon = "lock",
    cls = "sec-chip";
  if (a && a.internal) {
    icon = "settings";
    cls += " internal";
  } else if (a && a.is_tor) {
    icon = "privacy";
    cls += " tor";
  } else if (a && a.url && a.url.startsWith("https://")) {
    icon = "lock";
    cls += " secure";
  } else if (a && a.url && a.url.startsWith("http://")) {
    icon = "lock-slash";
    cls += " warn";
  }
  chip.className = cls;
  chip.dataset.icon = icon;
  paintIcons(chip);

  // Star reflects bookmark state.
  const starred = a && a.url && bookmarks.some((b) => b.url === a.url);
  const star = el("star");
  star.dataset.painted = "";
  star.innerHTML = "";
  star.dataset.icon = starred ? "star-solid" : "star";
  paintIcons(star);
  star.classList.toggle("on", !!starred);

  // Zoom badge.
  const zb = el("zoom-badge");
  if (a && a.zoom && Math.abs(a.zoom) > 0.01) {
    const pct = Math.round(Math.pow(1.2, a.zoom) * 100);
    zb.textContent = pct + "%";
    zb.classList.remove("hidden");
    zb.onclick = () => invoke("zoom_set", { id: a.id, action: "reset" });
  } else {
    zb.classList.add("hidden");
  }
  el("addr-hint").classList.toggle("hidden", addrFocused);
}

// ---- Internal page routing ----
let currentPageName = null;
let currentPageCtx = null;

function pageCtx() {
  return {
    navigate: (input) => {
      const a = activeTab();
      if (a) invoke("nav_navigate", { id: a.id, input });
    },
    toast: (m) => toast(m),
    setBookmarks: (b) => {
      bookmarks = b;
    },
  };
}

async function routeActivePage() {
  const a = activeTab();
  const page = el("page");
  if (a && a.internal) {
    if (currentPageName !== a.internal + "#" + a.id) {
      currentPageName = a.internal + "#" + a.id;
      page.innerHTML = "";
      const fn = window.VevPages[a.internal];
      currentPageCtx = fn ? await fn(page, pageCtx()) : null;
    }
    page.classList.remove("hidden");
  } else {
    currentPageName = null;
    currentPageCtx = null;
    page.classList.add("hidden");
  }
  syncContent();
}

// vev://<page> opens the matching internal tab.
function handleVevUrl(input) {
  const m = /^vev:\/\/([\w-]+)/.exec((input || "").trim().toLowerCase());
  if (!m) return false;
  const page = m[1];
  if (window.VevPages[page]) {
    invoke("tabs_create_internal", { page });
    return true;
  }
  return false;
}

function navGo(input) {
  input = (input || "").trim();
  if (!input) return;
  if (handleVevUrl(input)) return;
  const a = activeTab();
  if (a) invoke("nav_navigate", { id: a.id, input });
  else invoke("tabs_create", { url: input });
}

function openInternal(page) {
  invoke("tabs_create_internal", { page });
}

// ---- Omnibox: editing + suggestions ----
const address = el("address");
const omnibox = el("omnibox");
const suggest = el("suggest");
let sugItems = [];
let sugSel = -1;

address.addEventListener("focus", () => {
  addrFocused = true;
  omnibox.classList.add("focus");
  el("addr-hint").classList.add("hidden");
  // Pull keyboard focus away from the CEF page view — clicking the omnibox
  // alone left the caret visible but the keystrokes going to the page.
  invoke("shell_focus").catch(() => {});
  requestAnimationFrame(() => address.select());
});
address.addEventListener("blur", () => {
  addrFocused = false;
  omnibox.classList.remove("focus");
  setTimeout(hideSuggest, 120);
  syncToolbar();
});

// The CEF web view is a native layer that paints OVER the shell webview
// below the chrome, so a dropdown extending into the page area would render
// behind it. Hide the content while the suggestions dropdown is showing (as
// Chrome/Arc effectively do) and restore it when it closes.
function suggestContentHidden(hidden) {
  suggestOpen = hidden;
  syncContent();
}
address.addEventListener("input", () => {
  drawSuggest(address.value.trim());
});
address.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") {
    e.preventDefault();
    moveSug(1);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    moveSug(-1);
  } else if (e.key === "Enter") {
    e.preventDefault();
    const pick = sugSel >= 0 ? sugItems[sugSel] : null;
    hideSuggest();
    address.blur();
    navGo(pick ? pick.value : address.value);
  } else if (e.key === "Escape") {
    if (!suggest.classList.contains("hidden")) {
      hideSuggest();
    } else {
      address.value = editableUrl(activeTab());
      address.blur();
    }
  }
});

function hideSuggest() {
  const wasShown = !suggest.classList.contains("hidden");
  suggest.classList.add("hidden");
  sugItems = [];
  sugSel = -1;
  if (wasShown) suggestContentHidden(false);
}
function moveSug(d) {
  if (!sugItems.length) return;
  sugSel = (sugSel + d + sugItems.length) % sugItems.length;
  [...suggest.children].forEach((c, i) => c.classList.toggle("sel", i === sugSel));
}
function looksUrl(q) {
  return /^[a-z]+:\/\//i.test(q) || (!/\s/.test(q) && /\.[a-z]{2,}$/i.test(q.replace(/\/.*$/, "")));
}

function drawSuggest(q) {
  if (!q) return hideSuggest();
  const items = [];
  const isVev = /^vev:\/\//i.test(q);
  // Row 1: go/search what was typed.
  items.push(
    isVev
      ? { icon: "settings", label: q, sub: "Open Vev page", kind: "page", value: q }
      : looksUrl(q)
      ? { icon: "www", label: q, sub: "Open site", kind: "go", value: q }
      : { icon: "search", label: q, sub: "Search", kind: "search", value: q }
  );
  const ql = q.toLowerCase();
  const seen = new Set([q]);
  for (const b of bookmarks) {
    if (items.length >= 8) break;
    if ((b.url + " " + (b.title || "")).toLowerCase().includes(ql) && !seen.has(b.url)) {
      seen.add(b.url);
      items.push({ icon: "star", label: b.title || b.url, sub: b.url, kind: "bookmark", value: b.url });
    }
  }
  renderSuggest(items);
  // Async: history + network search suggestions.
  invoke("history_list", { limit: 300 })
    .then((hist) => {
      for (const hh of hist || []) {
        if (items.length >= 8) break;
        if ((hh.url + " " + (hh.title || "")).toLowerCase().includes(ql) && !seen.has(hh.url)) {
          seen.add(hh.url);
          items.push({ icon: "history", label: hh.title || hh.url, sub: hh.url, kind: "history", value: hh.url });
        }
      }
      if (address.value.trim() === q) renderSuggest(items);
    })
    .catch(() => {});
  if (!isVev && !looksUrl(q)) {
    clearTimeout(suggestTimer);
    suggestTimer = setTimeout(() => {
      invoke("search_suggest", { q })
        .then((sugs) => {
          for (const s of sugs || []) {
            if (items.length >= 9) break;
            if (!seen.has(s)) {
              seen.add(s);
              items.push({ icon: "search", label: s, sub: "Search", kind: "search", value: s });
            }
          }
          if (address.value.trim() === q) renderSuggest(items);
        })
        .catch(() => {});
    }, 140);
  }
}

function renderSuggest(items) {
  const wasHidden = suggest.classList.contains("hidden");
  sugItems = items;
  suggest.innerHTML = "";
  items.forEach((it, i) => {
    const row = document.createElement("div");
    row.className = "sug" + (i === sugSel ? " sel" : "");
    row.innerHTML = `${iconSvg(it.icon)}<span class="s-label">${escapeHtml(
      it.label
    )}</span><span class="s-sub">${escapeHtml(it.sub || "")}</span><span class="s-kind">${escapeHtml(
      it.kind
    )}</span>`;
    row.onmousedown = (e) => {
      e.preventDefault();
      hideSuggest();
      address.blur();
      navGo(it.value);
    };
    suggest.appendChild(row);
  });
  const show = !!items.length;
  suggest.classList.toggle("hidden", !show);
  if (show && wasHidden) suggestContentHidden(true);
  else if (!show && !wasHidden) suggestContentHidden(false);
}

// ---- Toolbar buttons ----
el("newtab").onclick = () => invoke("tabs_create", { url: null });
el("back").onclick = () => {
  const a = activeTab();
  if (a) invoke("nav_back", { id: a.id });
};
el("forward").onclick = () => {
  const a = activeTab();
  if (a) invoke("nav_forward", { id: a.id });
};
el("reload").onclick = () => {
  const a = activeTab();
  if (a) invoke("nav_reload", { id: a.id });
};
el("star").onclick = async () => {
  const a = activeTab();
  if (!a || !a.url || isBlank(a.url)) return;
  if (bookmarks.some((b) => b.url === a.url)) {
    bookmarks = await invoke("bookmarks_remove", { url: a.url }).catch(() => bookmarks);
  } else {
    bookmarks = await invoke("bookmarks_add", { url: a.url, title: a.title || a.url }).catch(() => bookmarks);
  }
  syncToolbar();
};
el("dllist").onclick = () => openInternal("downloads");
el("ext").onclick = () => openInternal("extensions");
el("read").onclick = runRead;
el("menu").onclick = openMenu;

// ---- Huma Read (in the island) ----
function runRead() {
  const a = activeTab();
  if (!a || a.internal) return toast("Open a page first, then summarize it.");
  showReadCard(true);
  invoke("huma_read_active").catch(() => showReadCard(false, "Couldn't read this page."));
}
listen("huma-read-result", (ev) => {
  showReadCard(false, ev.payload);
});

// ---- Overlay engine (palette + menu popover) ----
let overlayOpen = false;
let overlayRefresh = null;

function openOverlay(kind, buildFn) {
  const host = el("overlay");
  const panel = el("overlay-panel");
  panel.className = kind; // "palette" | "popover" | "popover wide"
  panel.innerHTML = "";
  buildFn(panel);
  paintIcons(panel);
  host.classList.remove("hidden");
  overlayOpen = true;
  syncContent();
  requestAnimationFrame(() => host.classList.add("in"));
}
function openPopover(buildFn, extra) {
  openOverlay("popover" + (extra === "wide" ? " palette" : ""), buildFn);
}
function closeOverlay() {
  if (!overlayOpen) return;
  overlayOpen = false;
  overlayRefresh = null;
  const host = el("overlay");
  host.classList.remove("in");
  syncContent();
  setTimeout(() => {
    if (!overlayOpen) host.classList.add("hidden");
  }, 200);
}
el("overlay-backdrop").onclick = closeOverlay;

// ---- Command palette (⌘P) ----
function paletteCommands(q) {
  const a = activeTab();
  const cmds = [
    { icon: "plus", label: "New tab", run: () => invoke("tabs_create", { url: null }) },
    { icon: "privacy", label: "New private window", run: () => invoke("window_new_private") },
    { icon: "open-new-window", label: "New window", run: () => invoke("window_new") },
    { icon: "star", label: "Bookmarks", run: () => openInternal("bookmarks") },
    { icon: "history", label: "History", run: () => openInternal("history") },
    { icon: "download", label: "Downloads", run: () => openInternal("downloads") },
    { icon: "puzzle", label: "Extensions", run: () => openInternal("extensions") },
    { icon: "key", label: "Passwords", run: () => openInternal("passwords") },
    { icon: "sparks", label: "Summarize this page (Huma Read)", run: runRead },
    { icon: "download", label: "Download media on this page", run: () => openMediaDownload() },
    { icon: "shield", label: "Deep scan this page (online verify)", run: () => a && !a.internal && runDeepScan(a.url) },
    { icon: "settings", label: "Settings", run: () => openInternal("settings") },
    {
      icon: "page",
      label: "View page source",
      run: () => a && !a.internal && invoke("nav_navigate", { id: a.id, input: "view-source:" + a.url }),
    },
  ];
  const ql = (q || "").toLowerCase();
  return cmds.filter((c) => !ql || c.label.toLowerCase().includes(ql));
}

function openPalette(initial) {
  openOverlay("palette", (panel) => {
    panel.innerHTML = `<div class="pal-input-row">${iconSvg("search")}
      <input class="pal-input" placeholder="Search or run a command…"></div>
      <div class="pal-list"></div>`;
    const input = panel.querySelector(".pal-input");
    const list = panel.querySelector(".pal-list");
    let sel = 0;
    const draw = () => {
      const q = input.value.trim();
      const items = [];
      if (q) {
        items.push({
          icon: looksUrl(q) ? "www" : "search",
          label: q,
          sub: looksUrl(q) ? "Open site" : "Search the web",
          run: () => navGo(q),
        });
      }
      for (const c of paletteCommands(q)) items.push(c);
      list.innerHTML = "";
      items.forEach((it, i) => {
        const row = document.createElement("div");
        row.className = "menu-item" + (i === sel ? " sel" : "");
        row.innerHTML = `${iconSvg(it.icon)}<span class="grow">${escapeHtml(it.label)}</span>${
          it.sub ? `<span class="k">${escapeHtml(it.sub)}</span>` : ""
        }`;
        row.onclick = () => {
          closeOverlay();
          it.run();
        };
        list.appendChild(row);
      });
      list._items = items;
    };
    input.addEventListener("input", () => {
      sel = 0;
      draw();
    });
    input.addEventListener("keydown", (e) => {
      const items = list._items || [];
      if (e.key === "ArrowDown") {
        sel = Math.min(sel + 1, items.length - 1);
        draw();
        e.preventDefault();
      } else if (e.key === "ArrowUp") {
        sel = Math.max(sel - 1, 0);
        draw();
        e.preventDefault();
      } else if (e.key === "Enter") {
        const it = items[sel];
        if (it) {
          closeOverlay();
          it.run();
        }
      }
    });
    if (initial) input.value = initial;
    draw();
    setTimeout(() => input.focus(), 40);
  });
}

// ---- Menu popover ----
function openMenu() {
  const a = activeTab();
  const items = [
    { icon: "plus", label: "New tab", key: "⌘T", run: () => invoke("tabs_create", { url: null }) },
    { icon: "open-new-window", label: "New window", key: "⌘N", run: () => invoke("window_new") },
    { icon: "privacy", label: "New private window", key: "⌘⇧N", run: () => invoke("window_new_private") },
    { sep: true },
    { icon: "star", label: "Bookmarks", key: "⌘⇧B", run: () => openInternal("bookmarks") },
    { icon: "history", label: "History", key: "⌘⇧Y", run: () => openInternal("history") },
    { icon: "download", label: "Downloads", key: "⌘J", run: () => openInternal("downloads") },
    { icon: "key", label: "Passwords", run: () => openInternal("passwords") },
    { icon: "puzzle", label: "Extensions", run: () => openInternal("extensions") },
    { sep: true },
    { icon: "search", label: "Find in page", key: "⌘F", run: openFind },
    { icon: "download", label: "Download media…", key: "⌘⇧J", run: () => openMediaDownload() },
    { icon: "sparks", label: "Summarize page", run: runRead },
    {
      icon: "page",
      label: "View source",
      key: "⌘⇧U",
      run: () => a && !a.internal && invoke("nav_navigate", { id: a.id, input: "view-source:" + a.url }),
    },
    { icon: "settings", label: "Settings", key: "⌘,", run: () => openInternal("settings") },
  ];
  openOverlay("popover", (panel) => {
    for (const it of items) {
      if (it.sep) {
        panel.appendChild(Object.assign(document.createElement("div"), { className: "menu-sep" }));
        continue;
      }
      const row = document.createElement("div");
      row.className = "menu-item";
      row.innerHTML = `${iconSvg(it.icon)}<span class="grow">${it.label}</span>${
        it.key ? `<span class="k">${it.key}</span>` : ""
      }`;
      row.onclick = () => {
        closeOverlay();
        it.run();
      };
      panel.appendChild(row);
    }
  });
}

// ---- Find in page (⌘F) ----
let findOpen = false;
const findInput = el("find-input");
function openFind() {
  const a = activeTab();
  if (!a || a.internal) return;
  findOpen = true;
  el("findbar").classList.remove("hidden");
  findInput.value = "";
  el("find-count").textContent = "";
  setTimeout(() => findInput.focus(), 20);
}
function closeFind() {
  if (!findOpen) return;
  findOpen = false;
  el("findbar").classList.add("hidden");
  const a = activeTab();
  if (a) invoke("find_stop", { id: a.id }).catch(() => {});
}
function runFind(forward, next) {
  const a = activeTab();
  const text = findInput.value;
  if (!a || !text) {
    el("find-count").textContent = "";
    return;
  }
  invoke("find_start", { id: a.id, text, forward, matchCase: false, findNext: next }).catch(() => {});
}
findInput.addEventListener("input", () => runFind(true, false));
findInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    runFind(!e.shiftKey, true);
  } else if (e.key === "Escape") {
    closeFind();
  }
});
el("find-next").onclick = () => runFind(true, true);
el("find-prev").onclick = () => runFind(false, true);
el("find-close").onclick = closeFind;
listen("find-result", (ev) => {
  const c = el("find-count");
  const v = ev.payload;
  if (c && v && v.total >= 0) c.textContent = v.total ? `${v.current}/${v.total}` : "0";
});


// ---- Huma island (Dynamic-Island nudge) ----
// One morphing top-center component. States: hidden | compact | expanded.
const island = el("island");
const islandCompact = el("island-compact");
const islandExpanded = el("island-expanded");
let islandTimer = null;
// Per-page blocked hosts for the active tab, keyed host -> kind.
let blockedForPage = new Map();
let blockedPageUrl = null;
let pendingWarn = null; // active phishing warning payload

function islandState(s) {
  island.dataset.state = s;
  syncContent();
}

// Single source of truth for whether the CEF page view must be hidden so
// shell UI (which the native CEF view otherwise paints over below the chrome)
// stays visible. Everything that shows over the page routes through here so
// nothing fights over content_hidden (the bug where the island's lower half —
// its action buttons — got re-covered by a mid-load tabs-changed event).
let suggestOpen = false;
function contentShouldHide() {
  const a = activeTab();
  return (
    overlayOpen ||
    suggestOpen ||
    (a && !!a.internal) ||
    island.dataset.state === "expanded"
  );
}
let lastContentHidden = null;
function syncContent() {
  const hide = contentShouldHide();
  if (hide === lastContentHidden) return;
  lastContentHidden = hide;
  invoke("content_hidden", { hidden: hide }).catch(() => {});
}
function collapseIsland() {
  // Return to compact if there are blocks to report, else hide.
  pendingWarn = null;
  island.classList.remove("warn");
  if (blockedForPage.size) {
    renderIslandCompact();
    islandState("compact");
  } else {
    islandState("hidden");
  }
}
function autoHideSoon() {
  clearTimeout(islandTimer);
  islandTimer = setTimeout(collapseIsland, 6000);
}

function renderIslandCompact() {
  const n = blockedForPage.size;
  islandCompact.innerHTML = `${iconSvg("shield")}<span>Shielded</span><span class="count">${n}</span>`;
}
islandCompact.onclick = () => showBlockedCard();

// Click anywhere outside the expanded island collapses it. Uses the CEF
// keyboard bridge too (a click on the web page can't reach this listener, so
// also collapse on any focus leaving the shell / navigation).
document.addEventListener("mousedown", (e) => {
  if (island.dataset.state === "expanded" && !island.contains(e.target)) {
    collapseIsland();
  }
});

// Brief confirmation (settings saved, etc.) shown in the island.
function toast(text, opts) {
  opts = opts || {};
  if (opts.warn) return; // warnings route through the guard flow
  clearTimeout(islandTimer);
  island.classList.remove("warn");
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("check-circle")}
    <div class="h-t">${escapeHtml(text)}</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>`;
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandState("expanded");
  islandTimer = setTimeout(collapseIsland, opts.sticky ? 12000 : 3200);
}

// Expanded: list of blocked trackers on this page, each with Allow.
function showBlockedCard() {
  clearTimeout(islandTimer);
  island.classList.remove("warn");
  const rows = [...blockedForPage.entries()]
    .map(
      ([host, kind]) =>
        `<div class="isl-row"><span class="r-host">${escapeHtml(host)}</span>
         <span class="r-kind">${escapeHtml(kind)}</span>
         <button class="r-allow" data-host="${escapeHtml(host)}">Allow</button></div>`
    )
    .join("");
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("shield")}
    <div class="h-t">${blockedForPage.size} tracker${blockedForPage.size === 1 ? "" : "s"} blocked here</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-list">${rows || `<div class="isl-msg">Nothing blocked on this page.</div>`}</div>
    <div class="isl-actions"><span class="spacer"></span>
      <button class="read-from-island accent">${iconSvg("sparks")}Summarize page</button></div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandExpanded.querySelectorAll(".r-allow").forEach((b) => {
    b.onclick = async () => {
      const host = b.dataset.host;
      await invoke("blocklist_add_allow", { host }).catch(() => {});
      blockedForPage.delete(host);
      const a = activeTab();
      if (a) invoke("nav_reload", { id: a.id });
      toast("Allowed " + host + " — reloading.");
    };
  });
  islandExpanded.querySelector(".read-from-island").onclick = () => {
    collapseIsland();
    runRead();
  };
  islandState("expanded");
}

// Phishing / tracking warning: amber, allow-or-leave.
function showWarnCard(v) {
  pendingWarn = v;
  clearTimeout(islandTimer);
  island.classList.add("warn");
  const reasons = (v.reasons || []).slice(0, 3).map((r) => "• " + r).join("<br>");
  const community =
    v.community && v.community.reports
      ? `<br><b>Community-confirmed phishing: ${v.community.percent}%</b> (${v.community.reports} reports)`
      : "";
  const lead =
    v.source === "content"
      ? `This page is impersonating <b>${escapeHtml(v.impersonated || "a brand")}</b>.`
      : `Huma Guard scored it <b>${Math.round((v.score || 0) * 100)}%</b> likely phishing.`;
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("warning-triangle")}
    <div class="h-t">This link looks unsafe</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-msg">${lead}<br>${reasons}${community}</div>
    <div class="isl-actions">
      <button class="leave warn-btn">${iconSvg("arrow-left")}Go back</button>
      <button class="deepscan">${iconSvg("shield")}Deep scan</button>
      <button class="report">${iconSvg("magnet")}Report</button>
      <span class="spacer"></span>
      <button class="allow">Allow anyway</button></div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  const ds = islandExpanded.querySelector(".deepscan");
  if (ds) ds.onclick = () => runDeepScan(v.url);
  islandExpanded.querySelector(".leave").onclick = () => {
    const a = activeTab();
    if (a && a.can_back) invoke("nav_back", { id: a.id });
    collapseIsland();
  };
  islandExpanded.querySelector(".allow").onclick = () => {
    // "Allow anyway" is a false-positive signal — teach the on-device Guard
    // so this site's structure scores lower next time (SEAL-style adaptation).
    if (v && v.url) invoke("huma_guard_feedback", { url: v.url, malicious: false }).catch(() => {});
    collapseIsland();
  };
  const reportBtn = islandExpanded.querySelector(".report");
  if (reportBtn) {
    reportBtn.onclick = () => {
      if (v && v.url)
        invoke("report_phishing", { url: v.url })
          .then((msg) => toast(msg))
          .catch(() => {});
      collapseIsland();
    };
  }
  islandState("expanded");
}

// Deep scan: verify the URL against the online threat-intel sources and show
// a combined danger percentage with each source's verdict.
function runDeepScan(url) {
  if (!url) return;
  clearTimeout(islandTimer);
  island.classList.add("warn");
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("shield")}
    <div class="h-t">Deep scanning…</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-read loading">Checking this link against Google Safe Browsing, VirusTotal, URLhaus, ThreatFox and OTX…</div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandState("expanded");
  invoke("huma_deep_scan", { url })
    .then(showDeepScanCard)
    .catch((e) => {
      const b = islandExpanded.querySelector(".isl-read");
      if (b) {
        b.className = "isl-read";
        b.textContent = "Couldn't reach the scan services: " + e;
      }
    });
}
function showDeepScanCard(rep) {
  const danger = rep.malicious || rep.percent >= 60;
  island.classList.toggle("warn", danger);
  const rows = (rep.signals || [])
    .map((s) => {
      const badge =
        s.verdict === "malicious" ? "danger" : s.verdict === "clean" ? "ok" : "unk";
      const label = s.verdict === "unknown" ? "no data" : s.verdict;
      return `<div class="isl-row"><span class="r-host">${escapeHtml(s.source)}</span>
        <span class="r-kind ds-${badge}">${escapeHtml(label)}</span></div>`;
    })
    .join("");
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg(danger ? "warning-triangle" : "shield")}
    <div class="h-t">${danger ? "Likely dangerous" : "Looks clean"} — ${rep.percent}%</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-msg">Combined danger score across ${(rep.signals || []).length} sources for <b>${escapeHtml(hostOfUrl(rep.url))}</b>.${rep.tor ? " Routed through a private proxy (Tor or your custom proxy) — your IP wasn't exposed." : ""}</div>
    <div class="isl-list">${rows}</div>
    <div class="isl-actions">
      <button class="leave">${iconSvg("arrow-left")}Go back</button>
      <span class="spacer"></span>
      <button class="allow">Open anyway</button></div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandExpanded.querySelector(".leave").onclick = () => {
    const a = activeTab();
    if (a && a.can_back) invoke("nav_back", { id: a.id });
    collapseIsland();
  };
  islandExpanded.querySelector(".allow").onclick = collapseIsland;
  islandState("expanded");
}
function hostOfUrl(u) {
  try {
    return new URL(u).host;
  } catch (e) {
    return u;
  }
}

// ---- Huma pre-open sandbox (gate) ----
// The backend held a navigation back and is rendering it in a hidden
// Tor-routed browser. Compact "checking" state while it runs; the verdict
// either navigates (clean) or shows a blocking allow/deny card.
function showSandboxChecking(v) {
  clearTimeout(islandTimer);
  island.classList.remove("warn");
  islandCompact.innerHTML = `${iconSvg("shield")}<span>Checking ${escapeHtml(hostOfUrl(v.url))} in sandbox…</span>`;
  islandState("compact");
}
function showSandboxVerdict(v) {
  if (v.clean) {
    toast(`Sandbox-checked ${hostOfUrl(v.url)} — clean, opening.`);
    return;
  }
  clearTimeout(islandTimer);
  island.classList.add("warn");
  const rows = (v.signals || [])
    .map((s) => {
      const badge =
        s.verdict === "malicious" ? "danger" : s.verdict === "clean" ? "ok" : "unk";
      const label = s.verdict === "unknown" ? "no data" : s.verdict;
      return `<div class="isl-row"><span class="r-host">${escapeHtml(s.source)}</span>
        <span class="r-kind ds-${badge}">${escapeHtml(label)}</span></div>`;
    })
    .join("");
  const reasons = (v.reasons || []).slice(0, 3).map((r) => "• " + escapeHtml(r)).join("<br>");
  const lead = v.impersonated
    ? `The sandboxed render is impersonating <b>${escapeHtml(v.impersonated)}</b>.`
    : `Combined danger score <b>${v.percent}%</b>.`;
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("warning-triangle")}
    <div class="h-t">Blocked before opening — ${v.percent}%</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-msg">Vev opened <b>${escapeHtml(hostOfUrl(v.url))}</b> in an isolated
    proxy-routed sandbox first (Tor, or your custom proxy) — your tab never touched it. ${lead}${reasons ? "<br>" + reasons : ""}</div>
    <div class="isl-list">${rows}</div>
    <div class="isl-actions">
      <button class="leave warn-btn">${iconSvg("check-circle")}Keep it blocked</button>
      <button class="report">${iconSvg("magnet")}Report</button>
      <span class="spacer"></span>
      <button class="allow">Open anyway</button></div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandExpanded.querySelector(".leave").onclick = collapseIsland;
  islandExpanded.querySelector(".allow").onclick = () => {
    invoke("sandbox_proceed", { id: v.tabId, url: v.url }).catch(() => {});
    collapseIsland();
  };
  const reportBtn = islandExpanded.querySelector(".report");
  if (reportBtn) {
    reportBtn.onclick = () => {
      invoke("report_phishing", { url: v.url })
        .then((msg) => toast(msg))
        .catch(() => {});
      collapseIsland();
    };
  }
  islandState("expanded");
}

// Huma Read summary in the island.
function showReadCard(loading, text) {
  clearTimeout(islandTimer);
  island.classList.remove("warn");
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("sparks")}
    <div class="h-t">Huma Read</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-read${loading ? " loading" : ""}">${
    loading ? "Reading this page on-device…" : escapeHtml(text)
  }</div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandState("expanded");
}

// Reset the per-page block list when the active tab navigates.
function resetBlocksIfNavigated() {
  const a = activeTab();
  const url = a ? a.url : null;
  if (url !== blockedPageUrl) {
    blockedPageUrl = url;
    blockedForPage = new Map();
    if (!pendingWarn) {
      if (island.dataset.state !== "expanded") islandState("hidden");
    }
  }
}

// ---- Keyboard shortcuts ----
function runShortcut(action) {
  const a = activeTab();
  switch (action) {
    case "new-tab": return invoke("tabs_create", { url: null });
    case "new-window": return invoke("window_new");
    case "new-private-window": return invoke("window_new_private");
    case "history": return openInternal("history");
    case "bookmarks": return openInternal("bookmarks");
    case "downloads": return openInternal("downloads");
    case "download-media": return openMediaDownload();
    case "settings": return openInternal("settings");
    case "view-source":
      return a && !a.internal && invoke("nav_navigate", { id: a.id, input: "view-source:" + a.url });
    case "reopen-tab": return invoke("tabs_restore");
    case "close-tab": return a && invoke("tabs_close", { id: a.id });
    case "focus-address":
      address.focus();
      invoke("shell_focus").catch(() => {});
      return;
    case "command-palette": return openPalette("");
    case "find": return openFind();
    case "reload": return a && invoke("nav_reload", { id: a.id });
    case "back": return a && a.can_back && invoke("nav_back", { id: a.id });
    case "forward": return a && a.can_forward && invoke("nav_forward", { id: a.id });
    case "bookmark": return el("star").onclick();
    case "read": return runRead();
    case "zoom-in": return a && invoke("zoom_set", { id: a.id, action: "in" });
    case "zoom-out": return a && invoke("zoom_set", { id: a.id, action: "out" });
    case "zoom-reset": return a && invoke("zoom_set", { id: a.id, action: "reset" });
    case "next-tab": return cycleTab(1);
    case "prev-tab": return cycleTab(-1);
    case "close-overlay":
      if (findOpen) return closeFind();
      if (overlayOpen) return closeOverlay();
      if (island.dataset.state === "expanded") return collapseIsland();
      return;
    default:
      if (action.startsWith("tab-")) {
        const n = parseInt(action.slice(4), 10);
        const t = n === 9 ? tabs[tabs.length - 1] : tabs[n - 1];
        if (t) invoke("tabs_activate", { id: t.id });
      }
  }
}
function cycleTab(dir) {
  if (!tabs.length) return;
  let i = tabs.findIndex((t) => t.active);
  i = (i + dir + tabs.length) % tabs.length;
  invoke("tabs_activate", { id: tabs[i].id });
}

function shortcutFor(e) {
  const mod = e.metaKey || e.ctrlKey;
  const k = e.key.toLowerCase();
  if (e.key === "Escape") return "close-overlay";
  if (!mod) return null;
  if (k >= "1" && k <= "9") return "tab-" + k;
  if (e.shiftKey) {
    if (k === "t") return "reopen-tab";
    if (k === "n") return "new-private-window";
    if (k === "]" || k === "arrowright") return "next-tab";
    if (k === "[" || k === "arrowleft") return "prev-tab";
    if (k === "b") return "bookmarks";
    if (k === "y") return "history";
    if (k === "u") return "view-source";
    if (k === "j") return "download-media";
  }
  switch (k) {
    case "t": return "new-tab";
    case "n": return "new-window";
    case "w": return "close-tab";
    case "l":
    case "k": return "focus-address";
    case "r": return "reload";
    case "d": return "bookmark";
    case "f": return "find";
    case "j": return "downloads";
    case "p": return "command-palette";
    case "=":
    case "+": return "zoom-in";
    case "-": return "zoom-out";
    case "0": return "zoom-reset";
    case ",": return "settings";
    case "[":
    case "arrowleft": return "back";
    case "]":
    case "arrowright": return "forward";
  }
  return null;
}
document.addEventListener("keydown", (e) => {
  // Don't hijack typing in the omnibox/find/page inputs except for Escape.
  const typing =
    e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.isContentEditable;
  const action = shortcutFor(e);
  if (!action) return;
  if (typing && action !== "close-overlay" && !action.startsWith("tab-")) {
    // Allow ⌘L etc. even while typing elsewhere, but let plain typing pass.
    if (!(e.metaKey || e.ctrlKey)) return;
  }
  e.preventDefault();
  runShortcut(action);
});
// Shortcuts forwarded from the CEF page (keyboard handler in cef_engine).
listen("shortcut", (ev) => runShortcut(ev.payload));

// ---- Events ----
listen("tabs-changed", (ev) => {
  tabs = ev.payload;
  renderTabs();
  resetBlocksIfNavigated();
});

// Blocked tracker/ad → feed the island. Deduped per host; the compact pill
// updates live while a page loads.
let islandRaf = null;
listen("resource-blocked", (ev) => {
  const v = ev.payload;
  if (!v || !v.host) return;
  blockedForPage.set(v.host, v.kind || "tracker");
  // Don't steal an open warn/read card; only drive the compact pill.
  if (island.dataset.state === "expanded") return;
  if (islandRaf) return;
  islandRaf = requestAnimationFrame(() => {
    islandRaf = null;
    renderIslandCompact();
    if (!pendingWarn) islandState("compact");
  });
});
let dlCount = 0;
listen("download-updated", (ev) => {
  const d = ev.payload;
  if (d && (d.state === "in_progress" || d.state === "paused")) dlCount = Math.max(1, dlCount);
  const badge = el("dl-badge");
  const active = tabs.length; // cheap; refreshed on open
  void active;
  if (currentPageCtx && currentPageCtx.refresh) currentPageCtx.refresh();
  // Show a small badge while something is downloading.
  if (d && d.state === "in_progress") {
    badge.textContent = "";
    badge.classList.remove("hidden");
  } else if (d && (d.state === "complete" || d.state === "cancelled")) {
    badge.classList.add("hidden");
  }
});
listen("huma-guard-warning", (ev) => {
  const v = ev.payload || {};
  if (lastCommunityFlag && lastCommunityFlag.url === v.url) v.community = lastCommunityFlag;
  showWarnCard(v);
});
// Community-confirmed phishing percentage for the current navigation.
let lastCommunityFlag = null;
listen("community-flag", (ev) => {
  const v = ev.payload || {};
  lastCommunityFlag = v;
  // If a warning is already showing for this URL, fold in the percentage.
  if (pendingWarn && pendingWarn.url === v.url) {
    pendingWarn.community = v;
    showWarnCard(pendingWarn);
  } else {
    // Otherwise surface it on its own (community says it's phishing even if
    // the local model didn't flag it).
    showWarnCard({
      url: v.url,
      score: v.percent / 100,
      reasons: ["flagged by the Vev community"],
      community: v,
      source: "community",
    });
  }
});
listen("tab-crashed", () => {
  toast("That page's process stopped. Reload to try again.");
});
// Script-spawned pop-under / ad popups are blocked in the backend. Let the
// user know, but throttle so an ad-heavy page can't spam the island.
let lastPopupToast = 0;
listen("popup-blocked", () => {
  const now = Date.now();
  if (now - lastPopupToast < 4000) return;
  lastPopupToast = now;
  toast("Blocked a pop-up.");
});

// A .torrent file or magnet link was handed to the torrent engine instead of
// being saved as a file — jump to the Downloads page so the user sees it grow.
listen("torrent-added", (ev) => {
  const v = ev.payload || {};
  toast("Added to torrents — downloading now.");
  openInternal("downloads");
  const a = activeTab();
  if (a && a.internal === "downloads" && currentPageCtx && currentPageCtx.refresh) {
    currentPageCtx.refresh();
  }
  void v;
});
// Pre-open sandbox gate: checking state, then verdict (clean → backend
// navigates and this toasts; dangerous → blocking allow/deny card).
listen("sandbox-checking", (ev) => showSandboxChecking(ev.payload || {}));
listen("sandbox-verdict", (ev) => showSandboxVerdict(ev.payload || {}));

// ---- Downloads: started notification + media (yt-dlp) popup ----
// A CEF download began saving. Never silent: show it in the island with a
// jump to the Downloads page.
listen("download-started", (ev) => {
  const d = ev.payload || {};
  clearTimeout(islandTimer);
  island.classList.remove("warn");
  islandExpanded.innerHTML = `<div class="isl-head">${iconSvg("download")}
    <div class="h-t">Downloading</div>
    <button class="h-close">${iconSvg("xmark")}</button></div>
    <div class="isl-msg">${escapeHtml(d.name || "file")} → ${escapeHtml(d.dir || "Downloads")}</div>
    <div class="isl-actions"><span class="spacer"></span>
      <button class="accent isl-show-dl">${iconSvg("download")}Show in Downloads</button></div>`;
  paintIcons(islandExpanded);
  islandExpanded.querySelector(".h-close").onclick = collapseIsland;
  islandExpanded.querySelector(".isl-show-dl").onclick = () => {
    collapseIsland();
    openInternal("downloads");
  };
  islandState("expanded");
  islandTimer = setTimeout(collapseIsland, 6000);
});

// The media download confirmation popup: probe the page with yt-dlp, let the
// user pick a format / mp3 / play online, then download (into the IDM list)
// or stream. `url` defaults to the active tab.
async function openMediaDownload(url) {
  const a = activeTab();
  url = url || (a && !a.internal ? a.url : "");
  if (!url) return toast("Open a page first, then download its media.");
  openOverlay("palette", (panel) => {
    panel.classList.add("dl-pop");
    panel.innerHTML = `<div class="dl-head">${iconSvg("download")}<div class="dl-title">Download media</div>
      <button class="dl-x">${iconSvg("xmark")}</button></div>
      <div class="dl-body"><div class="dl-loading">Checking this page for media…</div></div>`;
    panel.querySelector(".dl-x").onclick = closeOverlay;
    const body = panel.querySelector(".dl-body");
    loadMediaInto(body, url);
  });
}

async function loadMediaInto(body, url) {
  // Tools first — offer the one-time fetch if yt-dlp isn't available.
  const tools = await invoke("media_tools_status").catch(() => ({ ytdlp: false, ffmpeg: false }));
  if (!tools.ytdlp) {
    body.innerHTML = `<div class="dl-msg">Vev needs the media tools (yt-dlp) to grab video/audio from sites
      like YouTube. It's a one-time download into Vev's data folder — nothing bundled or installed system-wide.</div>
      <div class="dl-actions"><span class="spacer"></span>
        <button class="btn accent dl-get">${iconSvg("download")}Get media tools</button></div>`;
    paintIcons(body);
    body.querySelector(".dl-get").onclick = async () => {
      body.innerHTML = `<div class="dl-loading">Downloading media tools…</div>`;
      try {
        await invoke("media_fetch_tools");
        loadMediaInto(body, url);
      } catch (e) {
        body.innerHTML = `<div class="dl-msg">Couldn't fetch the tools: ${escapeHtml(String(e))}</div>`;
      }
    };
    return;
  }
  let info;
  try {
    info = await invoke("media_probe", { url });
  } catch (e) {
    // Not an extractor-supported page: offer a direct download of the URL.
    body.innerHTML = `<div class="dl-msg">No embedded video/audio Vev can extract here
      (${escapeHtml(String(e).slice(0, 80))}). You can still download the address directly.</div>
      <div class="dl-actions"><span class="spacer"></span>
        <button class="btn dl-direct">${iconSvg("download")}Download this URL</button></div>`;
    paintIcons(body);
    body.querySelector(".dl-direct").onclick = () => {
      invoke("download_fast", { url, destDir: null });
      toast("Download started.");
      closeOverlay();
    };
    return;
  }
  renderMediaChoices(body, url, info, tools);
}

function renderMediaChoices(body, url, info, tools) {
  // Build the format menu: video qualities (dedup by label), then audio.
  const vids = (info.formats || []).filter((f) => f.kind !== "audio");
  const seen = new Set();
  const vOpts = [];
  vOpts.push({ v: "best", label: "Best quality (auto)" });
  for (const f of vids) {
    if (seen.has(f.label)) continue;
    seen.add(f.label);
    const size = f.filesize ? ` · ${(f.filesize / 1048576).toFixed(0)} MB` : "";
    vOpts.push({ v: f.id, label: `${f.label}${f.progressive ? "" : " (merged)"}${size}` });
  }
  const mp3ok = tools.ffmpeg;
  const dur = info.duration_secs
    ? ` · ${Math.floor(info.duration_secs / 60)}:${String(info.duration_secs % 60).padStart(2, "0")}`
    : "";
  const thumb = info.thumbnail
    ? `<img class="dl-thumb" src="${escapeHtml(info.thumbnail)}" alt="">`
    : `<div class="dl-thumb ph">${iconSvg("play")}</div>`;
  body.innerHTML = `
    <div class="dl-item">${thumb}<div class="dl-meta">
      <div class="dl-name">${escapeHtml(info.title)}</div>
      <div class="dl-sub">${escapeHtml(hostOfUrl(url))}${dur}</div></div></div>
    <div class="dl-row"><label>Format</label>
      <select class="field dl-fmt">
        <optgroup label="Video">${vOpts.map((o) => `<option value="v:${escapeHtml(o.v)}">${escapeHtml(o.label)}</option>`).join("")}</optgroup>
        <optgroup label="Audio">
          <option value="a:mp3"${mp3ok ? "" : " disabled"}>MP3 (extract audio)${mp3ok ? "" : " — needs ffmpeg"}</option>
        </optgroup>
      </select></div>
    <div class="dl-actions">
      <button class="btn dl-play">${iconSvg("play")}Play online</button>
      <span class="spacer"></span>
      <button class="btn accent dl-go">${iconSvg("download")}Download</button></div>`;
  paintIcons(body);
  body.querySelector(".dl-go").onclick = () => {
    const sel = body.querySelector(".dl-fmt").value;
    const audioMp3 = sel === "a:mp3";
    const formatId = audioMp3 ? "" : sel.slice(2) === "best" ? "" : sel.slice(2);
    invoke("media_download", { url, formatId, audioMp3, destDir: null });
    toast("Download started — see the Downloads page.");
    closeOverlay();
  };
  body.querySelector(".dl-play").onclick = async () => {
    body.querySelector(".dl-play").textContent = "Resolving…";
    try {
      const streamUrl = await invoke("media_resolve_stream", { url });
      // Play in the shell-rendered player (never touches the nav gate, so a
      // googlevideo/CDN URL isn't flagged as "impersonating Google").
      window.__vevPlayerUrl = streamUrl;
      window.__vevPlayerTitle = info.title;
      window.__vevPlayerSource = url;
      openInternal("player");
      closeOverlay();
    } catch (e) {
      toast("Couldn't resolve a playable stream: " + e);
    }
  };
}

// Live-refresh an open downloads page.
setInterval(() => {
  const a = activeTab();
  if (a && a.internal === "downloads" && currentPageCtx && currentPageCtx.refresh) {
    currentPageCtx.refresh();
  }
}, 1200);

// ---- Boot ----
paintIcons();
(async () => {
  bookmarks = await invoke("bookmarks_list").catch(() => []);
  tabs = await invoke("tabs_list").catch(() => []);
  renderTabs();
})();
