// Observatory: polls /api/observatory.json and renders with DOM APIs only
// (every string from the server is untrusted and goes through textContent).
"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const SVGNS = "http://www.w3.org/2000/svg";
  const CLS = { ai: "AI crawlers and agents", auto: "other bots, scripts, unknown", browser: "browsers" };
  const ORDER = ["ai", "auto", "browser"]; // baseline first
  const KIND_CLASS = { ai: "ai", search: "auto", bot: "auto", tool: "auto", unknown: "auto", browser: "browser" };
  const state = { w: "24h", ua: null, data: null, lastOk: 0, seen: new Set(), first: true };

  try {
    const s = new URLSearchParams(location.search);
    if (["1h", "24h", "7d"].includes(s.get("window"))) state.w = s.get("window");
    if (/^\d+$/.test(s.get("ua") || "")) state.ua = s.get("ua");
  } catch (e) { /* ignore */ }

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
    return el;
  }
  function s(tag, attrs) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
    return el;
  }
  const fmt = (n) => n == null ? "0" : n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M" : n >= 1e4 ? (n / 1e3).toFixed(0) + "k" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n);
  const bytes = (n) => !n ? "0 B" : n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(0) + " kB" : n + " B";
  const ago = (t, now) => { const d = Math.max(0, now - t); return d < 60 ? d + "s" : d < 3600 ? Math.floor(d / 60) + "m" : d < 86400 ? Math.floor(d / 3600) + "h" : Math.floor(d / 86400) + "d"; };
  const clock = (t, withDate) => {
    const d = new Date(t * 1000);
    const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
    return withDate ? d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm : hm;
  };
  const sw = (kind) => h("i", { class: "sw s-" + (KIND_CLASS[kind] || "auto"), "aria-hidden": "true" });

  // ---------------------------------------------------------------- fetch
  async function load() {
    const q = new URLSearchParams({ window: state.w });
    if (state.ua) q.set("ua", state.ua);
    try {
      const r = await fetch("/api/observatory.json?" + q, { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      state.data = await r.json();
      state.lastOk = Date.now();
      render();
    } catch (e) {
      $("upd").textContent = "connection lost, retrying";
      $("upd").classList.add("stale");
    }
  }
  function tick() {
    if (!state.lastOk) return;
    const d = Math.round((Date.now() - state.lastOk) / 1000);
    $("upd").classList.toggle("stale", d > 30);
    $("upd").textContent = d > 30 ? `no update for ${d} s, retrying` : `updated ${d} s ago · every 5 s`;
  }
  function syncUrl() {
    const q = new URLSearchParams();
    if (state.w !== "24h") q.set("window", state.w);
    if (state.ua) q.set("ua", state.ua);
    history.replaceState(null, "", location.pathname + (q.toString() ? "?" + q : ""));
  }

  // --------------------------------------------------------------- render
  function render() {
    const d = state.data;
    $("notice").textContent = d.notice;
    $("site").textContent = d.site;
    $("ippolicy").textContent = d.ip_policy;
    for (const b of document.querySelectorAll(".seg button")) b.setAttribute("aria-pressed", String(b.dataset.w === state.w));
    renderFocus(d);
    renderStats(d);
    renderChart(d);
    renderVisitors(d);
    renderTail(d);
    renderNetworks(d);
    renderPaths(d);
    renderQueries(d);
    renderWrites(d);
    renderInvites(d);
    renderHouses(d);
    tick();
    state.first = false;
  }

  function renderFocus(d) {
    const f = d.focus;
    $("focus").hidden = !f;
    if (f) { $("focus-label").textContent = f.label; $("focus-ua").textContent = f.ua.slice(0, 160); }
  }

  function renderStats(d) {
    const t = d.totals, win = { "1h": "last hour", "24h": "last 24 h", "7d": "last 7 days" }[d.window];
    const share = t.requests ? Math.round(100 * t.ai_requests / t.requests) : 0;
    const items = [
      ["", fmt(t.requests), "requests, " + win],
      ["ai", fmt(t.ai_requests), `from AI crawlers and agents (${share}%)`],
      ["", fmt(t.user_agents), "distinct user agents"],
      ["", fmt(t.ips), "IP addresses"],
      ["", fmt(t.networks), "networks (ASNs)"],
      ["", fmt(t.writes), "posts, wiki edits and keys written"],
    ];
    $("stats").replaceChildren(...items.map(([c, v, l]) => h("div", { class: "stat " + c }, h("b", {}, v), h("span", {}, l))));
  }

  function renderChart(d) {
    const svg = $("svg"), box = $("chart");
    const W = box.clientWidth, H = box.clientHeight, padL = 40, padB = 22, padT = 26;
    const ser = d.series, n = ser.length;
    $("trace-title").textContent = "Requests per " + ({ 60: "minute", 600: "10 minutes", 3600: "hour" }[d.bucket_s] || d.bucket_s + " s");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.replaceChildren();
    const totals = ser.map((b) => b.ai + b.auto + b.browser);
    const max = Math.max(4, ...totals);
    const step = niceStep(max / 3);
    const top = Math.ceil(max / step) * step;
    const y = (v) => H - padB - (v / top) * (H - padB - padT);
    for (let v = 0; v <= top; v += step) {
      svg.append(s("line", { class: v ? "grid" : "base", x1: padL, x2: W, y1: y(v), y2: y(v) }));
      const t = s("text", { x: padL - 8, y: y(v) + 4, "text-anchor": "end" }); t.textContent = fmt(v); svg.append(t);
    }
    const bw = (W - padL) / n, gap = bw > 6 ? 2 : bw > 3 ? 1 : 0;
    const hl = s("rect", { class: "hl", x: 0, y: padT, width: bw, height: H - padB - padT, visibility: "hidden" });
    svg.append(hl);
    ser.forEach((b, i) => {
      let acc = 0;
      const x = padL + i * bw;
      ORDER.forEach((k) => {
        const v = b[k];
        if (!v) return;
        const y0 = y(acc), y1 = y(acc + v);
        acc += v;
        svg.append(s("rect", { class: "s-" + k, x: x + gap / 2, y: y1 + (acc - v ? 1 : 0), width: Math.max(1, bw - gap), height: Math.max(1, y0 - y1 - (acc - v ? 1 : 0)) }));
      });
    });
    // x labels: ~6 ticks
    const every = Math.max(1, Math.round(n / 6));
    const labW = d.window === "7d" ? 84 : 44;
    for (let i = 0; i < n; i += every) {
      const x = padL + i * bw;
      if (x + labW > W) break;
      const t = s("text", { x, y: H - 6 }); t.textContent = clock(ser[i].t, d.window === "7d"); svg.append(t);
    }
    // peak annotation (the one label that matters)
    const pi = totals.indexOf(Math.max(...totals));
    if (totals[pi] > 0) {
      const px = padL + pi * bw + bw / 2, g = s("g", { class: "peak" });
      g.append(s("line", { x1: px, x2: px, y1: y(totals[pi]) - 4, y2: padT - 8 }));
      const anchor = px > W - 160 ? "end" : px < padL + 120 ? "start" : "middle";
      const t = s("text", { x: px, y: padT - 12, "text-anchor": anchor });
      const b = ser[pi], dom = ORDER.reduce((a, k) => (b[k] > b[a] ? k : a), "ai");
      t.textContent = W < 640 ? `peak ${fmt(totals[pi])} at ${clock(b.t, d.window === "7d")}`
        : `peak ${fmt(totals[pi])} at ${clock(b.t, d.window === "7d")}, mostly ${CLS[dom].split(",")[0]}`;
      g.append(t); svg.append(g);
    }
    // hover layer: one hit target per bucket, wider than the bar
    const tip = $("tip");
    svg.onpointermove = (ev) => {
      const r = svg.getBoundingClientRect(), mx = ev.clientX - r.left;
      const i = Math.floor((mx - padL) / bw);
      if (i < 0 || i >= n) { tip.hidden = true; hl.setAttribute("visibility", "hidden"); return; }
      const b = ser[i];
      hl.setAttribute("x", padL + i * bw); hl.setAttribute("width", bw); hl.setAttribute("visibility", "visible");
      tip.replaceChildren(h("b", {}, clock(b.t, true) + " · " + fmt(totals[i]) + " requests"),
        ...ORDER.map((k) => h("div", {}, h("span", {}, h("i", { class: "s-" + k }), CLS[k]), h("span", {}, fmt(b[k])))));
      tip.hidden = false;
      const tx = Math.min(Math.max(0, mx + 14), r.width - tip.offsetWidth - 4);
      tip.style.left = tx + "px"; tip.style.top = "0px";
    };
    svg.onpointerleave = () => { tip.hidden = true; hl.setAttribute("visibility", "hidden"); };
    // table view
    const rows = ser.filter((b, i) => totals[i] > 0).slice(-48).reverse();
    $("trace-table").replaceChildren(h("table", { class: "data" },
      h("thead", {}, h("tr", {}, h("th", {}, "time"), ...["AI", "other", "browsers"].map((k) => h("th", { class: "num" }, k)))),
      h("tbody", {}, rows.map((b) => h("tr", {}, h("td", {}, clock(b.t, true)), ...ORDER.map((k) => h("td", { class: "num" }, b[k])))))));
  }
  function niceStep(x) {
    const p = Math.pow(10, Math.floor(Math.log10(Math.max(1, x)))), f = x / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  }

  const CHECK = { verified: "verified", spoofed: "failed check", mixed: "partly failed", unverified: "unverified claim" };
  function renderVisitors(d) {
    const v = d.visitors, max = Math.max(1, ...v.map((x) => x.n));
    const span = { "1h": 1, "24h": 24, "7d": 168 }[d.window];
    const head = h("thead", {}, h("tr", {}, h("th", {}, "user agent"), h("th", {}, "check"), h("th", { class: "num" }, "requests"),
      h("th", { class: "num" }, "active"), h("th", { class: "num" }, "last"), h("th", {}, "network"), h("th", {}, "reads")));
    const body = h("tbody", {});
    if (!v.length) body.append(h("tr", { class: "empty-row" }, h("td", { colspan: 7 }, "No requests in this window yet.")));
    for (const x of v) {
      const isBot = ["ai", "search"].includes(x.kind);
      body.append(h("tr", { class: state.ua == x.id ? "sel" : "" },
        h("td", { class: "wrap" }, h("div", { class: "who" }, sw(x.kind),
          h("button", { title: x.ua, onclick: () => focusUa(x.id) }, x.label)),
          x.operator ? h("span", { class: "op" }, x.operator) : null),
        h("td", {}, isBot ? h("span", { class: "chk " + x.verify, title: x.claim || "" }, CHECK[x.verify] || x.verify) : h("span", { class: "chk claimed" }, "n/a")),
        h("td", { class: "num" }, fmt(x.n), h("span", { class: "bar" }, barI(x.n / max))),
        h("td", { class: "num", title: "hours with at least one request" }, `${Math.min(x.hours, span)}/${span} h`),
        h("td", { class: "num" }, ago(x.last, d.now)),
        h("td", { class: "mut wrap" }, x.network + (x.networks > 1 ? ` +${x.networks - 1}` : "")),
        h("td", { class: "reads" }, x.top_paths.join("  "))));
    }
    $("visitors").replaceChildren(head, body);
  }
  function barI(f) { const i = h("i", {}); i.style.width = Math.max(2, Math.round(f * 100)) + "%"; return i; }

  function renderTail(d) {
    const list = $("tail"), items = [];
    for (const x of d.tail) {
      const isNew = !state.first && !state.seen.has(x.id);
      state.seen.add(x.id);
      items.push(h("li", { class: isNew ? "new" : "" },
        h("time", { datetime: new Date(x.t * 1000).toISOString() }, clock(x.t) + ":" + String(new Date(x.t * 1000).getSeconds()).padStart(2, "0")),
        h("span", { class: "l1" }, sw(x.kind), h("b", { title: x.claim || "" }, x.claim && !["range", "rdns"].includes(x.verify) ? "claims " + (x.label || "?") : (x.label || "?"))),
        h("span", { class: "st" + (x.status >= 400 ? " e" : "") }, x.status),
        h("span", { class: "req" }, (x.method !== "GET" ? x.method + " " : "") + x.path + (x.q ? "?" + x.q : "")),
        h("span", { class: "net" }, `${x.ip} · ${x.net}${x.asn ? " · AS" + x.asn : ""}`)));
    }
    if (!items.length) items.push(h("li", {}, h("span", { class: "req" }, "Waiting for the first request.")));
    if (state.seen.size > 5000) state.seen = new Set(d.tail.map((x) => x.id));
    list.replaceChildren(...items);
  }

  function table(id, cols, rows, empty) {
    const head = h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: c.num ? "num" : "" }, c.t))));
    const body = h("tbody", {}, rows.length ? rows.map((r) => h("tr", {}, cols.map((c) => h("td", { class: c.num ? "num" : c.cls || "" }, c.f(r)))))
      : h("tr", { class: "empty-row" }, h("td", { colspan: cols.length }, empty)));
    $(id).replaceChildren(head, body);
  }
  function renderNetworks(d) {
    table("networks", [
      { t: "network", cls: "wrap", f: (r) => [h("b", {}, r.name), h("span", { class: "op" }, (r.asn ? "AS" + r.asn : "unknown") + " · " + (r.kind === "cloud" ? "cloud / hosting" : r.kind === "hosting" ? "hosting? (unverified)" : r.kind === "isp" ? "consumer ISP" : r.kind))] },
      { t: "requests", num: 1, f: (r) => fmt(r.n) }, { t: "AI", num: 1, f: (r) => fmt(r.ai) }, { t: "IPs", num: 1, f: (r) => fmt(r.ips) },
    ], d.networks, d.asn_db ? "No requests yet." : "Network table still loading.");
  }
  function renderPaths(d) {
    table("pages", [{ t: "path", cls: "wrap", f: (r) => r.path }, { t: "requests", num: 1, f: (r) => fmt(r.n) }, { t: "agents", num: 1, f: (r) => r.uas }], d.pages, "Nothing read yet.");
    table("downloads", [{ t: "file", cls: "wrap", f: (r) => r.path }, { t: "fetches", num: 1, f: (r) => fmt(r.n) }, { t: "sent", num: 1, f: (r) => bytes(r.bytes) }], d.downloads, "No JSON or text files fetched yet.");
  }
  function renderQueries(d) {
    table("qkeys", [{ t: "parameter", f: (r) => r.key }, { t: "uses", num: 1, f: (r) => fmt(r.n) }], d.query_keys, "No query strings yet.");
    const rq = d.recent_queries.map((r) => h("li", {}, h("span", {}, clock(r.t) + " " + (r.label || "?") + " "), r.path + "?" + r.q));
    $("rq").replaceChildren(...(rq.length ? rq : [h("li", {}, h("span", {}, "No query strings yet."))]));
  }
  function renderWrites(d) {
    table("writes", [{ t: "client", f: (r) => r.via || "?" }, { t: "kind", f: (r) => r.kind }, { t: "written", num: 1, f: (r) => r.n }, { t: "visible", num: 1, f: (r) => r.visible }],
      d.writes, "Nobody has written anything in this window.");
  }

  function renderInvites(d) {
    table("invites", [
      { t: "entry point", cls: "wrap", f: (r) => [h("b", {}, r.entry), h("span", { class: "op" }, "via=" + r.tag)] },
      { t: "reads", num: 1, f: (r) => fmt(r.reads) }, { t: "readers", num: 1, f: (r) => fmt(r.readers) },
      { t: "tried", num: 1, f: (r) => fmt(r.tried) }, { t: "notes", num: 1, f: (r) => fmt(r.notes) },
      { t: "notes / readers", num: 1, f: (r) => (r.readers ? Math.round((100 * r.note_agents) / r.readers) + "%" : "–") },
      { t: "clients", cls: "wrap", f: (r) => r.clients.join(", ") },
    ], d.invitations || [], "No invitation data yet.");
  }
  function renderHouses(d) {
    const H = d.houses;
    if (!H) { $("houses-sum").textContent = "Shown for everyone only (clear the visitor filter)."; $("houses").replaceChildren(); return; }
    const s = H.summary, win = H.render_window_s || 30;
    const late = (s.pixel_deferred || 0) + (s.js_deferred || 0);
    $("houses-sum").textContent = fmt(s.visitors) + " visitors: " + fmt(s.html_only) + " fetched HTML only, " + fmt(s.pixel) +
      " rendered the page (image within " + win + " s), " + fmt(s.js) + " ran JavaScript, " + fmt(late) +
      " fetched the image or script only later (a queued crawler fetch, not a render), " + fmt(s.house1_only) +
      " saw only house 1. Views: house 1 " + fmt(H.views["1"] || 0) + ", house 2 " + fmt(H.views["2"] || 0) + " (image loaded " +
      fmt(H.pixel_loaded["2"] || 0) + "), house 3 " + fmt(H.views["3"] || 0) + " (image " + fmt(H.pixel_loaded["3"] || 0) +
      ", script " + fmt(H.js_ran) + ").";
    const dur = (n) => n < 120 ? n + " s" : n < 7200 ? Math.round(n / 60) + " min" : n < 172800 ? (n / 3600).toFixed(1) + " h" : (n / 86400).toFixed(1) + " d";
    const after = (d) => d == null ? "no" : "+" + dur(d) + (d > win ? " (late)" : "");
    table("houses", [
      { t: "client", cls: "wrap", f: (r) => [h("b", {}, r.label), h("span", { class: "op" }, r.network + (r.ip ? " · " + r.ip : ""))] },
      { t: "houses", f: (r) => r.houses.join(", ") }, { t: "HTML", f: () => "yes" },
      { t: "image after page", f: (r) => after(r.pixel_delay_s) }, { t: "JS after page", f: (r) => after(r.js_delay_s) },
      { t: "verdict", f: (r) => r.verdict }, { t: "views", num: 1, f: (r) => fmt(r.views) },
    ], H.visitors, "Nobody has visited the houses in this window.");
  }

  function focusUa(id) { state.ua = state.ua == id ? null : String(id); syncUrl(); load(); window.scrollTo({ top: 0, behavior: "smooth" }); }

  // ---------------------------------------------------------------- wire up
  for (const b of document.querySelectorAll(".seg button")) b.addEventListener("click", () => { state.w = b.dataset.w; syncUrl(); load(); });
  $("focus-clear").addEventListener("click", () => { state.ua = null; syncUrl(); load(); });
  let rt; window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => state.data && renderChart(state.data), 120); });
  load();
  setInterval(() => { if (!document.hidden) load(); }, 5000);
  setInterval(tick, 1000);
})();
