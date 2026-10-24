"""Owner-only view: full IPs, reverse DNS, ASN/range whois summary, every
request from an IP, review queue with decoded payloads, audit log.

Listens on the tailnet address only. Every request is checked against the
Tailscale LocalAPI whois of the TCP peer (same rule as pages-server): login
in owner_allow, node untagged, node name not matching owner_deny_nodes.
No proxy headers are trusted here (Tailscale-*, X-Forwarded-*, X-Real-IP are
ignored). Writes (hide/unhide/ok) are POST with a per-login CSRF token,
Sec-Fetch-Site / Origin checks and a redirect only to a local path.
"""
import collections
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse

import forum as F
import hardening as hd
import moderation as mod
import netintel

_cache, _lock = collections.OrderedDict(), threading.Lock()
DENY = re.compile(F.CFG["owner_deny_nodes"])
SECRET = os.urandom(32)   # CSRF key; new on every start (reload the page after a restart)
BACK_RE = re.compile(r"^/(?:|ips|hits|audit|invites|ip/[0-9a-fA-F.:]{2,45})$")
CRAWLER_SUFFIXES = tuple(sorted({sfx for *_, ver in netintel.UA_RULES if ver for sp in ver
                                 if not isinstance(sp, str) and sp[0] == "rdns" for sfx in sp[1]}))


def csrf(login):
    return hmac.new(SECRET, (login or "").encode(), hashlib.sha256).hexdigest()[:40]


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("local-tailscaled.sock", timeout=3)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(self._path)
        self.sock = s


def whois(ip, port):
    now = time.time()
    with _lock:
        hit = _cache.get(ip)
        if hit and now - hit[0] < 60:
            return hit[1]
    res = None
    try:
        c = _UnixConn(F.CFG["tailscale_socket"])
        c.request("GET", "/localapi/v0/whois?addr=" + urllib.parse.quote(f"{ip}:{port}"),
                  headers={"Host": "local-tailscaled.sock"})
        r = c.getresponse()
        body = r.read()
        c.close()
        if r.status == 200:
            d = json.loads(body)
            node = d.get("Node") or {}
            name = node.get("ComputedName") or (node.get("Hostinfo") or {}).get("Hostname") or ""
            res = ((d.get("UserProfile") or {}).get("LoginName", ""), name, node.get("Tags") or [])
    except Exception as e:
        hd.elog(f"owner whois error: {e!r}")
        return None
    with _lock:
        _cache[ip] = (now, res)
        while len(_cache) > 256:
            _cache.popitem(last=False)
    return res


def allowed(ip, port):
    """-> the owner's login, or None."""
    w = whois(ip, port)
    if not w:
        return None
    login, name, tags = w
    if (not tags) and not DENY.search(name or "") and login in F.CFG["owner_allow"]:
        return login
    return None


esc = F.esc
esc_text = F.esc_text


def shell(title, body):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>
<meta name="robots" content="noindex"><link rel="stylesheet" href="/static/site.css"></head>
<body class="owner"><header class="top"><a class="brand" href="/">owner view</a>
<nav><a href="/">queue</a><a href="/ips">IPs</a><a href="/hits">requests</a><a href="/houses">houses</a><a href="/audit">audit</a><a href="/invites">invites</a></nav></header>
<p class="notice">Private: full IP addresses. Tailnet only, owner login only. Do not screenshot into public places.</p>
<main>{body}</main></body></html>"""


def item_card(r, now, tok, back):
    dec = "".join(f'<div class="dec"><b>{esc(m)} (decoded, untrusted)</b><pre>{esc_text(t[:1500])}</pre></div>' for m, t in mod.decode_views(r["text"]))
    st = r["status"]
    btn = []
    if st == "visible":
        btn.append(f'<button name="action" value="hide">hide</button>')
    else:
        btn.append(f'<button name="action" value="unhide">unhide</button>')
    if not r["reviewed"]:
        btn.append(f'<button name="action" value="ok" class="primary">looks fine</button>')
    where = (f'<a href="{esc(F.CFG["site_url"])}/t/{int(r["thread"] or 0)}">thread {int(r["thread"] or 0)}</a> · /{esc(r["board"])}' if r["kind"] == "post"
             else f'{esc(r["kind"])} <code>{esc(r["key"])}</code>')
    return f"""<article class="card st-{esc(st)}"><div class="meta"><span class="pid">#{int(r['id'])}</span>{F.who(r['name'])}
<span>{where}</span><span class="tag">{esc(st)}{(': ' + esc(r['reason'])) if r['reason'] else ''}</span>{('<span class="tag">' + esc(r['flags']) + '</span>') if r['flags'] else ''}{('<span class="tag">via=' + esc(r['invite']) + '</span>') if r['invite'] else ''}
<time>{F.ago(r['created'], now)}</time></div>
<div class="meta"><a href="/ip/{esc(r['ip'])}">{esc(r['ip'])}</a><span>{esc(r['net'])}</span><span>{esc(r['ua_label'])} ({esc(r['verify'] or '-')})</span></div>
<pre class="text">{esc_text(r['text'])}</pre>{dec}
<details><summary>raw request</summary><pre>{esc(r['ua'])}\n?{esc(r['query'])}</pre></details>
<form method="post" action="/act"><input type="hidden" name="id" value="{int(r['id'])}"><input type="hidden" name="csrf" value="{esc(tok)}"><input type="hidden" name="back" value="{esc(back)}"><input name="reason" placeholder="reason (for hide)" maxlength="80">{''.join(btn)}</form>
</article>"""


def page_queue(tok):
    now = time.time()
    pend = F.q("SELECT * FROM items WHERE reviewed=0 ORDER BY id DESC LIMIT 100")
    recent = F.q("SELECT * FROM items WHERE reviewed=1 ORDER BY id DESC LIMIT 20")
    body = [f"<h1 class='pg'>Review queue <span class='count'>{len(pend)}</span></h1>"]
    body += [item_card(r, now, tok, "/") for r in pend] or ["<p class='empty'>Nothing waiting.</p>"]
    body.append("<h2>Recently reviewed</h2>")
    body += [item_card(r, now, tok, "/") for r in recent]
    return shell("queue", "".join(body))


def split_mark(d):
    """Owner lists: a 2-vs-1 vote is marked; the public label shows only the majority."""
    if not d.get("dissent"):
        return ""
    return " <span class='small'>[split vote: " + esc(", ".join(
        f"{x['source']} AS{'/AS'.join(map(str, x['asns']))}" for x in d["dissent"])) + " outvoted]</span>"


def page_ips():
    now = int(time.time())
    rows = F.q("SELECT ip, asn, count(*) n, min(ts) f, max(ts) l, count(DISTINCT ua_id) u FROM hits WHERE ts>? "
               "GROUP BY ip ORDER BY n DESC LIMIT 300", (now - 7 * 86400,))
    tr = []
    for r in rows:
        d = F.NET.describe_ip(r["ip"])
        ptr = F.VERIFY.cached_reverse(r["ip"]) or ""   # no DNS from a list page; open the IP to look it up
        tr.append(f"<tr><td><a href='/ip/{esc(r['ip'])}'>{esc(r['ip'])}</a></td><td>{esc(ptr)}</td><td>AS{int(d['asn'] or 0) or '?'} {esc(d['label'])}{split_mark(d)}</td>"
                  f"<td>{esc(d['kind'])} / {esc(d['status'])}</td><td>{esc(d['cc'])}</td><td class='num'>{int(r['n'])}</td><td class='num'>{int(r['u'])}</td><td>{F.ago(r['l'], now)}</td></tr>")
    return shell("IPs", "<h1 class='pg'>IPs, last 7 days</h1><table class='kv'><thead><tr><th>IP</th><th>reverse DNS</th><th>network</th>"
                 "<th>kind</th><th>cc</th><th>req</th><th>UAs</th><th>last</th></tr></thead><tbody>" + "".join(tr) + "</tbody></table>")


def hits_table(rows, now):
    tr = []
    for r in rows:
        d = F.NET.describe_ip(r["ip"])
        tr.append(f"<tr><td>{time.strftime('%m-%d %H:%M:%S', time.gmtime(r['ts']))}</td><td><a href='/ip/{esc(r['ip'])}'>{esc(r['ip'])}</a></td>"
                  f"<td>{esc(d['label'])}</td><td title='{esc(r['ua'])}'>{esc(r['label'])}</td><td>{esc(r['verify'] or '')}</td>"
                  f"<td class='path'>{esc(r['method'])} {esc(r['path'])}{('?' + esc(r['query'][:400])) if r['query'] else ''}</td>"
                  f"<td class='num'>{int(r['status'] or 0)}</td><td class='num'>{int(r['bytes'] or 0)}</td></tr>")
    return ("<table class='kv hits'><thead><tr><th>UTC</th><th>IP</th><th>network</th><th>UA</th><th>check</th><th>request</th>"
            "<th>st</th><th>bytes</th></tr></thead><tbody>" + "".join(tr) + "</tbody></table>")


def page_hits():
    rows = F.q("SELECT h.*, u.label, u.ua FROM hits h LEFT JOIN uas u ON u.id=h.ua_id ORDER BY h.id DESC LIMIT 300")
    return shell("requests", "<h1 class='pg'>Last 300 requests</h1>" + hits_table(rows, time.time()))


def vote_text(d):
    """Owner view: who voted for what, and who was outvoted."""
    v = d.get("votes") or {}
    if not v:
        return "no fresh source knows this IP"
    names = {"iptoasn": "iptoasn", "ris": "RIPE RIS", "dbip": "DB-IP"}
    parts = [f"{names.get(s, s)} AS{'/AS'.join(map(str, a))}" for s, a in v.items()]
    out = ", ".join(parts) + f" -> {'AS' + str(d['asn']) if d.get('asn') else 'no majority'}"
    if d.get("moas"):
        out += "; also fine: " + ", ".join(f"{names.get(x['source'], x['source'])} AS{'/AS'.join(map(str, x['asns']))}"
                                           for x in d["moas"]) + " (another origin RIS sees for this prefix)"
    if d.get("dissent"):
        out += "; DISSENT: " + ", ".join(f"{names.get(x['source'], x['source'])} says AS{'/AS'.join(map(str, x['asns']))}"
                                         for x in d["dissent"])
    return out


def page_ip(ip, tok):
    now = int(time.time())
    d = F.NET.describe_ip(ip)
    asn = d["asn"]
    rng = F.NET.range_info(ip) or {}
    ages = F.NET.ages()

    def age(name):
        a = ages.get(name) or {}
        return "never fetched" if a.get("age_h") is None else f"{a['age_h']} h ago" + ("" if a.get("fresh") else " (STALE, ignored)")

    def dbip_age():
        a = ages.get("dbip") or {}
        if a.get("age_h") is None:
            return "never fetched"
        return (f"{a.get('published') or '?'} ({round(a['age_h'] / 24)} d old, limit 45 d)"
                + ("" if a.get("fresh") else " (STALE, ignored)"))
    ptr = F.VERIFY.reverse(ip, wait=2.0)   # PTR of a client IP (bounded, cached)
    fwd = ""
    if ptr:
        if ptr.lower().endswith(CRAWLER_SUFFIXES):
            addrs = F.VERIFY.forward(ptr, wait=2.0)
            fwd = ("no forward record" if not addrs else
                   ", ".join(addrs[:6]) + (" (confirms)" if ip in addrs else " (does NOT confirm)"))
        else:
            fwd = "not checked: the name is chosen by whoever runs that reverse zone (no lookups of client-chosen hosts)"
    agg = F.q1("SELECT count(*) n, min(ts) f, max(ts) l, count(DISTINCT ua_id) u, count(DISTINCT path) p FROM hits WHERE ip=?", (ip,))
    uas = F.q("SELECT u.label, u.ua, count(*) n FROM hits h JOIN uas u ON u.id=h.ua_id WHERE h.ip=? GROUP BY h.ua_id ORDER BY n DESC LIMIT 20", (ip,))
    hits = F.q("SELECT h.*, u.label, u.ua FROM hits h LEFT JOIN uas u ON u.id=h.ua_id WHERE h.ip=? ORDER BY h.id DESC LIMIT 1000", (ip,))
    items = F.q("SELECT * FROM items WHERE ip=? ORDER BY id DESC LIMIT 50", (ip,))
    try:
        a = ipaddress.ip_address(ip)
        flags = [x for x, on in (("private", a.is_private), ("global", a.is_global), ("reserved", a.is_reserved)) if on]
    except ValueError:
        flags = []
    rows = [("IP", ip), ("reverse DNS", ptr if ptr is not None else "pending, reload"), ("forward check", fwd or "-"),
            ("network (public label)", d["label"]), ("status", f"{d['status']}: {d['why']}"),
            ("origin AS, iptoasn.com", (f"AS{d['a']}" if d["a"] else "not in table") + f"  · data {age('iptoasn')}"),
            ("origin AS, RIPE RIS", (" / ".join(f"AS{x}" for x in d["b"]) or "not announced")
             + f"  · data {age('ris6' if ':' in ip else 'ris4')}"),
            ("origin AS, DB-IP", (f"AS{d['c']}" if d["c"] else "not in table") + f"  · release {dbip_age()}"),
            ("vote", vote_text(d)),
            ("published cloud range", d["provider"] or "no"),
            ("registry name (RIPE asn.txt)", (d.get("raw") or "-") + f"  · list {age('asnames')}"),
            ("country (ASN)", d["cc"]),
            ("network kind", d["kind"] + "  (public full IP only for kind=cloud with status=verified; all else /24 or /48)"),
            ("announced range", f"{rng.get('first', '?')} – {rng.get('last', '?')}"), ("as CIDR", ", ".join(rng.get("cidrs", [])) or "-"),
            ("address flags", ", ".join(flags)), ("Cloudflare edge", "yes" if F.VERIFY.is_cloudflare(ip) else "no"),
            ("public display", F.public_ip(ip, d)),
            ("requests logged", f"{agg['n']} · {agg['u']} user agents · {agg['p']} paths"),
            ("first / last seen", f"{F.iso(agg['f'])} / {F.iso(agg['l'])}" if agg["n"] else "-")]
    dl = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in rows)
    ua_l = "".join(f"<li><b>{esc(u['label'])}</b> ×{u['n']}<br><code>{esc(u['ua'])}</code></li>" for u in uas)
    body = (f"<h1 class='pg'>{esc(ip)}</h1><p class='small'>Offline data: iptoasn.com + RIPE RIS + DB-IP origin tables (2 of 3 must agree), RIPE AS names, providers' published ranges (no live lookups except reverse DNS). <a href='https://db-ip.com'>IP Geolocation by DB-IP</a>.</p>"
            f"<dl class='whois'>{dl}</dl><h2>User agents</h2><ul class='side wide'>{ua_l}</ul>"
            + (("<h2>Writes from this IP</h2>" + "".join(item_card(r, now, tok, "/ip/" + ip) for r in items)) if items else "")
            + f"<h2>All requests (newest 1000)</h2>{hits_table(hits, now)}")
    return shell(ip, body)


def page_invites(tok):
    """Invitation funnel, 7 days, nothing excluded (the public one hides the owner's networks)."""
    now = int(time.time())
    with F.reader() as c:
        rows = F.invite_funnel(c, now - 7 * 86400, public=False)
    tr = "".join(f"<tr><td><code>via={esc(r['tag'])}</code></td><td>{esc(r['entry'])}</td><td class='num'>{int(r['reads'])}</td>"
                 f"<td class='num'>{int(r['readers'])}</td><td class='num'>{int(r['tried'])}</td><td class='num'>{int(r['notes'])}</td>"
                 f"<td class='num'>{int(r['visible'])}</td><td>{esc(', '.join(r['clients']))}</td></tr>" for r in rows)
    items = F.q("SELECT * FROM items WHERE invite IS NOT NULL ORDER BY id DESC LIMIT 100")
    tries = F.q("SELECT h.*, u.label, u.ua FROM hits h LEFT JOIN uas u ON u.id=h.ua_id WHERE h.invite IS NOT NULL "
                "ORDER BY h.id DESC LIMIT 200")
    body = ("<h1 class='pg'>Invitation funnel, last 7 days</h1><p class='small'>Each entry point shows the same invitation with its own "
            "<code>via=</code> tag. reads = requests for the entry point (readers = distinct user agents); tried = requests to a write route "
            "carrying the tag; notes = writes stored with it (visible + held). Owner view: nothing excluded.</p>"
            "<table class='kv'><thead><tr><th>tag</th><th>entry point</th><th>reads</th><th>readers</th><th>tried</th><th>notes</th>"
            "<th>visible</th><th>clients</th></tr></thead><tbody>" + tr + "</tbody></table>"
            "<h2>Notes left through an invitation</h2>"
            + ("".join(item_card(r, now, tok, "/invites") for r in items) or "<p class='empty'>None yet.</p>")
            + "<h2>Requests carrying a via= tag (newest 200)</h2>" + hits_table(tries, now))
    return shell("invites", body)


def page_houses():
    """Three houses, every view with full IP: which stages it reached, whether
    the image/script came from the same IP+UA as the page, the script's facts."""
    rows = F.q("SELECT h.*, u.label, u.ua FROM houses h LEFT JOIN uas u ON u.id=h.ua_id ORDER BY h.ts DESC LIMIT 500")
    tot = F.q1("SELECT count(*) n, sum(house>=2) offered, sum(px_ts IS NOT NULL) px, sum(house=3) h3, sum(js_ts IS NOT NULL) js "
               "FROM houses")

    def stage(ts, same, base, n):
        if not ts:
            return "-"
        return f"+{int(ts - base)} s" + ("" if same else " (other IP/UA)") + (f" ×{int(n)}" if n and n > 1 else "")
    tr = []
    for r in rows:
        d = F.NET.describe_ip(r["ip"]) if r["ip"] else {"label": "?"}
        verdict = "ran JS" if r["js_ts"] else "loaded image" if r["px_ts"] else "HTML only" if r["house"] >= 2 else "house 1"
        tr.append(f"<tr><td>{time.strftime('%m-%d %H:%M:%S', time.gmtime(r['ts']))}</td><td class='num'>{int(r['house'])}</td>"
                  f"<td><a href='/ip/{esc(r['ip'])}'>{esc(r['ip'])}</a></td><td>{esc(d['label'])}</td>"
                  f"<td title='{esc(r['ua'])}'>{esc(r['label'])}</td><td>{esc(r['verify'] or '')}</td>"
                  f"<td>{esc(stage(r['px_ts'], r['px_same'], r['ts'], r['px_n']))}</td>"
                  f"<td>{esc(stage(r['js_ts'], r['js_same'], r['ts'], r['js_n']))}</td><td>{esc(r['js_info'] or '')}</td>"
                  f"<td>{esc(verdict)}</td></tr>")
    head = (f"<p class='small'>{int(tot['n'] or 0)} views kept; image loaded on {int(tot['px'] or 0)} of {int(tot['offered'] or 0)} "
            f"views of houses 2-3; script ran on {int(tot['js'] or 0)} of {int(tot['h3'] or 0)} views of house 3. "
            "Owner networks are never recorded.</p>")
    return shell("houses", "<h1 class='pg'>Three houses, newest 500 views</h1>" + head +
                 "<table class='kv hits'><thead><tr><th>UTC</th><th>house</th><th>IP</th><th>network</th><th>UA</th><th>check</th>"
                 "<th>image</th><th>script</th><th>script facts</th><th>verdict</th></tr></thead><tbody>" + "".join(tr) + "</tbody></table>")


def page_audit():
    rows = F.q("SELECT * FROM audit ORDER BY id DESC LIMIT 300")
    tr = "".join(f"<tr><td>{F.iso(r['ts'])}</td><td>{esc(r['actor'])}</td><td>{esc(r['action'])}</td><td>#{int(r['item'] or 0)}</td><td>{esc(r['reason'])}</td></tr>" for r in rows)
    return shell("audit", "<h1 class='pg'>Audit log</h1><p class='small'>Nothing is ever deleted; hide only changes visibility.</p>"
                 "<table class='kv'><thead><tr><th>UTC</th><th>actor</th><th>action</th><th>item</th><th>reason</th></tr></thead><tbody>" + tr + "</tbody></table>")


class Owner(hd.HardenedHandler):
    io_timeout = 15.0
    head_timeout = 15.0
    extra_headers = (("X-Robots-Tag", "noindex, nofollow"),)

    def out(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def gate(self):
        """Identity = Tailscale whois of the TCP peer. Nothing from the request
        (headers, query) is consulted."""
        ip, port = self.client_address[0], self.client_address[1]
        self.login = allowed(ip, port)
        if not self.login:
            self.close_connection = True
            self.out(403, "forbidden\n", "text/plain; charset=utf-8")
            return False
        return True

    def do_GET(self):
        if not self.gate():
            return
        u = urllib.parse.urlsplit("http://owner" + self.path)
        p = urllib.parse.unquote(u.path)
        tok = csrf(self.login)
        try:
            if p.startswith("/static/"):
                f = F.STATIC_FILES.get(p[8:])
                if f is None:
                    return self.out(404, "not found\n", "text/plain; charset=utf-8")
                return self.out(200, f[0], f[1])
            if p == "/":
                return self.out(200, page_queue(tok))
            if p == "/ips":
                return self.out(200, page_ips())
            if p == "/hits":
                return self.out(200, page_hits())
            if p == "/audit":
                return self.out(200, page_audit())
            if p == "/invites":
                return self.out(200, page_invites(tok))
            if p == "/houses":
                return self.out(200, page_houses())
            if p.startswith("/ip/") and F.valid_ip(p[4:]):
                return self.out(200, page_ip(F.valid_ip(p[4:]), tok))
            return self.out(404, shell("not found", "<p class='empty'>not found</p>"))
        except OSError:
            self.close_connection = True
        except Exception as e:
            hd.elog(f"owner error: {e!r}")
            return self.out(500, "error\n", "text/plain; charset=utf-8")

    def do_POST(self):
        if not self.gate():
            return
        self.close_connection = True
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        site = self.headers.get("Sec-Fetch-Site")
        if site not in (None, "same-origin", "none"):
            return self.out(403, "cross-site request refused\n", "text/plain; charset=utf-8")
        if origin not in (None, "null") and urllib.parse.urlsplit(origin).netloc != host:
            return self.out(403, "bad origin\n", "text/plain; charset=utf-8")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            return self.out(415, "form posts only\n", "text/plain; charset=utf-8")
        try:
            n = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            n = -1
        if n < 0 or n > 4096 or self.headers.get("Transfer-Encoding"):
            return self.out(413, "bad length\n", "text/plain; charset=utf-8")
        try:
            self.allow_body(n)
            raw = self.rfile.read(n)
        except OSError:
            return
        form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), max_num_fields=10)
        if not hmac.compare_digest((form.get("csrf") or [""])[0], csrf(self.login)):
            return self.out(403, "bad or missing csrf token (reload the page)\n", "text/plain; charset=utf-8")
        action = (form.get("action") or [""])[0]
        ids = F.parse_ids((form.get("id") or [""])[0])
        reason = (form.get("reason") or [""])[0][:80]
        actor = "owner:" + self.login[:40]
        if action == "hide":
            F.set_status(ids, "hidden", actor, reason or "owner")
        elif action == "unhide":
            F.set_status(ids, "visible", actor)
        elif action == "ok":
            F.mark_ok(ids, actor)
        else:
            return self.out(400, "unknown action\n", "text/plain; charset=utf-8")
        back = (form.get("back") or ["/"])[0]
        return self.out(303, "", headers={"Location": back if BACK_RE.match(back) else "/"})
