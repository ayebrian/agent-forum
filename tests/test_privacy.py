"""The origin server's own addresses never leave the owner view.

The origin's public IPs showed up in full in the public observatory (a hosting network counts
as "cloud", so its IPs are not masked), which exposed the origin behind
Cloudflare. exclude_nets (the origin's /26 and /64 plus loopback) is applied like
exclude_asns: at log time and again at read time, so rows stored before the
entry existed stay in the DB and the owner view but leave every public output.
Our own test tooling ("self": self_ua_markers, self_nets) is logged but hidden
from public stats unless ?self=1; the excluded networks stay hidden even then."""
import ipaddress
import json
import os
import sqlite3
import sys
import time
import tomllib
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import (AS_NAMES, ASN_ROWS, CLOUDS, CLOUD_V4, REPO, RESIDENTIAL_V4, RIS_ROWS, Instance,  # noqa: E402
                     qs)

MC_V4 = "198.18.7.72"                 # the origin (benchmark range), seen as RybbitSetupCheck
MC_V6 = "3fff:0:172:1950::2"          # the origin, IPv6 (documentation range), seen as curl
MC_V4_NEIGHBOUR = "198.18.7.100"     # same /26
MC_V6_OTHER = "3fff:0:172:1950::abcd"
MC_NETS = ["198.18.7.64/26", "3fff:0:172:1950::/64", "127.0.0.0/8", "::1/128"]
VM_IP = "198.18.200.29"               # our test machine (self_nets)
SELF_NETS = ["198.18.200.0/24"]
RYBBIT_CHECK = "Mozilla/5.0 (compatible; RybbitSetupCheck/1.0; +https://rybbit.com)"
VERIFY_RYBBIT = "Mozilla/5.0 (X11; Linux x86_64) verify-rybbit/1.0"
WORKER_CHECK = "claude-worker-check (headless screenshot)"

# Anything that would identify the origin, in any public spelling: full v4, the /24 mask
# ("198.18.7.x"), full v6, the /48 mask, the IPv4-mapped hex form.
MC_LEAKS = ("198.18.7.", "3fff:0:172", "c612:748", "Origin Host", "\":64510", "AS64510")   # ASN as a JSON value / label, not inside a timestamp
SELF_LEAKS = ("198.18.200", "RybbitSetupCheck", "verify-rybbit", "claude-worker-check", "\":64511", "AS64511", "EXAMPLE-TESTVM", "Example Test Cloud")

# The origin and the test machine classified the way production sees them: a confirmed cloud
# network, i.e. a full IP if nothing hid it.
NET = dict(
    asn_rows=ASN_ROWS + [("198.18.7.0", "198.18.7.255", 64510, "ZZ", "EXAMPLE-ORIGIN - Example Origin Host"),
                         ("3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", 64510, "ZZ", "EXAMPLE-ORIGIN - Example Origin Host"),
                         ("198.18.200.0", "198.18.200.255", 64511, "ZZ", "EXAMPLE-TESTVM - Example Test Cloud")],
    ris_rows=RIS_ROWS + [(64510, "198.18.7.0/24", 300), (64510, "3fff::/20", 300), (64511, "198.18.200.0/24", 300)],
    names={**AS_NAMES, 64510: "EXAMPLE-ORIGIN - Example Origin Host, ZZ", 64511: "EXAMPLE-TESTVM - Example Test Cloud, ZZ"},
    clouds={**CLOUDS, "Provider A List": ["198.18.7.0/24", "3fff::/20"], "Provider B List": ["198.18.200.0/24"]},   # list names are public (net_data)
)
BIG = [100000, 1000.0]
FAST = dict(rate_write={"ip": [100000, 1], "ipday": [100000, 1], "ua": [100000, 1], "asn": [100000, 1], "all": [100000, 1]},
            max_items_per_day=100000, rate_read_ip=BIG, rate_read_asn=BIG, rate_read_ua=BIG, rate_read_all=BIG,
            rate_log_ip=BIG, rate_log_all=BIG, rate_expensive_ip=BIG)


def public_urls(f, extra=()):
    """Every public read the app serves (HTML, text, JSON), incl. the observatory
    for every window and every user agent id, with and without ?self=1."""
    db = sqlite3.connect(os.path.join(f.dir, "forum.sqlite3"), timeout=10)
    try:
        uids = [r[0] for r in db.execute("SELECT id FROM uas")]
        threads = [r[0] for r in db.execute("SELECT id FROM items WHERE kind='post' AND parent IS NULL")]
        pages = [r[0] for r in db.execute("SELECT DISTINCT key FROM items WHERE kind='wiki'")]
    finally:
        db.close()
    urls = ["/", "/observatory", "/feed.txt", "/llms.txt", "/llms-full.txt", "/howto.txt", "/robots.txt", "/sitemap.xml",
            "/wiki/", "/kv", "/kv?key=privkey", "/count?key=privcount&peek=1", "/houses", "/houses/1", "/houses/2", "/houses/3",
            "/api/boards.json", "/api/posts.json", "/api/posts.json?limit=200", "/api/wiki.json", "/api/kv.json",
            "/api/counters.json", "/api/search.json?q=privacy", "/api/search.json?q=198.18", "/static/obs.js",
            *[f"/b/{b}" for b in ("general", "introductions")], *[f"/t/{t}" for t in threads],
            *[f"/api/thread/{t}.json" for t in threads], *[f"/wiki/{p}" for p in pages], *[f"/api/wiki/{p}.json" for p in pages]]
    for win in ("1h", "24h", "7d"):
        urls.append(f"/api/observatory.json?window={win}")
        for u in uids:
            urls.append(f"/api/observatory.json?window={win}&ua={u}")
    return urls + list(extra)


class ConfigCoversOrigin(unittest.TestCase):
    def test_example_config_has_valid_privacy_lists(self):
        with open(os.path.join(REPO, "config.example.toml"), "rb") as fh:
            cfg = tomllib.load(fh)
        for key in ("exclude_cidrs", "exclude_nets", "self_nets"):
            self.assertIsInstance(cfg[key], list, key)
            for n in cfg[key]:
                ipaddress.ip_network(n)
        nets = [ipaddress.ip_network(n) for n in cfg["exclude_cidrs"] + cfg["exclude_nets"]]
        for ip in ("127.0.0.1", "::1"):
            self.assertTrue(any(ipaddress.ip_address(ip) in n for n in nets), ip)
        for m in ("claude-worker-check", "verify-rybbit", "RybbitSetupCheck"):
            self.assertIn(m, cfg["self_ua_markers"])

    def test_bad_cidr_stops_the_server(self):
        with self.assertRaises(RuntimeError) as cm:
            Instance(exclude_nets=["198.18.7.300/26"])
        self.assertIn("exclude_nets", str(cm.exception))


class OriginNeverPublic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f = cls.f = Instance(net=NET, exclude_nets=MC_NETS, self_nets=SELF_NETS, **FAST)
        # --- control traffic that must stay visible
        f.get("/howto.txt", ip=RESIDENTIAL_V4, headers={"User-Agent": "curl/8.5.0"})
        f.get("/llms.txt", ip=CLOUD_V4, headers={"User-Agent": "GPTBot/1.2"})
        f.get("/post?" + qs(board="general", name="control", text="privacy control post", via="llms"), ip=CLOUD_V4)
        # --- live traffic from the origin after the fix: dropped at log time
        for ip, ua in ((MC_V4, RYBBIT_CHECK), (MC_V6, "curl/8.14.1"), (MC_V4_NEIGHBOUR, "curl/8.14.1"),
                       (MC_V6_OTHER, "python-requests/2.32"), ("::ffff:198.18.7.72", "curl/8.14.1")):
            h = {"User-Agent": ua}
            for path in ("/", "/llms.txt", "/observatory", "/houses/1", "/houses/2", "/api/posts.json", "/nope-from-origin?x=1"):
                f.get(path, ip=ip, headers=h)
            f.get("/houses/2/px.gif?r=0123456789abcdef", ip=ip, headers=h)
            f.get("/post?" + qs(board="introductions", name="origin-note", text="privacy note from origin", via="llms"), ip=ip, headers=h)
            f.get("/count?key=privcount", ip=ip, headers=h)
        # --- our own test tooling: logged, hidden unless ?self=1
        f.get("/howto.txt", ip=VM_IP, headers={"User-Agent": "curl/8.5.0"})
        f.get("/houses/1", ip=VM_IP, headers={"User-Agent": "curl/8.5.0"})
        f.get("/llms.txt", ip=RESIDENTIAL_V4, headers={"User-Agent": WORKER_CHECK})
        f.get("/robots.txt", ip=CLOUD_V4, headers={"User-Agent": VERIFY_RYBBIT})
        time.sleep(1.6)   # hit writer batch
        db = sqlite3.connect(os.path.join(f.dir, "forum.sqlite3"), timeout=10)
        cls.logged_ips = {r[0] for r in db.execute("SELECT DISTINCT ip FROM hits")}
        cls.house_ips = {r[0] for r in db.execute("SELECT DISTINCT ip FROM houses")}
        # --- rows stored BEFORE the fix (exactly what the live DB holds): kept, but never public
        now = int(time.time())
        with db:
            db.execute("INSERT INTO uas(id, ua, label, kind, first, last, n) VALUES (9013, 'curl/8.14.1-old', 'curl', 'tool', ?, ?, 1)",
                       (now, now))
            db.execute("INSERT INTO uas(id, ua, label, kind, first, last, n) VALUES (9015, ?, 'Mozilla', 'unknown', ?, ?, 1)",
                       (RYBBIT_CHECK, now, now))
            for ip, uid in ((MC_V6, 9013), (MC_V4, 9015), (MC_V4, 9013)):
                for asn in (64510, None):
                    db.execute("INSERT INTO hits(ts, ip, asn, ua_id, kind, verify, method, path, query, status, bytes, ms, invite) "
                               "VALUES (?, ?, ?, ?, 'tool', NULL, 'GET', '/llms.txt', 'via=llms', 200, 10, 1, 'llms')",
                               (now, ip, asn, uid))
                db.execute("INSERT INTO houses(token, house, ts, ip, asn, ua_id, kind, px_ts, px_same, px_n) "
                           "VALUES (?, 2, ?, ?, 64510, ?, 'tool', ?, 1, 1)", (f"old{uid}{ip}"[:40], now, ip, uid, now + 1))
            db.execute("INSERT INTO items(kind, board, subject, name, text, created, bumped, ip, asn, ua, ua_label, ua_kind, "
                       "net, net_kind, status, invite) VALUES ('post', 'introductions', '', 'old-origin', 'old privacy note', ?, ?, ?, "
                       "64510, ?, 'Mozilla', 'unknown', 'Example Origin Host', 'cloud', 'visible', 'llms')",
                       (now, now, MC_V4, RYBBIT_CHECK))
            db.execute("UPDATE items SET thread=id WHERE thread IS NULL AND kind='post'")
        db.close()
        time.sleep(2.1)   # page cache

    @classmethod
    def tearDownClass(cls):
        cls.f.stop()

    def get_text(self, url):
        st, _, body = self.f.get(url, ip="127.0.0.1")
        self.assertIn(st, (200, 302, 404), url)
        return body.decode("utf-8", "replace")

    def test_1_origin_traffic_dropped_at_log_time(self):
        for ip in (MC_V4, MC_V6, MC_V4_NEIGHBOUR, MC_V6_OTHER):
            self.assertNotIn(ip, self.logged_ips)
            self.assertNotIn(ip, self.house_ips)
        self.assertFalse(any(ip and ("198.18.7." in ip or "c612:748" in ip or ip.startswith("3fff:0:172"))
                             for ip in self.logged_ips), self.logged_ips)
        self.assertIn(VM_IP, self.logged_ips)   # self traffic is logged (owner view)

    def test_2_no_public_output_mentions_the_origin(self):
        for url in public_urls(self.f):
            for variant in (url, url + ("&" if "?" in url else "?") + "self=1"):
                body = self.get_text(variant)
                for leak in MC_LEAKS:
                    self.assertNotIn(leak, body, (variant, leak))

    def test_3_self_traffic_hidden_by_default(self):
        for url in public_urls(self.f):
            if url.startswith("/static/"):
                continue
            body = self.get_text(url)
            for leak in SELF_LEAKS:
                self.assertNotIn(leak, body, (url, leak))

    def test_4_totals_count_only_public_rows(self):
        for win in ("1h", "24h", "7d"):
            d = json.loads(self.get_text(f"/api/observatory.json?window={win}"))
            self.assertEqual(d["own_test_traffic"], "hidden")
            self.assertEqual(d["totals"]["ips"], 2, win)                 # RESIDENTIAL_V4 + CLOUD_V4
            self.assertEqual({n["asn"] for n in d["networks"]}, {64500, 64501}, win)
            self.assertEqual(d["totals"]["writes"], 1, win)              # the control post only
            fun = {r["tag"]: r for r in d["invitations"]}
            self.assertEqual(fun["llms"]["notes"], 1, win)
            self.assertEqual(fun["llms"]["tried"], 1, win)
            self.assertEqual(d["houses"]["summary"]["visitors"], 0, win)

    def test_5_self_toggle_shows_our_tooling_but_never_the_origin(self):
        d = json.loads(self.get_text("/api/observatory.json?window=24h&self=1"))
        self.assertEqual(d["own_test_traffic"], "shown")
        raw = json.dumps(d)
        for want in (VM_IP, "claude-worker-check", "verify-rybbit"):
            self.assertIn(want, raw)
        self.assertEqual(d["houses"]["summary"]["visitors"], 1)          # the VM's house 1 view
        for leak in MC_LEAKS:
            self.assertNotIn(leak, raw)
        # the UA RybbitSetupCheck was only ever seen from the origin: still no rows anywhere public
        self.assertNotIn("RybbitSetupCheck", raw)

    def test_6_self_ua_focus_is_404_unless_asked(self):
        st, _, _ = self.f.get("/api/observatory.json?window=24h&ua=9015", ip="127.0.0.1")
        self.assertEqual(st, 404)
        st, _, body = self.f.get("/api/observatory.json?window=24h&ua=9015&self=1", ip="127.0.0.1")
        self.assertEqual(st, 200)
        d = json.loads(body)
        self.assertEqual(d["totals"]["requests"], 0)                     # its rows are all from the origin
        self.assertEqual(d["tail"], [])
        for leak in MC_LEAKS:
            self.assertNotIn(leak, body.decode())

    def test_7_owner_view_keeps_the_stored_rows(self):
        f = self.f
        f.ts.idents["127.0.0.10"] = {"login": "owner@github", "name": "laptop", "tags": []}
        st, _, body = f.owner("/hits", "127.0.0.10")
        self.assertEqual(st, 200)
        page = body.decode()
        self.assertIn(MC_V4, page)
        self.assertIn(MC_V6, page)
        self.assertIn(VM_IP, page)
        st, _, body = f.owner("/houses", "127.0.0.10")
        self.assertEqual(st, 200)
        self.assertIn(MC_V4, body.decode())
        db = sqlite3.connect(os.path.join(f.dir, "forum.sqlite3"), timeout=10)
        self.assertEqual(db.execute("SELECT count(*) FROM hits WHERE ip IN (?, ?)", (MC_V4, MC_V6)).fetchone()[0], 6)
        db.close()


if __name__ == "__main__":
    unittest.main()
