"""Server-side Rybbit sender and the "three houses" experiment.

    python3 -m unittest tests.test_rybbit -v      (from the repo root)

A fake Rybbit (/api/track) on 127.0.0.1 records what the forum sends; nothing
leaves the machine."""
import json
import os
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rybbit  # noqa: E402
from support import CLOUD_V4, COLOMBIA_V4, RESIDENTIAL_V4, RESIDENTIAL_V6, Instance, free_port, hdrs  # noqa: E402

BASE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
            "font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
KEY = "rb_test_key_0123456789"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"


class FakeRybbit:
    """Records every POST /api/track (headers + JSON). `delay` slows each answer."""

    def __init__(self, delay=0.0, status=200):
        self.events, self.headers, self.delay, self.status = [], [], delay, status
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                if outer.delay:
                    time.sleep(outer.delay)
                outer.headers.append(dict(self.headers))
                try:
                    outer.events.append(json.loads(body))
                except ValueError:
                    outer.events.append({"_bad": body[:100]})
                out = b'{"success":true}'
                try:
                    self.send_response(outer.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                except OSError:   # the client gave up (timeout test) or the test is over
                    pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def keyfile(text=None):
    """A 0600 env file with the test key, in a temp dir (never in the repo)."""
    fd, path = tempfile.mkstemp(prefix="aft-rybbit-", suffix=".env")
    with os.fdopen(fd, "w") as f:
        f.write(text if text is not None else f"RYBBIT_API_KEY={KEY}\n")
    return path


def wait_for(cond, timeout=8.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.05)
    return False


def closed_port_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()   # nothing listens there now: connection refused
    return f"http://127.0.0.1:{port}"


# ================================================================ units

class Units(unittest.TestCase):
    def test_ip_truncation(self):
        self.assertEqual(rybbit.mask_ip("203.0.113.77"), "203.0.113.0")
        self.assertEqual(rybbit.mask_ip("2001:db8:abcd:1234::77"), "2001:db8:abcd::")
        self.assertIsNone(rybbit.mask_ip("not-an-ip"))
        self.assertEqual(rybbit.rybbit_ip("198.51.100.20", True), "198.51.100.20")
        self.assertEqual(rybbit.rybbit_ip("198.51.100.20", False), "198.51.100.0")
        self.assertEqual(rybbit.rybbit_ip("2001:db8:abcd:1234::77", False), "2001:db8:abcd::")
        self.assertIsNone(rybbit.rybbit_ip("", True))

    def test_event_fields_clipped_to_rybbit_limits(self):
        ev = rybbit.event("7", hostname="agents.example", pathname="/" + "p" * 5000, ip="203.0.113.0",
                          user_agent="U" * 2000, referrer="http://r/" + "x" * 5000, querystring="a=1",
                          properties={"net": "n" * 3000, "status": 200, "client": "curl"})
        self.assertEqual(ev["type"], "pageview")
        self.assertEqual(ev["site_id"], "7")
        self.assertEqual(len(ev["pathname"]), 2048)
        self.assertEqual(len(ev["user_agent"]), 512)
        self.assertEqual(len(ev["referrer"]), 2048)
        self.assertEqual(ev["querystring"], "?a=1")
        props = json.loads(ev["properties"])       # still valid JSON, the over-long value dropped
        self.assertLessEqual(len(ev["properties"]), 2048)
        self.assertEqual(props, {"status": 200, "client": "curl"})
        ce = rybbit.event("7", hostname="h", pathname="/x", etype="custom_event")
        self.assertEqual(ce["event_name"], "event")
        self.assertNotIn("ip_address", rybbit.event("7", hostname="h", pathname="/"))

    def test_read_key(self):
        path = keyfile("# comment\nOTHER=1\nRYBBIT_API_KEY='abc123'\n")
        try:
            self.assertEqual(rybbit.read_key(path, env={}), "abc123")
            self.assertEqual(rybbit.read_key(path, env={"RYBBIT_API_KEY": "fromenv"}), "fromenv")
            self.assertEqual(rybbit.read_key("/nonexistent/x.env", env={}), "")
        finally:
            os.unlink(path)

    def test_sender_posts_with_bearer(self):
        fake = FakeRybbit()
        try:
            s = rybbit.Sender(fake.url, KEY).start()
            for i in range(5):
                self.assertTrue(s.submit({"type": "pageview", "site_id": "7", "pathname": f"/{i}"}))
            self.assertTrue(wait_for(lambda: len(fake.events) == 5))
            self.assertEqual(sorted(e["pathname"] for e in fake.events), [f"/{i}" for i in range(5)])
            self.assertTrue(all(h.get("Authorization") == "Bearer " + KEY for h in fake.headers))
            self.assertTrue(all(h.get("Content-Type") == "application/json" for h in fake.headers))
            self.assertTrue(wait_for(lambda: s.stats()["sent"] == 5))
            self.assertNotIn(KEY, json.dumps(s.stats()))   # stats never show the key
        finally:
            fake.stop()

    def test_bounded_queue_drops_instead_of_blocking(self):
        fake = FakeRybbit(delay=0.5)   # a slow Rybbit: the worker is stuck on one event
        try:
            s = rybbit.Sender(fake.url, KEY, maxsize=5, timeout=2.0).start()
            t0 = time.time()
            ok = sum(s.submit({"type": "pageview", "site_id": "7", "pathname": "/"}) for _ in range(200))
            self.assertLess(time.time() - t0, 0.2)     # 200 submits never wait on the network
            st = s.stats()
            self.assertLessEqual(ok, 6)
            self.assertGreaterEqual(st["dropped_full"], 194)
            self.assertLessEqual(st["queue"], 5)
        finally:
            fake.stop()

    def test_rybbit_down_pauses_and_never_raises(self):
        s = rybbit.Sender(closed_port_url(), KEY, timeout=0.5, pause_after=3, pause_s=30).start()
        t0 = time.time()
        for _ in range(50):
            s.submit({"type": "pageview", "site_id": "7", "pathname": "/"})
        self.assertLess(time.time() - t0, 0.2)
        self.assertTrue(wait_for(lambda: s.stats()["paused_until"] > time.time()))
        st = s.stats()
        self.assertGreaterEqual(st["failed"], 3)
        self.assertEqual(st["queue"], 0)               # backlog dropped, not retried into the outage
        self.assertFalse(s.submit({"type": "pageview", "site_id": "7", "pathname": "/"}))   # paused: dropped at once
        self.assertGreater(s.stats()["dropped_paused"], 0)

    def test_server_errors_count_as_rejected(self):
        fake = FakeRybbit(status=400)
        try:
            s = rybbit.Sender(fake.url, KEY).start()
            s.submit({"type": "pageview", "site_id": "7"})
            self.assertTrue(wait_for(lambda: s.stats()["rejected"] == 1))
            self.assertEqual(s.stats()["last_error"], "HTTP 400")
        finally:
            fake.stop()


# ========================================================== integration

def token_of(body):
    m = re.search(rb'(?:px\.gif\?r=|data-r=")([0-9a-f]{16})', body)
    return m.group(1).decode() if m else None


class Forum(unittest.TestCase):
    """One forum wired to a fake Rybbit. Colombia's ASN (64502) plays the owner's
    home network: it must never reach Rybbit or the houses table."""

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeRybbit()
        cls.env = keyfile()
        cls.f = Instance(rybbit_enabled=True, rybbit_url=cls.fake.url, rybbit_site_id="7", rybbit_env_file=cls.env,
                         exclude_asns=[64502], rate_read_ip=[100000, 1000.0], rate_log_ip=[100000, 1000.0])
        f = cls.f
        # plain reads from each kind of network
        for i, ip in enumerate((RESIDENTIAL_V4, RESIDENTIAL_V6, CLOUD_V4, COLOMBIA_V4)):
            f.get(f"/?from=net{i}", ip=ip, headers={"User-Agent": BROWSER, "Referer": "https://ref.example/x"})
        # houses: a browser that does everything, an HTML-only fetcher, a house-1-only fetcher, the excluded owner
        cls.tok = {}
        for n in (1, 2, 3):
            st, h, body = f.get(f"/houses/{n}", ip=CLOUD_V4, headers={"User-Agent": BROWSER})
            assert st == 200, (n, st)
            cls.tok[n] = token_of(body)
        time.sleep(1.2)   # the view rows are written by the batching hit writer
        f.get(f"/houses/2/px.gif?r={cls.tok[2]}", ip=CLOUD_V4, headers={"User-Agent": BROWSER})
        f.get(f"/houses/3/px.gif?r={cls.tok[3]}", ip=CLOUD_V4, headers={"User-Agent": BROWSER})
        f.get(f"/houses/3/js-ping?r={cls.tok[3]}&wd=0&sw=1920&sh=1080&tz=Etc/UTC&lang=en-US&hc=8<script>",
              ip=CLOUD_V4, headers={"User-Agent": BROWSER})
        for n in (1, 2, 3):
            f.get(f"/houses/{n}", ip=RESIDENTIAL_V4, headers={"User-Agent": "curl/8.14.1"})
        f.get("/houses/1", ip=RESIDENTIAL_V6, headers={"User-Agent": "Wget/1.25.0"})
        for n in (1, 2, 3):
            st, _, body = f.get(f"/houses/{n}", ip=COLOMBIA_V4, headers={"User-Agent": BROWSER})
            tk = token_of(body)
            if tk and n >= 2:
                f.get(f"/houses/{n}/px.gif?r={tk}", ip=COLOMBIA_V4, headers={"User-Agent": BROWSER})
        f.get("/houses/2/px.gif?r=0123456789abcdef", ip=CLOUD_V4, headers={"User-Agent": "stray"})   # unknown token
        time.sleep(1.5)
        wait_for(lambda: len(cls.fake.events) >= 16)

    @classmethod
    def tearDownClass(cls):
        cls.f.stop()
        cls.fake.stop()
        os.unlink(cls.env)

    def test_hits_reach_rybbit_with_bearer_and_fields(self):
        ev = [e for e in self.fake.events if e.get("pathname") == "/" and e.get("type") == "pageview"]
        self.assertTrue(ev)
        e = ev[0]
        self.assertEqual(e["site_id"], "7")
        self.assertEqual(e["hostname"], "agents.example")
        self.assertEqual(e["user_agent"], BROWSER)
        self.assertEqual(e["referrer"], "https://ref.example/x")
        self.assertTrue(e["querystring"].startswith("?from="))
        props = json.loads(e["properties"])
        for k in ("client", "ua_kind", "net", "net_kind", "net_status", "crawler", "status", "method"):
            self.assertIn(k, props)
        self.assertTrue(all(h.get("Authorization") == "Bearer " + KEY for h in self.fake.headers))

    def test_ip_rule_full_only_for_cloud(self):
        ips = {e.get("ip_address") for e in self.fake.events if e.get("pathname") == "/"}
        self.assertIn(CLOUD_V4, ips)                    # confirmed cloud: full
        self.assertIn("203.0.113.0", ips)               # residential v4: /24 network address
        self.assertIn("2001:db8:abcd::", ips)           # residential v6: /48
        blob = json.dumps(self.fake.events)
        self.assertNotIn(RESIDENTIAL_V4, blob)
        self.assertNotIn("abcd:1234", blob)

    def test_excluded_network_never_sent(self):
        blob = json.dumps(self.fake.events)
        self.assertNotIn("192.0.2.", blob)
        self.assertFalse([e for e in self.fake.events if "from=net3" in e.get("querystring", "")])

    def test_house_stages_are_custom_events(self):
        names = [e.get("event_name") for e in self.fake.events if e.get("type") == "custom_event"]
        self.assertIn("house_image", names)
        self.assertIn("house_script", names)
        js = [e for e in self.fake.events if e.get("event_name") == "house_script"][0]
        props = json.loads(js["properties"])
        self.assertEqual(props["house"], 3)
        self.assertIn("wd=0", props["js"])
        self.assertNotIn("<", props["js"])
        self.assertFalse([e for e in self.fake.events if (e.get("pathname") or "").startswith("/static/")])

    def test_house_stage_recording(self):
        H = json.loads(self.f.get("/api/observatory.json?window=1h")[2])["houses"]
        by = {(v["label"], v["ip"]): v for v in H["visitors"]}
        browser = [v for (lab, ip), v in by.items() if ip == CLOUD_V4]
        self.assertEqual(len(browser), 1, by)
        b = browser[0]
        self.assertEqual((b["houses"], b["pixel"], b["js"], b["verdict"]), ([1, 2, 3], True, True, "ran JS"))
        self.assertLessEqual(b["pixel_delay_s"], 30)
        self.assertLessEqual(b["js_delay_s"], 30)
        curl = [v for (lab, ip), v in by.items() if ip == "203.0.113.x"][0]
        self.assertEqual((curl["houses"], curl["pixel"], curl["js"], curl["verdict"]), ([1, 2, 3], False, False, "HTML only"))
        self.assertEqual((curl["pixel_delay_s"], curl["js_delay_s"]), (None, None))
        wget = [v for (lab, ip), v in by.items() if ip.startswith("2001:db8:abcd::")][0]
        self.assertEqual(wget["verdict"], "house 1 only")
        self.assertEqual(H["summary"], {"visitors": 3, "html_only": 1, "pixel": 0, "js": 1, "house1_only": 1,
                                        "pixel_deferred": 0, "js_deferred": 0})
        self.assertEqual(H["render_window_s"], 30)
        self.assertEqual(H["views"], {"1": 3, "2": 2, "3": 2})
        self.assertEqual(H["pixel_loaded"], {"2": 1, "3": 1})
        self.assertEqual(H["js_ran"], 1)
        # the excluded network left no house rows at all (owner view counts everything kept)
        st = json.loads(self.f.admin("GET", "/stats")[1])
        self.assertEqual(st["houses"], 7)
        self.assertEqual(st["rybbit"]["rejected"], 0)
        self.assertNotIn(KEY, json.dumps(st))

    def test_owner_houses_page(self):
        self.f.ts.idents["127.0.0.10"] = {"login": "owner@github", "name": "laptop", "tags": []}
        st, h, body = self.f.owner("/houses", "127.0.0.10")
        self.assertEqual(st, 200)
        text = body.decode()
        self.assertIn(CLOUD_V4, text)
        self.assertIn(RESIDENTIAL_V4, text)            # owner view: full IPs
        self.assertIn("sw=1920", text)
        self.assertNotIn("192.0.2.44", text)            # never recorded
        self.assertNotIn("<script>", text.split("</nav>", 1)[1])

    def test_house_pages_headers_and_markup(self):
        for n in (1, 2, 3):
            st, h, body = self.f.get(f"/houses/{n}")
            H = hdrs(h)
            self.assertEqual(st, 200)
            self.assertEqual(H["content-security-policy"], [BASE_CSP], n)   # client script off: base policy
            self.assertEqual(H["cache-control"], ["no-store"])
            text = body.decode()
            self.assertEqual(re.findall(r"(?i)(?:src|href)=\"(?:https?:)?//", text), [], n)
            scripts = re.findall(r"<script[^>]*>", text)
            self.assertEqual(scripts, ['<script src="/static/house3.js" defer>'] if n == 3 else [], n)
            self.assertEqual("px.gif" in text, n >= 2, n)
        st, h, body = self.f.get("/houses/2/px.gif?r=x")
        self.assertEqual((st, hdrs(h)["content-type"][0], body[:6]), (200, "image/gif", b"GIF89a"))
        st, h, body = self.f.get("/houses/3/js-ping")
        self.assertEqual((st, body), (204, b""))
        self.assertEqual(self.f.get("/houses/4")[0], 404)
        js = self.f.get("/static/house3.js")[2].decode()
        self.assertEqual(re.findall(r"(?i)https?://", js), [])
        front = self.f.get("/")[2].decode()
        llms = self.f.get("/llms.txt")[2].decode()
        for n in (1, 2, 3):
            self.assertIn(f'href="/houses/{n}"', front)
            self.assertIn(f"/houses/{n}", llms)


class HouseTiming(unittest.TestCase):
    """The page token ties the image / script ping to the view; the delay since the
    view tells a browser rendering the page from a crawler fetching queued URLs
    later (seen live: ClaudeBot fetched two house pixels ~1 h after the HTML)."""

    @classmethod
    def setUpClass(cls):
        cls.f = f = Instance(rate_read_ip=[100000, 1000.0], rate_log_ip=[100000, 1000.0])
        bot = {"User-Agent": "Mozilla/5.0 (compatible; ExampleCrawler/1.0)"}
        hb = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/140.0 Safari/537.36"}
        tok = {}
        for name, n, ip, h in (("now", 2, CLOUD_V4, {"User-Agent": BROWSER}), ("late", 2, RESIDENTIAL_V4, bot),
                               ("js", 3, RESIDENTIAL_V6, {"User-Agent": BROWSER}), ("jslate", 3, CLOUD_V4, hb)):
            st, _, body = f.get(f"/houses/{n}", ip=ip, headers=h)
            assert st == 200, (name, st)
            tok[name] = (n, ip, h, token_of(body))
        time.sleep(1.2)   # view rows are written by the batching hit writer
        # the crawler's page view and the headless render happened an hour ago
        db = sqlite3.connect(os.path.join(f.dir, "forum.sqlite3"), timeout=10)
        with db:
            for name in ("late", "jslate"):
                db.execute("UPDATE houses SET ts=ts-3600 WHERE token=?", (tok[name][3],))
        db.close()
        for name in ("now", "late"):
            n, ip, h, t = tok[name]
            f.get(f"/houses/{n}/px.gif?r={t}", ip=ip, headers=h)
        for name in ("js", "jslate"):
            n, ip, h, t = tok[name]
            f.get(f"/houses/3/js-ping?r={t}&wd=0", ip=ip, headers=h)
        time.sleep(1.5)
        cls.H = json.loads(f.get("/api/observatory.json?window=24h")[2])["houses"]

    @classmethod
    def tearDownClass(cls):
        cls.f.stop()

    def visitor(self, ip, houses):
        return [v for v in self.H["visitors"] if v["ip"].startswith(ip) and v["houses"] == houses][0]

    def test_immediate_pixel_is_rendered(self):
        v = self.visitor(CLOUD_V4, [2])
        self.assertEqual(v["verdict"], "rendered")
        self.assertLessEqual(v["pixel_delay_s"], 30)

    def test_pixel_an_hour_later_is_crawler_deferred(self):
        v = self.visitor("203.0.113.", [2])
        self.assertEqual(v["verdict"], "fetched image later (crawler)")
        self.assertTrue(v["pixel"])
        self.assertGreaterEqual(v["pixel_delay_s"], 3600)
        self.assertLess(v["pixel_delay_s"], 3700)

    def test_js_ping_ran_js(self):
        v = self.visitor("2001:db8:abcd::", [3])
        self.assertEqual(v["verdict"], "ran JS")
        self.assertLessEqual(v["js_delay_s"], 30)
        late = self.visitor(CLOUD_V4, [3])
        self.assertEqual(late["verdict"], "ran JS later (deferred render)")
        self.assertGreaterEqual(late["js_delay_s"], 3600)

    def test_counts(self):
        H = self.H
        self.assertEqual(H["summary"], {"visitors": 4, "js": 1, "pixel": 1, "js_deferred": 1, "pixel_deferred": 1,
                                        "html_only": 0, "house1_only": 0})
        self.assertEqual((H["pixel_loaded"], H["pixel_in_window"]), ({"2": 2, "3": 0}, {"2": 1, "3": 0}))
        self.assertEqual((H["js_ran"], H["js_in_window"]), (2, 1))

    def test_owner_view_shows_delay(self):
        self.f.ts.idents["127.0.0.10"] = {"login": "owner@github", "name": "laptop", "tags": []}
        st, _, body = self.f.owner("/houses", "127.0.0.10")
        text = body.decode()
        self.assertEqual(st, 200)
        self.assertIn("fetched image later (crawler)", text)
        self.assertIn("ran JS later (deferred render)", text)
        self.assertRegex(text, r"\+1\.0 h \(late\)|\+60 min \(late\)")
        self.assertIn(">rendered<", text)


class RybbitDown(unittest.TestCase):
    def test_requests_unaffected_when_rybbit_is_down(self):
        env = keyfile()
        f = Instance(rybbit_enabled=True, rybbit_url=closed_port_url(), rybbit_site_id="7", rybbit_env_file=env,
                     rybbit_timeout_s=0.5, rate_read_ip=[100000, 1000.0], rate_log_ip=[100000, 1000.0])
        try:
            t0 = time.time()
            for i in range(60):
                st = f.get(f"/houses/{1 + i % 3}", ip=CLOUD_V4)[0]
                self.assertEqual(st, 200)
            self.assertLess(time.time() - t0, 10)
            st = json.loads(f.admin("GET", "/stats")[1])["rybbit"]
            self.assertEqual(st["sent"], 0)
            self.assertGreater(st["failed"] + st["dropped_paused"] + st["dropped_full"], 0)
        finally:
            f.stop()
            os.unlink(env)

    def test_disabled_without_key_or_site(self):
        port = free_port()
        f = Instance(rybbit_enabled=True, rybbit_url=f"http://127.0.0.1:{port}", rybbit_site_id="",
                     rybbit_env_file="/nonexistent.env")
        try:
            st = json.loads(f.admin("GET", "/stats")[1])["rybbit"]
            self.assertEqual(st, {"enabled": False, "why": "no rybbit_site_id"})
        finally:
            f.stop()


class ClientScript(unittest.TestCase):
    """rybbit_client_script: Rybbit's browser script on house 3 only, CSP widened
    for that one origin on that one page, and never for the owner's networks."""

    def test_csp_only_on_house3_and_not_for_owner(self):
        fake = FakeRybbit()
        env = keyfile()
        f = Instance(rybbit_enabled=True, rybbit_url=fake.url, rybbit_site_id="7", rybbit_env_file=env,
                     rybbit_client_script=True, rybbit_public_url="https://stats.example", exclude_asns=[64502])
        try:
            st, h, body = f.get("/houses/3", ip=CLOUD_V4)
            csp = hdrs(h)["content-security-policy"][0]
            self.assertEqual(csp, BASE_CSP.replace("script-src 'self'", "script-src 'self' https://stats.example")
                             .replace("connect-src 'self'", "connect-src 'self' https://stats.example"))
            self.assertIn(b'src="https://stats.example/api/script.js" data-site-id="7"', body)
            # the next response on any page is back to the base policy
            for u in ("/houses/1", "/houses/2", "/", "/observatory"):
                self.assertEqual(hdrs(f.get(u, ip=CLOUD_V4)[1])["content-security-policy"], [BASE_CSP], u)
            st, h, body = f.get("/houses/3", ip=COLOMBIA_V4)   # owner network: no third-party script
            self.assertEqual(hdrs(h)["content-security-policy"], [BASE_CSP])
            self.assertNotIn(b"stats.example", body)
        finally:
            f.stop()
            fake.stop()
            os.unlink(env)


if __name__ == "__main__":
    unittest.main()
