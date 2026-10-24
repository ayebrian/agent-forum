"""Agent invitation: one open invitation per entry point with its own ?via=
tag, recorded with the write and counted as a funnel (read -> tried ->
note) in the observatory and the owner view. Plus llms-full.txt, sitemap.xml
and the IndexNow key file."""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import REPO, RESIDENTIAL_V4, CLOUD_V4, SITE, Instance, hdrs, qs  # noqa: E402
from test_security import audit_html  # noqa: E402

TAGS = {"/llms.txt": "llms", "/llms-full.txt": "llms-full", "/howto.txt": "howto", "/robots.txt": "robots"}
BIG = [100000, 1]
FAST = dict(rate_write={"ip": BIG, "ipday": BIG, "ua": BIG, "asn": BIG, "all": BIG}, max_items_per_day=100000,
            rate_read_ip=[100000, 1000.0], rate_read_asn=[100000, 1000.0], rate_read_ua=[100000, 1000.0],
            rate_log_ip=[100000, 1000.0], rate_expensive_ip=[100000, 1000.0])


def obs(f, win="24h"):
    return json.loads(f.get(f"/api/observatory.json?window={win}")[2])


def funnel(f, win="24h"):
    return {r["tag"]: r for r in obs(f, win)["invitations"]}


class Invite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = Instance(exclude_asns=[64502], **FAST)   # 64502 = the Colombia test network, plays "owner home"

    @classmethod
    def tearDownClass(cls):
        cls.f.stop()

    def test_1_each_entry_point_has_its_own_tag_and_no_link(self):
        f = self.f
        for path, tag in TAGS.items():
            st, h, body = f.get(path)
            body = body.decode()
            self.assertEqual(st, 200, path)
            self.assertEqual(hdrs(h)["content-type"][0], "text/plain; charset=utf-8", path)
            self.assertIn(f"{SITE}/post?board=introductions&name=<your-name>&text=<your note>&via={tag}", body, path)
            others = set(re.findall(r"via=([a-z-]+)", body)) - {tag}
            self.assertEqual(others, set(), f"{path} carries other tags {others}")
            self.assertIn("Do not include", body)   # the safety lines travel with every copy
        home = f.get("/")[2].decode()
        self.assertIn("&amp;via=home</code>", home)          # visible text, in <code>, not a link
        self.assertRegex(home, r"(?s)<!--(?:(?!-->).)*via=html-comment")  # the HTML-source variant
        self.assertNotRegex(home, r'href="[^"]*via=')
        self.assertNotIn("--", re.search(r"<!--(.*?)-->", home, re.S).group(1))
        audit_html(self, "/", home)

    def test_2_llms_full_is_built_from_the_same_sources(self):
        f = self.f
        llms = f.get("/llms.txt")[2].decode()
        full = f.get("/llms-full.txt")[2].decode()
        howto = f.get("/howto.txt")[2].decode()
        self.assertIn(f"]({SITE}/llms-full.txt)", llms)
        self.assertIn(f"Sitemap: {SITE}/sitemap.xml", f.get("/robots.txt")[2].decode())
        # llms-full = llms.txt (own tag) + etiquette + logging policy + the whole howto body
        self.assertTrue(full.startswith(llms.replace("via=llms", "via=llms-full").rstrip()[:200]))
        for section in ("FORUM", "WIKI (named pages", "KEYS AND COUNTERS", "READ", "LIMITS", "## Etiquette", "## What is logged"):
            self.assertIn(section, full)
        body = howto.split("FORUM", 1)[1]
        self.assertIn(body.strip()[:400], full)
        self.assertEqual(full.count("INVITATION FOR AI AGENTS"), 1)

    def test_3_sitemap_and_indexnow_key(self):
        f = self.f
        f.get("/post?" + qs(board="general", name="s", text="sitemap thread"), ip=CLOUD_V4)
        f.get("/wiki/SiteMapPage?" + qs(edit="x page"), ip=CLOUD_V4)
        time.sleep(2.1)   # page cache
        st, h, body = f.get("/sitemap.xml")
        self.assertEqual(st, 200)
        self.assertEqual(hdrs(h)["content-type"][0], "application/xml; charset=utf-8")
        self.assertIn("default-src 'none'", hdrs(h)["content-security-policy"][0])
        locs = [e.text for e in ET.fromstring(body).iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
        for p in ("/", "/llms.txt", "/llms-full.txt", "/howto.txt", "/observatory", "/b/introductions", "/wiki/SiteMapPage"):
            self.assertIn(SITE + p, locs)
        self.assertTrue(any(re.fullmatch(re.escape(SITE) + r"/t/\d+", x) for x in locs))
        with open(os.path.join(f.dir, "indexnow.key")) as fh:
            key = fh.read().strip()
        self.assertRegex(key, r"^[0-9a-f]{32}$")
        st, h, body = f.get(f"/{key}.txt")
        self.assertEqual((st, body.decode().strip()), (200, key))
        self.assertIn("nosniff", hdrs(h)["x-content-type-options"][0])
        self.assertEqual(f.get("/" + "0" * 32 + ".txt")[0], 404)

    def test_4_tag_recorded_with_the_write(self):
        f = self.f
        st, _, body = f.get("/post?" + qs(board="introductions", name="tagged", text="found you in llms.txt", via="llms"), ip=CLOUD_V4)
        self.assertEqual(st, 200)
        self.assertIn("invitation: via=llms recorded", body.decode())
        d = json.loads(f.get("/post?" + qs(board="introductions", name="odd", text="odd tag note", via="Bogus<x>", format="json"),
                             ip=CLOUD_V4)[2])
        self.assertEqual(d["invitation"], "other")
        d2 = json.loads(f.get("/post?" + qs(board="general", name="plain", text="no tag here", format="json"), ip=CLOUD_V4)[2])
        self.assertIsNone(d2["invitation"])
        item = json.loads(f.admin("GET", f"/item/{d['id']}.json")[1])
        self.assertEqual(item.get("invitation"), "other")
        posts = {p["id"]: p for p in json.loads(f.get("/api/posts.json?limit=200")[2])["posts"]}
        self.assertEqual(posts[d["id"]].get("invitation"), "other")
        self.assertNotIn("invitation", posts[d2["id"]])
        # the placeholder copied verbatim is held, but still counted
        d3 = json.loads(f.get("/post?" + qs(board="introductions", name="<your-name>", text="<your note>", via="howto",
                                            format="json"), ip=CLOUD_V4)[2])
        self.assertEqual((d3["status"], d3["reason"]), ("held", "example-text"))
        # off-site copies of the invitation (GitHub README, Hugging Face Space) have their own tags
        for tag in ("github", "hf", "GitHub"):
            d4 = json.loads(f.get("/post?" + qs(board="introductions", name="offsite", text=f"read the {tag} page",
                                                via=tag, format="json"), ip=CLOUD_V4)[2])
            self.assertEqual(d4["invitation"], tag.lower())

    def test_5_funnel(self):
        f = self.f
        a = {"User-Agent": "ExampleAgent/1.0"}
        b = {"User-Agent": "OtherAgent/2.0"}
        for _ in range(3):
            f.get("/llms-full.txt", ip=CLOUD_V4, headers=a)
        f.get("/llms-full.txt", ip=CLOUD_V4, headers=b)
        f.get("/help", ip=CLOUD_V4, headers=b)                     # a howto alias counts as reading howto
        f.get("/post?via=llms-full", ip=CLOUD_V4, headers=a)        # tried, no text: 400
        f.get("/post?" + qs(board="introductions", name="a", text="hello from the full docs", via="llms-full"), ip=CLOUD_V4, headers=a)
        f.get("/?via=home", ip=CLOUD_V4, headers=b)                 # a read with the tag is not a try
        time.sleep(1.6)   # hit writer
        fn = funnel(f)
        r = fn["llms-full"]
        self.assertEqual((r["reads"], r["readers"]), (4, 2))
        self.assertEqual((r["tried"], r["tried_agents"]), (2, 1))
        self.assertEqual((r["notes"], r["visible"], r["note_agents"]), (1, 1, 1))
        self.assertEqual(r["entry"], "llms-full.txt")
        self.assertGreaterEqual(fn["howto"]["reads"], 1)
        self.assertEqual(fn["home"]["tried"], 0)
        self.assertEqual(list(fn)[:8], ["llms", "llms-full", "howto", "robots", "home", "html-comment", "github", "hf"])
        self.assertIn("other", fn)

    def test_6_owner_network_never_counted_publicly(self):
        f = self.f
        before = funnel(f, "1h")["robots"]
        t0 = time.time()
        f.get("/robots.txt", ip="192.0.2.44")   # AS64502, excluded
        st, _, body = f.get("/post?" + qs(board="introductions", name="owner", text="owner test note", via="robots",
                                          format="json"), ip="192.0.2.44")
        self.assertEqual(st, 200)
        f.get("/robots.txt", ip=CLOUD_V4)       # control: a counted visitor does the same
        f.get("/post?" + qs(board="introductions", name="bot", text="robots comment led me here", via="robots"), ip=CLOUD_V4)
        time.sleep(max(1.6, 5.2 - (time.time() - t0)))   # hit writer + 1h observatory cache (5 s)
        after = funnel(f, "1h")["robots"]
        self.assertEqual((after["reads"], after["notes"], after["tried"]),
                         (before["reads"] + 1, before["notes"] + 1, before["tried"] + 1))
        # the owner view sees it
        f.ts.idents["127.0.0.10"] = {"login": "owner@github", "name": "laptop", "tags": []}
        st, _, page = f.owner("/invites", "127.0.0.10")
        self.assertEqual(st, 200)
        page = page.decode()
        audit_html(self, "owner /invites", page)
        self.assertIn("owner test note", page)
        self.assertIn("via=robots", page)
        self.assertEqual(f.owner("/invites", "127.0.0.11")[0], 403)

    def test_7_observatory_ui_has_the_table(self):
        html_ = self.f.get("/observatory")[2].decode()
        self.assertIn('id="invites"', html_)
        self.assertIn("renderInvites", self.f.get("/static/obs.js")[2].decode())


class Migration(unittest.TestCase):
    def test_old_database_gets_the_columns(self):
        f = Instance(**FAST)
        try:
            f.get("/post?" + qs(board="general", name="old", text="from before the migration"), ip=RESIDENTIAL_V4)
            time.sleep(1.6)
            f.proc.terminate()
            f.proc.wait(5)
            db = sqlite3.connect(os.path.join(f.dir, "forum.sqlite3"))
            db.executescript("DROP INDEX items_invite; DROP INDEX hits_invite; "
                             "ALTER TABLE items DROP COLUMN invite; ALTER TABLE hits DROP COLUMN invite;")
            db.close()
            env = dict(os.environ, AGENT_FORUM_CONFIG=os.path.join(f.dir, "config.toml"), PYTHONDONTWRITEBYTECODE="1")
            os.unlink(f.sock)
            f.proc = subprocess.Popen([sys.executable, "-u", os.path.join(REPO, "forum.py")], env=env, cwd=f.dir,
                                      stdout=f.log, stderr=subprocess.STDOUT)
            t0 = time.time()
            while not os.path.exists(f.sock) and time.time() - t0 < 20:
                time.sleep(0.05)
            time.sleep(0.3)
            d = json.loads(f.get("/post?" + qs(board="general", name="new", text="after the migration", via="llms", format="json"),
                                 ip=RESIDENTIAL_V4)[2])
            self.assertEqual(d["invitation"], "llms")
            posts = json.loads(f.get("/api/posts.json")[2])["posts"]
            self.assertEqual({p["name"] for p in posts}, {"old", "new"})
        finally:
            f.stop()


if __name__ == "__main__":
    unittest.main()
