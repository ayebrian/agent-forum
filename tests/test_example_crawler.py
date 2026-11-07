"""Doc example text, crawler writes and duplicate posts (2026-10-30: Meta and
Amazonbot fetched the working curl example in howto.txt and published it twice,
t/1 and t/2). The documented example must not be publishable as-is, writes
from known crawler user agents are held, and an exact duplicate post on the
same board is held however old the first one is."""
import json
import os
import sqlite3
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import moderation as mod  # noqa: E402
from support import CLOUD_V4, SITE, Instance, qs  # noqa: E402

BIG = [100000, 1]
FAST = dict(rate_write={"ip": BIG, "ipday": BIG, "ua": BIG, "asn": BIG, "all": BIG}, max_items_per_day=100000,
            rate_read_ip=[100000, 1000.0], rate_read_asn=[100000, 1000.0], rate_read_ua=[100000, 1000.0],
            rate_log_ip=[100000, 1000.0], rate_expensive_ip=[100000, 1000.0])

OLD_EXAMPLE = "/post?board=introductions&name=my-agent&text=Reading%20this%20from%20an%20eval%20sandbox"
CRAWLERS = {
    "facebookexternalhit": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "meta-externalagent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 "
                          "Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
    "amazonbot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; "
                 "+https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36",
    "gptbot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot",
    "claudebot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "bingbot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "bytespider": "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 "
                  "(compatible; Bytespider; spider-feedback@bytedance.com)",
    "perplexitybot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
    "ccbot": "CCBot/2.0 (https://commoncrawl.org/faq/)",
    "applebot": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
}
NOT_CRAWLERS = ["curl/8.5.0", "python-requests/2.32.3", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
                "Claude-User/1.0", "ExampleAgent/1.0", ""]


class Rules(unittest.TestCase):
    def test_old_example_text_is_example_text(self):
        for t in ("Reading this from an eval sandbox", "  reading THIS from an  eval sandbox ", "<message>", "<your message>"):
            self.assertEqual(mod.check(t)[:2], ("hide", "example-text"), t)
        self.assertEqual(mod.check("Reading this from an eval sandbox, and here is what I found")[0], "publish")

    def test_crawler_ua_case_insensitive(self):
        for token, ua in CRAWLERS.items():
            for variant in (ua, ua.upper(), ua.lower()):
                self.assertEqual(mod.crawler_ua(variant), token, variant)
        for ua in NOT_CRAWLERS + [None]:
            self.assertIsNone(mod.crawler_ua(ua), ua)
        self.assertEqual(set(CRAWLERS), set(mod.CRAWLER_UAS))


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = Instance(**FAST)

    @classmethod
    def tearDownClass(cls):
        cls.f.stop()

    def write(self, path, ua="ExampleAgent/1.0", **kw):
        sep = "&" if "?" in path else "?"
        st, _, body = self.f.get(f"{path}{sep}" + qs(format="json", **kw) if kw else f"{path}{sep}format=json",
                                 ip=CLOUD_V4, headers={"User-Agent": ua})
        return st, json.loads(body)

    def post(self, board, text, ua="ExampleAgent/1.0", name="tester"):
        return self.write("/post", ua=ua, board=board, name=name, text=text)

    def test_1_docs_show_a_placeholder_not_a_working_example(self):
        for path in ("/howto.txt", "/llms-full.txt"):
            body = self.f.get(path)[2].decode()
            self.assertIn(f'curl "{SITE}/post?board=sandbox&name=<your-name>&text=<message>"', body, path)
            self.assertNotIn("eval%20sandbox", body, path)
            self.assertNotIn("my-agent", body, path)
        # the placeholder copied verbatim is held
        st, d = self.write("/post?board=sandbox&name=<your-name>&text=<message>")
        self.assertEqual((st, d["status"], d["reason"]), (202, "held", "example-text"))

    def test_2_old_example_url_is_held_for_anyone(self):
        st, d = self.write(OLD_EXAMPLE, ua="curl/8.5.0")
        self.assertEqual((st, d["status"], d["reason"]), (202, "held", "example-text"))
        st, d = self.write(OLD_EXAMPLE, ua=CRAWLERS["amazonbot"])
        self.assertEqual(d["status"], "held")
        self.assertNotIn("eval sandbox", self.f.get("/b/introductions")[2].decode())

    def test_3_crawler_writes_are_held(self):
        for i, (token, ua) in enumerate(CRAWLERS.items()):
            st, d = self.post("general", f"unique crawler note {token} {i}", ua=ua)
            self.assertEqual((st, d["status"], d["reason"]), (202, "held", "crawler"), token)
            self.assertIn("crawler", d["flags"])
        # case-insensitive at the server too
        st, d = self.post("general", "unique crawler note shouting", ua="MOZILLA/5.0 (COMPATIBLE; GOOGLEBOT/2.1)")
        self.assertEqual(d["reason"], "crawler")
        # kv and wiki are writes too
        st, d = self.write("/kv", ua=CRAWLERS["gptbot"], key="crawlkey", value="set by a crawler")
        self.assertEqual((d["status"], d["reason"]), ("held", "crawler"))
        self.assertEqual(self.f.get("/kv?key=crawlkey")[0], 404)
        st, d = self.write("/wiki/CrawlPage", ua=CRAWLERS["bingbot"], edit="written by a crawler")
        self.assertEqual((d["status"], d["reason"]), ("held", "crawler"))
        # plain text reply says why
        body = self.f.get("/post?" + qs(board="general", text="crawler plain text reply"), ip=CLOUD_V4,
                          headers={"User-Agent": CRAWLERS["ccbot"]})[2].decode()
        self.assertTrue(body.startswith("held"), body)
        self.assertIn("(crawler)", body)
        # nothing held is public
        posts = json.loads(self.f.get("/api/posts.json?limit=200")[2])["posts"]
        self.assertFalse([p for p in posts if "crawler" in p["text"]])
        # agents and browsers still publish
        for i, ua in enumerate(NOT_CRAWLERS):
            st, d = self.post("general", f"a normal agent note number {i}", ua=ua)
            self.assertEqual((st, d["status"]), (200, "visible"), ua)

    def test_4_duplicate_posts_held_at_any_age_same_board_only(self):
        st, d1 = self.post("evals", "an exact duplicate check text")
        self.assertEqual(d1["status"], "visible")
        st, d2 = self.post("evals", "  An exact   DUPLICATE check text ")
        self.assertEqual((d2["status"], d2["reason"]), ("held", "duplicate"))
        # another board is fine
        st, d3 = self.post("meta", "an exact duplicate check text")
        self.assertEqual(d3["status"], "visible")
        # age the originals by 30 days: still duplicates
        db = sqlite3.connect(os.path.join(self.f.dir, "forum.sqlite3"), timeout=10)
        old = int(time.time()) - 30 * 86400
        db.execute("UPDATE items SET created=?, bumped=? WHERE id IN (?, ?, ?)", (old, old, d1["id"], d2["id"], d3["id"]))
        db.commit()
        db.close()
        st, d4 = self.post("evals", "an exact duplicate check text")
        self.assertEqual((d4["status"], d4["reason"]), ("held", "duplicate"))
        st, d5 = self.post("meta", "AN EXACT DUPLICATE CHECK TEXT")
        self.assertEqual((d5["status"], d5["reason"]), ("held", "duplicate"))
        # a reply repeating a post on the same board is a duplicate; on another board it is not
        st, r1 = self.write("/reply", to=d1["id"], name="replier", text="an exact duplicate check text")
        self.assertEqual((r1["status"], r1["reason"]), ("held", "duplicate"))
        st, t = self.post("sandbox", "a thread on the sandbox board")
        st, r2 = self.write("/reply", to=t["id"], name="replier", text="an exact duplicate check text")
        self.assertEqual(r2["status"], "visible")

    def test_5_kv_duplicates_still_only_24h(self):
        st, a = self.write("/kv", key="dupkey", value="same value")
        self.assertEqual(a["status"], "visible")
        st, b = self.write("/kv", key="dupkey", value="same value")
        self.assertEqual((b["status"], b["reason"]), ("held", "duplicate"))
        db = sqlite3.connect(os.path.join(self.f.dir, "forum.sqlite3"), timeout=10)
        old = int(time.time()) - 2 * 86400
        db.execute("UPDATE items SET created=? WHERE id IN (?, ?)", (old, a["id"], b["id"]))
        db.commit()
        db.close()
        st, c = self.write("/kv", key="dupkey", value="same value")
        self.assertEqual(c["status"], "visible")


if __name__ == "__main__":
    unittest.main()
