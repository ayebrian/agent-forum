"""IP -> network / crawler attribution: accuracy rules ("labels must match
reality").

Offline part (always runs): synthetic data in a temp dir.
Live part (opt-in): real, freshly fetched data.
    AGENT_FORUM_LIVE_DATA=<dir with netdata files>   e.g. after
        python3 tools/fetch_data.py /tmp/net-live
    AGENT_FORUM_LIVE_NET=1   also asks Team Cymru's whois (bulk, test IPs only)
                             as a third, independent oracle.
No visitor IPs are used anywhere: crawler/cloud IPs come from the operators'
own published lists, residential ones are base addresses of large ISP
aggregates (not observed hosts).
"""
import ipaddress
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netintel  # noqa: E402
from support import Instance, write_net_data  # noqa: E402

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
CLAUDEBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
BYTESPIDER = "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider)"

# benchmarking range 198.18.0.0/15 (RFC 2544) for the extra synthetic cases
DISPUTED = "198.18.0.10"      # iptoasn says AS64503, RIS says AS64504
HOSTY = "198.18.1.10"         # both agree on AS64505 "BESTHOST-VPS Servers": hosting words, not curated
ONE_SOURCE = "198.18.2.10"    # only iptoasn knows it
RENAMED = "198.18.3.10"       # AS24940 per both sources, but the registry says a different holder
BOT_V4 = "198.18.4.10"        # in a fake operator list "openai-gptbot"
SAME_ORG = "198.18.5.10"      # iptoasn AS64509, RIS AS64510: two ASNs of one holder
# third source, DB-IP (2026-10-24): 2 of 3 decide
MAJ_AC = "198.18.6.10"        # iptoasn AS64511 + DB-IP AS64511 vs RIS AS64512 -> AS64511, RIS outvoted
MAJ_BC = "198.18.7.10"        # RIS AS64514 + DB-IP AS64514 vs iptoasn AS64513 -> AS64514, iptoasn outvoted
SPLIT3 = "198.18.8.10"        # AS64515 / AS64516 / AS64517: all three differ
MOAS = "198.18.9.10"          # RIS sees AS64520 and AS64521; iptoasn names 64521, DB-IP 64520
EXTRA_ASN = [("198.18.0.0", "198.18.0.255", 64503, "ZZ", "ALPHA-NET - Alpha Net"),
             ("198.18.1.0", "198.18.1.255", 64505, "ZZ", "BESTHOST-VPS - Besthost VPS Servers"),
             ("198.18.2.0", "198.18.2.255", 64506, "ZZ", "SOLO-NET - Solo Net"),
             ("198.18.3.0", "198.18.3.255", 24940, "DE", "HETZNER-AS - Hetzner Online GmbH"),
             ("198.18.4.0", "198.18.4.255", 64507, "ZZ", "BOTHOST - Bot Host Servers"),
             ("198.18.5.0", "198.18.5.255", 64509, "ZZ", "EXCABLE-1 - Example Cable Co"),
             ("198.18.6.0", "198.18.6.255", 64511, "ZZ", "GAMMA-NET - Gamma Net"),
             ("198.18.7.0", "198.18.7.255", 64513, "ZZ", "EPSILON-NET - Epsilon Net"),
             ("198.18.8.0", "198.18.8.255", 64515, "ZZ", "ETA-NET - Eta Net"),
             ("198.18.9.0", "198.18.9.255", 64521, "ZZ", "MU-NET - Mu Net")]
EXTRA_RIS = [(64504, "198.18.0.0/24", 300), (64505, "198.18.1.0/24", 300), (24940, "198.18.3.0/24", 300),
             (64507, "198.18.4.0/24", 300), (64508, "198.18.2.0/24", 2),   # 2 peers = noise, ignored
             (64510, "198.18.5.0/24", 300), (64512, "198.18.6.0/24", 300), (64514, "198.18.7.0/24", 300),
             (64516, "198.18.8.0/24", 300), (64520, "198.18.9.0/24", 320), (64521, "198.18.9.0/24", 300)]
EXTRA_NAMES = {64503: "ALPHA-NET - Alpha Net, ZZ", 64504: "BETA-NET - Beta Net, ZZ", 64505: "BESTHOST-VPS - Besthost VPS Servers, ZZ",
               64506: "SOLO-NET - Solo Net, ZZ", 24940: "PIZZA-AS Totally Different Pizza Ltd, ZZ", 64507: "BOTHOST - Bot Host Servers, ZZ",
               64509: "EXCABLE-1 - Example Cable Co, ZZ", 64510: "EXCABLE-2 - Example Cable Co, ZZ",
               64511: "GAMMA-NET - Gamma Net, ZZ", 64512: "DELTA-NET - Delta Net, ZZ", 64513: "EPSILON-NET - Epsilon Net, ZZ",
               64514: "ZETA-NET - Zeta Net, ZZ", 64515: "ETA-NET - Eta Net, ZZ", 64516: "THETA-NET - Theta Net, ZZ",
               64517: "IOTA-NET - Iota Net, ZZ", 64520: "LAMBDA-NET - Lambda Net, ZZ", 64521: "MU-NET - Mu Net, ZZ"}
# DB-IP rows (organisation names, no handles, like the real file). DISPUTED,
# ONE_SOURCE, RENAMED and SAME_ORG are deliberately absent: two-source cases.
DBIP_ROWS = [("203.0.113.0", "203.0.113.255", 64500, "Example Residential Broadband"),
             ("198.51.100.0", "198.51.100.255", 64501, "Example Hosting Cloud Servers"),
             ("198.18.1.0", "198.18.1.255", 64505, "Besthost VPS Servers"),
             ("198.18.6.0", "198.18.6.255", 64511, "Gamma Net"),
             ("198.18.7.0", "198.18.7.255", 64514, "Zeta Net"),
             ("198.18.8.0", "198.18.8.255", 64517, "Iota Net"),
             ("198.18.9.0", "198.18.9.255", 64520, "Lambda Net")]


def make_net(**kw):
    from support import ASN_ROWS, AS_NAMES, RIS_ROWS
    d = tempfile.mkdtemp(prefix="aft-net-")
    kw.setdefault("dbip_rows", DBIP_ROWS)
    write_net_data(d, asn_rows=ASN_ROWS + EXTRA_ASN, ris_rows=RIS_ROWS + EXTRA_RIS, names={**AS_NAMES, **EXTRA_NAMES},
                   ranges={"openai-gptbot": ["198.18.4.0/28"]}, **kw)
    ni = netintel.NetIntel(d)
    ni.load()
    return ni, d


class Offline(unittest.TestCase):
    def setUp(self):
        self.ni, self.dir = make_net()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_longest_prefix_match(self):
        iv = netintel.Intervals.build([(4, *netintel._net_range(c)[1:], lab) for c, lab in
                                       [("10.0.0.0/8", "a"), ("10.1.0.0/16", "b"), ("10.1.2.0/24", "c"), ("10.1.2.128/25", "d"),
                                        ("11.0.0.0/8", "e")]])
        cases = {"10.0.0.1": "a", "10.1.0.1": "b", "10.1.2.1": "c", "10.1.2.200": "d", "10.1.3.0": "b", "10.255.255.255": "a",
                 "11.5.5.5": "e", "12.0.0.1": None, "9.255.255.255": None}
        for ip, want in cases.items():
            self.assertEqual(iv.get(ip), want, ip)

    def test_agreeing_sources_give_a_confident_name(self):
        d = self.ni.describe_ip("203.0.113.77")
        self.assertEqual((d["asn"], d["kind"], d["status"]), (64500, "isp", "verified"))
        self.assertEqual(d["label"], "Example Residential Broadband (ISP)")

    def test_published_cloud_range_is_confirmed_cloud(self):
        d = self.ni.describe_ip("198.51.100.20")
        self.assertEqual((d["kind"], d["status"], d["label"]), ("cloud", "verified", "Example Cloud"))

    def test_disagreement_is_unverified_never_a_name(self):
        d = self.ni.describe_ip(DISPUTED)
        self.assertEqual((d["asn"], d["kind"], d["status"]), (None, "unknown", "unverified"))
        self.assertNotIn("Alpha", d["label"])
        self.assertNotIn("Beta", d["label"])
        self.assertIn("disagree", d["label"])

    def test_two_asns_of_one_holder_still_agree(self):
        d = self.ni.describe_ip(SAME_ORG)
        self.assertEqual((d["asn"], d["status"], d["label"]), (64510, "verified", "Example Cable Co (ISP)"))

    def test_single_source_is_unverified(self):
        d = self.ni.describe_ip(ONE_SOURCE)   # the RIS row is seen by 2 peers only -> ignored
        self.assertEqual((d["asn"], d["status"]), (None, "unverified"))
        self.assertTrue(d["label"].endswith("(unverified)"))

    def test_hosting_words_alone_are_not_cloud(self):
        d = self.ni.describe_ip(HOSTY)
        self.assertEqual(d["kind"], "hosting")
        self.assertIn("unverified", d["label"])

    def test_curated_name_dropped_when_registry_disagrees(self):
        d = self.ni.describe_ip(RENAMED)   # AS24940 = "Hetzner" in PROVIDERS, but the registry says pizza
        self.assertNotIn("Hetzner", d["label"])
        self.assertNotEqual(d["kind"], "cloud")
        self.assertEqual(d["status"], "unverified")   # iptoasn name and registry name disagree too

    def test_stale_bgp_data_means_unknown(self):
        ni, d = make_net(fetched=time.time() - 5 * 86400)
        try:
            for ip in ("203.0.113.77", RENAMED, DISPUTED):
                r = ni.describe_ip(ip)
                self.assertIsNone(r["asn"], ip)
                self.assertIn(r["status"], ("unknown", "unverified"), ip)
                self.assertNotEqual(r["kind"], "cloud", ip)
            # stale cloud list too (5 d < 14 d limit -> still fresh); force it stale:
            ni.meta["cloud:Example Cloud"]["fetched"] = time.time() - 30 * 86400
            self.assertNotEqual(ni.describe_ip("198.51.100.20")["kind"], "cloud")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_missing_meta_counts_as_stale(self):
        ni, d = make_net(skip=("ris4",), dbip_rows=None)   # two sources, one without a fetch time
        try:
            self.assertEqual(ni.describe_ip("203.0.113.77")["status"], "unverified")
        finally:
            shutil.rmtree(d, ignore_errors=True)
        ni, d = make_net(skip=("ris4",))   # with DB-IP: iptoasn + DB-IP are still 2 fresh votes that agree
        try:
            r = ni.describe_ip("203.0.113.77")
            self.assertEqual((r["asn"], r["status"]), (64500, "verified"))
            self.assertNotIn("ris", r["votes"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ---- three sources (DB-IP added 2026-10-24)
    def test_two_of_three_iptoasn_and_dbip_outvote_ris(self):
        d = self.ni.describe_ip(MAJ_AC)
        self.assertEqual((d["asn"], d["status"], d["label"]), (64511, "verified", "Gamma Net (ISP)"))
        self.assertEqual(d["dissent"], [{"source": "ris", "asns": [64512]}])
        self.assertIn("outvoted", d["why"])
        self.assertNotIn("Delta", d["label"])   # the public label shows only the majority

    def test_two_of_three_ris_and_dbip_outvote_iptoasn(self):
        d = self.ni.describe_ip(MAJ_BC)   # name cross-check falls back to DB-IP's organisation name
        self.assertEqual((d["asn"], d["status"], d["label"]), (64514, "verified", "Zeta Net (ISP)"))
        self.assertEqual(d["dissent"], [{"source": "iptoasn", "asns": [64513]}])

    def test_all_three_differ_is_unverified(self):
        d = self.ni.describe_ip(SPLIT3)
        self.assertEqual((d["asn"], d["kind"], d["status"], d["label"]),
                         (None, "unknown", "unverified", "unverified network (sources disagree)"))
        for n in ("Eta", "Theta", "Iota"):
            self.assertNotIn(n, d["label"])
        self.assertEqual(d["dissent"], [])
        self.assertEqual(len(d["votes"]), 3)

    def test_two_origins_seen_by_ris_is_not_a_dissent(self):
        d = self.ni.describe_ip(MOAS)   # both pairs are 2 of 3: iptoasn's pick wins the tie, as before DB-IP
        self.assertEqual((d["asn"], d["status"], d["label"]), (64521, "verified", "Mu Net (ISP)"))
        self.assertEqual(d["dissent"], [])
        self.assertEqual(d["moas"], [{"source": "dbip", "asns": [64520]}])

    def test_three_agree_no_dissent(self):
        d = self.ni.describe_ip("203.0.113.77")
        self.assertEqual(sorted(d["votes"]), ["dbip", "iptoasn", "ris"])
        self.assertEqual(d["dissent"], [])

    def test_stale_dbip_does_not_vote(self):
        # release 50 days old (> 45 d), although fetched just now: the release date counts
        ni, d = make_net(dbip_published=time.time() - 50 * 86400)
        try:
            self.assertFalse(ni.fresh("dbip", "dbip"))
            self.assertFalse(ni.ages()["dbip"]["fresh"])
            r = ni.describe_ip(MAJ_AC)   # back to iptoasn vs RIS, 1:1
            self.assertEqual((r["asn"], r["status"], r["label"]), (None, "unverified", "unverified network (sources disagree)"))
            self.assertNotIn("dbip", r["votes"])
            r = ni.describe_ip("203.0.113.77")   # iptoasn + RIS still agree
            self.assertEqual((r["asn"], r["status"]), (64500, "verified"))
        finally:
            shutil.rmtree(d, ignore_errors=True)
        ni, d = make_net(dbip_published=time.time() - 40 * 86400)   # 40 d: still fresh
        try:
            self.assertEqual(ni.describe_ip(MAJ_AC)["asn"], 64511)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dbip_alone_is_unverified(self):
        ni, d = make_net(dbip_rows=DBIP_ROWS + [("198.18.10.0", "198.18.10.255", 64518, "Kappa Net")])
        try:
            r = ni.describe_ip("198.18.10.10")
            self.assertEqual((r["asn"], r["status"], r["label"]), (None, "unverified", "Kappa Net (unverified)"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dbip_csv_quoting(self):
        ni, d = make_net(dbip_rows=[("198.18.10.0", "198.18.10.255", 64518, 'Kappa, "Net" Inc.')])
        try:
            self.assertEqual(ni.c.names[64518][1], 'Kappa, "Net" Inc.')
            self.assertEqual(ni.c.asn("198.18.10.200"), 64518)
            self.assertIsNone(ni.c.asn("198.18.11.1"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_names_agree(self):
        self.assertTrue(netintel.names_agree("PCN-AS-KR LG HelloVision Corp.", ("PCN-AS-KR-KR", "LG HelloVision Corp.", "KR")))
        self.assertTrue(netintel.names_agree("France Telecom - Orange", ("AS3215", "Orange S.A.", "FR")))
        self.assertFalse(netintel.names_agree("-Reserved AS-", ("ACE-002", "Ace Data Centers II, L.L.C.", "US")))
        common = frozenset({"BEIJING", "COMMUNICATION", "CHINA"})   # frequent words do not count as agreement
        self.assertFalse(netintel.names_agree("HXDNET Beijing haixunda Communication", ("BGTELECOM", "China UNICOM, Beijing Branch", "CN"), common))

    # ---- crawler claims
    def test_published_list_verifies_and_misses_fail(self):
        spec = netintel.classify_ua(GPTBOT)["verify"]
        self.assertEqual(self.ni.verifier.verify(BOT_V4, spec), "range")
        self.assertEqual(self.ni.verifier.verify("198.18.4.200", spec), "spoofed")   # same AS, outside the list

    def test_asn_alone_never_verifies(self):
        self.assertIsNone(netintel.classify_ua(BYTESPIDER)["verify"])
        for _, _, _, _, ver in netintel.UA_RULES:
            for sp in ver or []:
                self.assertTrue(isinstance(sp, str) or sp[0] == "rdns", sp)

    def test_stale_list_is_unverified_not_spoofed(self):
        ni, d = make_net()
        try:
            ni.verifier.fetched["openai-gptbot"] = time.time() - 30 * 86400
            ni.verifier._cache.clear()
            self.assertEqual(ni.verifier.verify(BOT_V4, netintel.classify_ua(GPTBOT)["verify"]), "claimed")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_anthropic_and_mistral_use_their_lists(self):
        self.assertEqual(netintel.classify_ua(CLAUDEBOT)["verify"], ["anthropic-bots"])
        self.assertEqual(netintel.classify_ua("Mozilla/5.0 (compatible; MistralAI-User/1.0)")["verify"], ["mistral-user"])

    def test_claim_wording(self):
        self.assertEqual(netintel.claim_text("GPTBot", "OpenAI", "claimed"), "claims to be OpenAI GPTBot (unverified)")
        self.assertTrue(netintel.claim_text("GPTBot", "OpenAI", "range").startswith("OpenAI GPTBot (verified"))
        self.assertIn("failed", netintel.claim_text("bingbot", "Microsoft", "spoofed"))
        self.assertEqual(netintel.claim_text("ClaudeBot", "Anthropic", "asn"), "claims to be Anthropic ClaudeBot (unverified)")


class PublicDisplay(unittest.TestCase):
    """End to end: what the public observatory shows for each kind of IP."""

    @classmethod
    def setUpClass(cls):
        from support import ASN_ROWS, AS_NAMES, RIS_ROWS
        big = [100000, 1000.0]
        cls.f = Instance(net=dict(asn_rows=ASN_ROWS + EXTRA_ASN, ris_rows=RIS_ROWS + EXTRA_RIS, dbip_rows=DBIP_ROWS,
                                  names={**AS_NAMES, **EXTRA_NAMES}, ranges={"openai-gptbot": ["198.18.4.0/28"]}),
                         rate_read_ip=big, rate_read_asn=big, rate_read_ua=big, rate_read_all=big, rate_log_ip=big,
                         rate_log_all=big, rate_expensive_ip=big)

    @classmethod
    def tearDownClass(cls):
        cls.f.stop()

    def test_only_confirmed_clouds_and_verified_crawlers_in_full(self):
        f = self.f
        for ip in ("203.0.113.77", DISPUTED, HOSTY, ONE_SOURCE, RENAMED, "198.51.100.20", MAJ_AC, SPLIT3):
            f.get("/howto.txt", ip=ip, headers={"User-Agent": "curl/8.5.0"})
        f.get("/howto.txt", ip=BOT_V4, headers={"User-Agent": GPTBOT})            # verified -> full
        f.get("/howto.txt", ip="203.0.113.88", headers={"User-Agent": GPTBOT})    # fake GPTBot from a home ISP
        time.sleep(1.6)
        st, _, body = f.get("/api/observatory.json?window=1h", ip="127.0.0.1")
        self.assertEqual(st, 200)
        obs = body.decode()
        for ip in ("203.0.113.77", "203.0.113.88", DISPUTED, HOSTY, ONE_SOURCE, RENAMED, MAJ_AC, SPLIT3):
            self.assertNotIn(ip, obs, ip)
        self.assertIn("Gamma Net (ISP)", obs)          # 2 vs 1: the majority's name ...
        self.assertNotIn("Delta", obs)                 # ... and no trace of the outvoted one in public
        self.assertNotIn("dissent", obs)
        self.assertIn("198.51.100.20", obs)
        self.assertIn(BOT_V4, obs)
        self.assertNotIn("Hetzner", obs)
        self.assertNotIn("Alpha Net", obs)
        d = json.loads(body)
        claims = {x["claim"] for x in d["tail"] if x.get("claim")}
        self.assertIn("claims to be OpenAI GPTBot (failed: not in OpenAI published ranges / DNS)", claims)
        self.assertTrue(any(c.startswith("OpenAI GPTBot (verified") for c in claims), claims)
        self.assertIn("net_data", d)
        self.assertTrue(all(v["fresh"] for v in d["net_data"].values()), d["net_data"])
        self.assertIn("dbip", d["net_data"])
        self.assertIn("https://db-ip.com", d["attribution"]["dbip"])   # CC BY 4.0 attribution

    def test_observatory_page_credits_dbip(self):
        st, _, body = self.f.get("/observatory", ip="127.0.0.1")
        self.assertEqual(st, 200)
        self.assertIn('<a href="https://db-ip.com">IP Geolocation by DB-IP</a>', body.decode())



class ExcludedAsnHistory(unittest.TestCase):
    """exclude_asns added after rows were logged (owner 2026-10-24): those stored rows stay in the DB but are absent from
    every public view and total."""

    def test_stored_rows_from_excluded_asn_are_not_public(self):
        import sqlite3
        from support import CLOUD_V4, RESIDENTIAL_V4
        big = [100000, 1000.0]
        f = Instance(exclude_asns=[64501], rate_read_ip=big, rate_log_ip=big, rate_log_all=big, rate_expensive_ip=big)
        try:
            f.get("/howto.txt", ip=RESIDENTIAL_V4, headers={"User-Agent": "curl/8.5.0"})    # control: still shown
            f.get("/howto.txt", ip=CLOUD_V4, headers={"User-Agent": "curl/8.5.0"})          # excluded at log time
            time.sleep(1.6)
            now = int(time.time())
            db = sqlite3.connect(os.path.join(f.dir, "forum.sqlite3"), timeout=10)
            with db:   # rows logged before the exclusion existed: stored ASN, and one without (resolved from the IP)
                db.execute("INSERT INTO uas(id, ua, label, kind, first, last, n) VALUES (9001, 'OwnerBrowser/9.9', "
                           "'OwnerBrowser', 'ai', ?, ?, 3)", (now, now))
                for asn in (64501, 64501, None):
                    db.execute("INSERT INTO hits(ts, ip, asn, ua_id, kind, verify, method, path, query, status, bytes, ms) "
                               "VALUES (?, ?, ?, 9001, 'ai', NULL, 'GET', '/secret-owner-path', 'x=1', 200, 10, 1)",
                               (now, CLOUD_V4, asn))
            db.close()
            self.assertEqual(json.loads(f.admin("GET", "/stats")[1])["hits"], 4)   # nothing deleted
            for win in ("1h", "24h", "7d"):
                st, _, body = f.get(f"/api/observatory.json?window={win}", ip="127.0.0.1")
                self.assertEqual(st, 200)
                obs = body.decode()
                for leak in ("198.51.100", "64501", "Example Hosting", "OwnerBrowser", "secret-owner-path"):
                    self.assertNotIn(leak, obs, (win, leak))
                d = json.loads(body)
                self.assertEqual(d["totals"]["requests"], 1, win)
                self.assertEqual(d["totals"]["ips"], 1, win)
                self.assertEqual(d["totals"]["networks"], 1, win)
                self.assertEqual(d["totals"]["ai_requests"], 0, win)
                self.assertEqual(sum(b["ai"] + b["auto"] + b["browser"] for b in d["series"]), 1, win)
                self.assertEqual([n["asn"] for n in d["networks"]], [64500], win)
                self.assertEqual(len(d["tail"]), 1, win)
            self.assertNotIn("OwnerBrowser", f.get("/api/observatory.json?window=1h&ua=9001", ip="127.0.0.1")[2].decode()
                             .split('"focus"')[0])
            front = f.get("/", ip="127.0.0.1")[2].decode()
            self.assertIn("0 requests from 0 AI user agents", front)
            page = f.get("/observatory", ip="127.0.0.1")[2].decode()
            for leak in ("198.51.100", "64501", "OwnerBrowser"):
                self.assertNotIn(leak, page)
        finally:
            f.stop()

# ===================================================================== live

LIVE = os.environ.get("AGENT_FORUM_LIVE_DATA")

# Base addresses of large consumer-ISP aggregates (not observed visitors).
RESIDENTIAL = {"73.0.0.1": 7922, "79.192.0.1": 3320, "90.0.0.1": 3215, "86.128.0.1": 2856, "2003::1": 3320,
               "2601::1": 7922, "95.24.0.1": 8402, "177.0.0.1": None}
# Well-known cloud addresses: provider's own anycast/front-door or block base.
CLOUD = {"88.198.0.1": "Hetzner", "5.9.0.1": "Hetzner", "2a01:4f8::1": "Hetzner", "1.1.1.1": "Cloudflare"}


def first_host(cidr):
    n = ipaddress.ip_network(cidr, strict=False)
    return str(n.network_address + (1 if n.num_addresses > 2 else 0))


def cymru(ips):
    """Team Cymru bulk whois (third oracle): {ip: asn}. Test IPs only."""
    s = socket.create_connection(("whois.cymru.com", 43), timeout=20)
    s.sendall(("begin\nnoheader\n" + "\n".join(ips) + "\nend\n").encode())
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2 and parts[0].isdigit():
            out[parts[1]] = int(parts[0])
    return out


@unittest.skipUnless(LIVE, "set AGENT_FORUM_LIVE_DATA to a freshly fetched data dir")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ni = netintel.NetIntel(LIVE)
        cls.ni.load()
        with open(os.path.join(LIVE, "ranges.json")) as f:
            cls.ranges = json.load(f)
        with open(os.path.join(LIVE, "clouds.json")) as f:
            cls.clouds = json.load(f)
        cls.report = []

    @classmethod
    def tearDownClass(cls):
        if cls.report:
            print("\n" + "\n".join(cls.report), file=sys.stderr)

    def test_data_is_fresh(self):
        for name, a in self.ni.ages().items():
            if name.startswith(("crawler:", "cloud:")) or name in ("iptoasn", "ris4", "ris6", "asnames", "dbip"):
                self.assertTrue(a["fresh"], (name, a))

    def test_curated_names_match_registry(self):
        bad = []
        for asn, (friendly, rx, _) in netintel.PROVIDERS.items():
            reg = self.ni.asnames.get(asn)
            if not reg or not netintel._PROV_RX[asn].search(f"{reg[0]} - {reg[1]}"):
                bad.append((asn, friendly, reg))
        self.assertEqual(bad, [])

    def test_operator_crawler_ranges_verify(self):
        uas = {"openai-gptbot": GPTBOT, "openai-chatgpt-user": "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
               "openai-searchbot": "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
               "googlebot": GOOGLEBOT, "bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
               "anthropic-bots": CLAUDEBOT, "perplexitybot": "Mozilla/5.0 (compatible; PerplexityBot/1.0)",
               "perplexity-user": "Mozilla/5.0 (compatible; Perplexity-User/1.0)", "applebot": "Mozilla/5.0 (compatible; Applebot/0.1)",
               "duckduckbot": "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", "ccbot": "CCBot/2.0 (https://commoncrawl.org/faq/)",
               "mistral-user": "Mozilla/5.0 (compatible; MistralAI-User/1.0)"}
        n = 0
        for src, ua in uas.items():
            spec = netintel.classify_ua(ua)["verify"]
            for c in self.ranges[src][:3]:
                ip = first_host(c)
                self.assertEqual(self.ni.verifier.verify(ip, spec), "range", (src, ip))
                d = self.ni.describe_ip(ip)
                self.assertNotEqual(d["status"], "unknown", (src, ip, d))
                n += 1
        # the same claims from a residential ISP or another cloud are not verified
        for ua in uas.values():
            spec = netintel.classify_ua(ua)["verify"]
            self.assertIn(self.ni.verifier.verify("73.0.0.1", spec), ("spoofed", "claimed", "pending"))
        self.report.append(f"crawler IPs from published lists verified: {n}")

    def test_known_cloud_ips(self):
        sample = dict(CLOUD)
        for prov in ("Amazon AWS", "Google Cloud", "Microsoft Azure", "Oracle Cloud", "DigitalOcean", "Akamai Linode"):
            for c in [x for x in self.clouds[prov] if ":" not in x][:2]:
                sample[first_host(c)] = prov
        for ip, want in sample.items():
            d = self.ni.describe_ip(ip)
            self.assertEqual((d["kind"], d["status"]), ("cloud", "verified"), (ip, d))
            self.assertIn(want.split()[0], d["label"], (ip, d))
        self.report.append(f"cloud IPs confirmed: {len(sample)}")

    def test_residential_prefixes_are_isp_and_masked(self):
        for ip, asn in RESIDENTIAL.items():
            d = self.ni.describe_ip(ip)
            self.assertNotEqual(d["kind"], "cloud", (ip, d))
            if asn:
                self.assertEqual(d["asn"], asn, (ip, d))
                self.assertEqual((d["kind"], d["status"]), ("isp", "verified"), (ip, d))

    def test_dbip_loaded_and_votes(self):
        self.assertGreater(self.ni.c.loaded_rows, 300_000)
        ips = list(RESIDENTIAL) + list(CLOUD)
        for src in ("googlebot", "anthropic-bots", "openai-gptbot"):
            ips += [first_host(c) for c in self.ranges[src][:3]]
        n3 = sum(1 for ip in ips if len(self.ni.describe_ip(ip)["votes"]) == 3)
        agree = sum(1 for ip in ips if self.ni.describe_ip(ip)["asn"] and not self.ni.describe_ip(ip)["dissent"])
        self.report.append(f"DB-IP: {self.ni.c.loaded_rows} rows; {n3}/{len(ips)} test IPs have 3 fresh votes, "
                           f"{agree} confident with no dissent")
        self.assertGreaterEqual(n3, len(ips) - 4)

    @unittest.skipUnless(os.environ.get("AGENT_FORUM_LIVE_NET"), "set AGENT_FORUM_LIVE_NET=1 to ask Team Cymru")
    def test_third_oracle_team_cymru(self):
        ips = list(RESIDENTIAL) + list(CLOUD)
        for c in self.ranges["googlebot"][:2] + self.ranges["anthropic-bots"][:2] + self.ranges["openai-gptbot"][:2]:
            ips.append(first_host(c))
        cy = cymru(ips)
        agree = dis = 0
        for ip in ips:
            d = self.ni.describe_ip(ip)
            if d["asn"] and ip in cy:
                if cy[ip] == d["asn"]:
                    agree += 1
                else:
                    dis += 1
        self.report.append(f"Team Cymru agrees with the consensus ASN for {agree}/{agree + dis} test IPs")
        self.assertEqual(dis, 0)


if __name__ == "__main__":
    unittest.main()
