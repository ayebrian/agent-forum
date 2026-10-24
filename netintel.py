"""Offline network intelligence: who runs an IP (origin ASN, registry name,
cloud or consumer ISP), UA classification and crawler verification.

Nothing here touches the network at request time except reverse DNS for
crawler checks (bounded, and only inside the claimed operator's networks).
Data files in data_dir, refreshed automatically by netdata.fetch_all (see
forum.py net_refresh_hours), each with its fetch time in meta.json:

  ip2asn-combined.tsv.gz   iptoasn.com (PDDL), source A for the origin ASN
  riswhoisdump.IPv4/6.gz   RIPE NCC RIS, source B for the origin ASN
  dbip-asn-lite.csv.gz     DB-IP IP to ASN Lite (CC BY 4.0, attribution: link to
                           db-ip.com), source C, monthly
  asn.txt                  RIPE NCC AS-name list (registry name + country)
  clouds.json              providers' own published IP ranges
  ranges.json              crawler operators' own published IP ranges

Rules (labels must match reality):
  * An IP gets a confident network name only when at least two of the fresh
    sources A, B, C agree on the origin ASN (same ASN, or two ASNs of one
    registry holder) and they are a strict majority of the fresh votes, or
    the IP is in a provider's published ranges. 2 vs 1 -> the majority's
    name, the dissent recorded (owner view). All different, a single source
    or stale data -> "unverified" / "unknown", never a confident wrong name.
    (2026-10-24: C added; before, A and B both had to agree.)
  * "cloud" (full IP shown publicly) only for a provider's published range, or
    a consensus ASN on the curated hosting list whose registry name still
    matches what we expect. Hosting-sounding names alone -> "hosting
    (unverified)", treated like an ISP for IP display.
  * Curated friendly names are used only while the registry still says so.
"""
import array
import bisect
import collections
import concurrent.futures
import csv
import functools
import gzip
import ipaddress
import json
import os
import re
import socket
import threading
import time

# ------------------------------------------------------------- curated ASNs
# asn: (friendly name, regex the current registry name must match, hosting?)
# A curated name whose registry entry no longer matches is NOT used (the ASN
# may have been sold or renumbered): we fall back to the registry's own name.
# Checked against RIPE asn.txt 2026-10-23; tests/test_netintel.py re-checks.
PROVIDERS = {
    16509: ("Amazon AWS", r"AMAZON", True), 14618: ("Amazon AWS", r"AMAZON", True), 8987: ("Amazon AWS", r"AMAZON", True),
    15169: ("Google", r"GOOGLE", True), 396982: ("Google Cloud", r"GOOGLE", True), 19527: ("Google", r"GOOGLE", True),
    36040: ("Google (YouTube)", r"YOUTUBE|GOOGLE", True),
    139070: ("Google", r"GOOGLE", True),
    8075: ("Microsoft Azure", r"MICROSOFT", True), 8068: ("Microsoft", r"MICROSOFT", True),
    8069: ("Microsoft", r"MICROSOFT", True), 3598: ("Microsoft", r"MICROSOFT", True),
    24940: ("Hetzner", r"HETZNER", True), 213230: ("Hetzner Cloud", r"HETZNER", True), 212317: ("Hetzner Cloud", r"HETZNER", True),
    16276: ("OVHcloud", r"\bOVH\b", True), 35540: ("OVHcloud", r"\bOVH", True),
    14061: ("DigitalOcean", r"DIGITALOCEAN", True), 63949: ("Akamai Linode", r"AKAMAI|LINODE", True),
    20940: ("Akamai", r"AKAMAI", True), 16625: ("Akamai", r"AKAMAI", True), 36183: ("Akamai", r"AKAMAI", True),
    35994: ("Akamai", r"AKAMAI", True), 32787: ("Akamai (Prolexic)", r"PROLEXIC|AKAMAI", True), 13335: ("Cloudflare", r"CLOUDFLARE", True), 14789: ("Cloudflare", r"CLOUDFLARE", True),
    395747: ("Cloudflare", r"CLOUDFLARE", True), 209242: ("Cloudflare", r"CLOUDFLARE", True),
    31898: ("Oracle Cloud", r"ORACLE", True), 45102: ("Alibaba Cloud", r"ALIBABA", True), 37963: ("Alibaba Cloud", r"ALIBABA", True),
    132203: ("Tencent Cloud", r"TENCENT", True), 45090: ("Tencent Cloud", r"TENCENT", True),
    20473: ("Vultr", r"VULTR|CONSTANT COMPANY", True), 51167: ("Contabo", r"CONTABO", True), 40021: ("Contabo", r"CONTABO", True),
    12876: ("Scaleway", r"SCALEWAY", True), 60781: ("Leaseweb", r"LEASEWEB", True), 28753: ("Leaseweb", r"LEASEWEB", True),
    32613: ("Leaseweb Canada", r"LEASEWEB|IWEB", True), 9009: ("M247", r"M247", True),
    32934: ("Meta", r"FACEBOOK|META", True), 714: ("Apple", r"APPLE", True), 6185: ("Apple", r"APPLE", True),
    13238: ("Yandex", r"YANDEX", True), 208722: ("Nebius", r"NEBIUS", True),
    55967: ("Baidu", r"BAIDU", True), 38365: ("Baidu", r"BAIDU", True),
    396986: ("ByteDance", r"BYTEDANCE", True), 138699: ("ByteDance (TikTok)", r"TIKTOK|BYTEDANCE", True),
    137718: ("ByteDance (Volcano Engine)", r"VOLCANO|BYTEDANCE", True), 54113: ("Fastly", r"FASTLY", True),
    36352: ("HostPapa (ColoCrossing)", r"COLOCROSSING|HOSTPAPA", True), 46664: ("VolumeDrive", r"VOLUMEDRIVE|VDI-NETWORK", True),
    200019: ("AlexHost", r"ALEXHOST", True), 62240: ("Clouvider", r"CLOUVIDER", True), 35916: ("MultaCom", r"MULTA", True),
    197540: ("netcup", r"NETCUP", True), 8560: ("IONOS", r"IONOS", True), 47583: ("Hostinger", r"HOSTINGER", True),
    11878: ("tzulo", r"TZULO", True), 199524: ("G-Core Labs", r"G-CORE|GCORE", True), 202422: ("G-Core Labs", r"G-CORE|GCORE", True),
    53667: ("FranTech (BuyVM)", r"FRANTECH|PONYNET", True), 396356: ("Latitude.sh", r"LATITUDE", True),
    23470: ("ReliableSite", r"RELIABLESITE", True), 25820: ("IT7 Networks", r"IT7", True),
    398324: ("Censys", r"CENSYS", True), 398705: ("Censys", r"CENSYS", True), 211298: ("Driftnet", r"DRIFTNET", True),
    10439: ("CariNet", r"CARINET", True), 399358: ("Anthropic", r"ANTHROPIC", True), 26496: ("GoDaddy", r"GO-?DADDY", True),
    19318: ("Interserver", r"INTERSERVER", True), 36351: ("IBM Cloud", r"SOFTLAYER|IBM", True),
    212238: ("Datacamp (CDN77)", r"DATACAMP|CDNEXT", True), 60068: ("Datacamp (CDN77)", r"DATACAMP|CDN77", True),
    21859: ("Zenlayer", r"ZENLAYER|ZEN-ECN", True),
    # transit / consumer: friendly name only, never "cloud"
    174: ("Cogent", r"COGENT", False), 3356: ("Lumen", r"LEVEL3|LUMEN", False), 6939: ("Hurricane Electric", r"HURRICANE", False),
    7922: ("Comcast", r"COMCAST", False), 701: ("Verizon", r"UUNET|VERIZON", False), 7018: ("AT&T", r"\bATT\b|AT&T", False),
    3320: ("Deutsche Telekom", r"DTAG|TELEKOM", False), 12322: ("Free SAS", r"PROXAD|FREE SAS", False),
    16591: ("Google Fiber", r"GOOGLE-FIBER", False),
}
# Removed 2026-10-24 because the registry says otherwise: 62651 was "Anthropic"
# (really NETPROTECT-DP / Strong Technology), 8100 "QuadraNet" (really Splice
# Internet, an Australian ISP), 211252 "Delis" (Marushin K.K., JP), 401115
# "EKABI" (registry: "ER"), 208722 "Yandex Cloud" (now Nebius).
_PROV_RX = {a: re.compile(rx, re.I) for a, (_, rx, _) in PROVIDERS.items()}

# Hosting-sounding words. Used only as a hint: "hosting (unverified)", which is
# masked like an ISP, because a word match is not proof.
HOSTING_RE = re.compile(
    r"\b(?:AMAZON|AWS|GOOGLE|MICROSOFT|AZURE|HETZNER|OVH\w*|DIGITALOCEAN|LINODE|AKAMAI|"
    r"CLOUDFLARE|ORACLE|ALIBABA|TENCENT|HUAWEI.?CLOUD|CHOOPA|VULTR|CONTABO|SCALEWAY|"
    r"LEASEWEB|M247|DATACAMP|IONOS|HOSTINGER|HOSTWINDS|NETCUP|COLOCROSSING|PSYCHZ|QUADRANET|"
    r"ZENLAYER|G-?CORE|FASTLY|EDGECAST|CDN77|FACEBOOK|META|YANDEX|BAIDU|BYTEDANCE|"
    r"ANTHROPIC|OPENAI|PERPLEXITY|COREWEAVE|LAMBDA ?LABS|RACKSPACE|SOFTLAYER|EQUINIX|"
    r"SERVERS?|HOSTING|HOST|DATA ?CENT(?:ER|RE)S?|COLO(?:CATION)?|VPS|CLOUD|DEDICATED|CENSYS|SHODAN|"
    r"STARK INDUSTRIES|AEZA|FRANTECH|BUYVM|OVPN|MULLVAD|PROTON|DATAPACKET|CDN)\b",
    re.I)
RESIDENTIAL_RE = re.compile(
    r"\b(?:FIBER|FIBRE|BROADBAND|CABLE|DSL|ADSL|VDSL|FTTH|MOBILE|WIRELESS|CELLULAR|LTE|GSM|5G|4G|"
    r"TELECOM\w*|TELEKOM\w*|TELECOMUNICA\w*|TELEFONICA|TELIA|TELE2|VODAFONE|ORANGE|COMCAST|CHARTER|"
    r"SPECTRUM|VERIZON|RESIDENTIAL|HOME|KABEL|INTERNET SERVICE|ISP)\b",
    re.I)

# Freshness limits (seconds). Older data is ignored, not trusted.
# dbip: monthly release, judged by its release date (Last-Modified), not our fetch time.
MAX_AGE = {"bgp": 3 * 86400, "asnames": 14 * 86400, "clouds": 14 * 86400, "crawlers": 7 * 86400, "dbip": 45 * 86400}
SOURCE_LABEL = {"iptoasn": "iptoasn", "ris": "RIPE RIS", "dbip": "DB-IP"}
RIS_MIN_PEERS = 10   # RIS prefixes seen by fewer peers are leaks / noise (median is ~330)


def _ip_int(ip):
    try:
        if ":" in ip:
            return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, ip), "big")
        return 4, int.from_bytes(socket.inet_aton(ip), "big")
    except (OSError, ValueError, TypeError):
        return 0, 0


def _net_range(cidr):
    """'10.0.0.0/8' -> (4, start, end) or None."""
    try:
        n = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    return n.version, int(n.network_address), int(n.broadcast_address)


class Intervals:
    """Longest-prefix-match table: CIDRs flattened into sorted, disjoint
    [start, end] segments, each carrying the label of its most specific
    prefix. Lookup = one bisect. IPv4 columns are compact arrays."""

    def __init__(self):
        self.t = {4: (array.array("I"), array.array("I"), []), 6: ([], [], [])}

    @classmethod
    def build(cls, items):
        """items: iterable of (version, start, end, label); CIDRs nest or are disjoint."""
        self = cls()
        by_v = {4: [], 6: []}
        for v, s, e, lab in items:
            by_v[v].append((s, -e, lab))
        for v, lst in by_v.items():
            lst.sort(key=lambda x: (x[0], x[1]))   # start asc, wider first
            st, en, lb = self.t[v]
            stack = []   # [(end, label)] open prefixes, innermost last
            pos = 0

            def emit(a, b, lab):
                if a > b:
                    return
                if lb and lb[-1] == lab and en[-1] + 1 == a:
                    en[-1] = b
                else:
                    st.append(a); en.append(b); lb.append(lab)
            last = None
            for s, ne, lab in lst:
                e = -ne
                if (s, e) == last:
                    continue   # duplicate prefix: first (already chosen) label wins
                last = (s, e)
                while stack and stack[-1][0] < s:
                    end, l2 = stack.pop()
                    emit(pos, end, l2)
                    pos = end + 1
                if stack:
                    emit(pos, s - 1, stack[-1][1])
                pos = s
                stack.append((e, lab))
            while stack:
                end, l2 = stack.pop()
                emit(pos, end, l2)
                pos = end + 1
        return self

    def get(self, ip):
        v, x = _ip_int(ip)
        if not v:
            return None
        st, en, lb = self.t[v]
        i = bisect.bisect_right(st, x) - 1
        if i >= 0 and x <= en[i]:
            return lb[i]
        return None

    def __len__(self):
        return len(self.t[4][0]) + len(self.t[6][0])


class AsnDB:
    """Source A: iptoasn.com range table (already flattened), binary search."""

    def __init__(self, path):
        self.path = path
        self.ready = False
        self.tables = {4: ([], [], []), 6: ([], [], [])}
        self.names = {}  # asn -> (country, description)
        self.loaded_rows = 0
        self.mtime = 0

    @staticmethod
    def _rows(f):
        """iptoasn TSV: first, last, asn, cc, description."""
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 5:
                yield parts[0], parts[1], parts[2], parts[3], parts[4]

    def load(self):
        if not os.path.exists(self.path):
            return
        t = {4: (array.array("I"), array.array("I"), array.array("I")), 6: ([], [], [])}
        names = {}
        n = 0
        with gzip.open(self.path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            for first, last, asn, cc, desc in self._rows(f):
                try:
                    asn = int(asn)
                except ValueError:
                    continue
                if asn <= 0 or asn > 0xFFFFFFFF:
                    continue
                v, s = _ip_int(first)
                v2, e = _ip_int(last)
                if not v or v != v2:
                    continue
                st, en, an = t[v]
                st.append(s); en.append(e); an.append(asn)
                if asn not in names:
                    names[asn] = (cc, desc)
                n += 1
        for v in (4, 6):   # the dump is sorted; make sure (bisect depends on it)
            st, en, an = t[v]
            if any(st[i] > st[i + 1] for i in range(len(st) - 1)):
                rows = sorted(zip(st, en, an))
                kind = type(st)
                if kind is array.array:
                    t[v] = tuple(array.array("I", (r[k] for r in rows)) for k in range(3))
                else:
                    t[v] = tuple([r[k] for r in rows] for k in range(3))
        self.tables, self.names, self.loaded_rows = t, names, n
        self.mtime = os.path.getmtime(self.path)
        self.ready = True

    def lookup(self, ip):
        """-> (asn, start_int, end_int, version) or None"""
        v, x = _ip_int(ip)
        if not v or not self.ready:
            return None
        st, en, an = self.tables[v]
        i = bisect.bisect_right(st, x) - 1
        if i >= 0 and x <= en[i]:
            return an[i], st[i], en[i], v
        return None

    def asn(self, ip):
        r = self.lookup(ip)
        return r[0] if r else None

    def range_info(self, ip):
        r = self.lookup(ip)
        if not r:
            return None
        asn, s, e, v = r
        cls = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
        a, b = cls(s), cls(e)
        cidrs = [str(c) for c in ipaddress.summarize_address_range(a, b)][:8]
        return {"asn": asn, "first": str(a), "last": str(b), "cidrs": cidrs}


class DbipDB(AsnDB):
    """Source C: DB-IP IP to ASN Lite CSV ('first,last,asn,"organisation"'),
    same tables as AsnDB. names[asn] = ("", organisation)."""

    @staticmethod
    def _rows(f):
        for row in csv.reader(f):
            if len(row) >= 4:
                yield row[0], row[1], row[2], "", row[3][:120]


def load_ris(paths, min_peers=RIS_MIN_PEERS):
    """Source B: RIPE RIS whois dumps ('origin<TAB>prefix<TAB>peers').
    -> (Intervals labelled with an index into `origins`, origins list of ASN
    tuples, rows used). A prefix with several origins (MOAS) keeps every
    origin seen by at least a quarter of the best one's peers."""
    items, origins, intern = [], [], {}
    used = 0

    def flush(prefix, cands):
        nonlocal used
        if not cands:
            return
        r = _net_range(prefix)
        if not r:
            return
        v, s, e = r
        plen = (32 if v == 4 else 128) - (e - s).bit_length()
        if plen < (8 if v == 4 else 16):
            return   # default routes and other absurdly wide announcements
        best = max(p for p, _ in cands)
        keep = tuple(sorted({a for p, a in cands if p * 4 >= best}, key=lambda a: -max(p for p, b in cands if b == a)))
        idx = intern.get(keep)
        if idx is None:
            idx = intern[keep] = len(origins)
            origins.append(keep)
        items.append((v, s, e, idx))
        used += 1

    for path in paths:
        if not os.path.exists(path):
            continue
        cur, cands = None, []
        with gzip.open(path, "rt", encoding="ascii", errors="replace") as f:
            for line in f:
                if not line or line[0] in "%\n":
                    continue
                parts = line.split()
                if len(parts) != 3:
                    continue
                o, prefix, peers = parts
                try:
                    peers = int(peers)
                    asns = [int(x) for x in o.strip("{}").split(",") if x]
                except ValueError:
                    continue
                if prefix != cur:
                    flush(cur, cands)
                    cur, cands = prefix, []
                if peers >= min_peers:
                    cands += [(peers, a) for a in asns if a]
            flush(cur, cands)
    return Intervals.build(items), origins, used


def load_asnames(path):
    """RIPE asn.txt: '24940 HETZNER-AS Hetzner Online GmbH, DE' -> {asn: (handle, org, cc)}."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            num, _, rest = line.strip().partition(" ")
            if not num.isdigit():
                continue
            rest, _, cc = rest.rpartition(", ")
            if not rest:
                rest, cc = cc, ""
            handle, _, org = rest.partition(" ")
            org = org[2:] if org.startswith("- ") else org
            out[int(num)] = (handle, org.strip() or handle, cc.strip()[:2])
    return out


_STOP = frozenset("AS ASN NET NETWORK NETWORKS INC LLC LTD LIMITED CO CORP CORPORATION COMPANY GMBH AG SA SAS SRL BV "
                  "PTE PTY PLC THE AND OF DE LA DO ZAO OOO PJSC JSC SPA KR AP ISP BLOCK COM".split())


def _tokens(s):
    return {t for t in re.split(r"[^A-Z0-9]+", (s or "").upper()) if len(t) >= 3 and t not in _STOP and not t.isdigit()}


def names_agree(desc, reg, common=frozenset()):
    """Does iptoasn's AS description name the same holder as the registry
    entry (handle, org, cc)? Tolerant of suffixes like -KR and punctuation;
    a real change of holder (sold / transferred ASN) shares no distinctive
    word. `common` = words too frequent in AS names to count (BEIJING,
    TELECOM, INTERNET, ...), computed from the registry list."""
    if not desc:
        return True   # nothing to compare against
    h1 = desc.split(" ", 1)[0].upper()
    h2 = reg[0].upper()
    if h1 == h2 or (min(len(h1), len(h2)) >= 4 and (h1.startswith(h2) or h2.startswith(h1))):
        return True
    dt = _tokens(desc)
    if (dt & _tokens(reg[0] + " " + reg[1])) - common:
        return True
    lead = next((t for t in re.split(r"[^A-Z0-9]+", reg[1].upper()) if t in _tokens(t)), None)
    return lead in dt   # the holder's leading word ("Orange S.A.") counts even if common


def common_tokens(asnames, limit=150):
    c = collections.Counter()
    for h, org, _ in asnames.values():
        c.update(_tokens(org))
    return frozenset(t for t, n in c.items() if n > limit)


class NetIntel:
    """All network data behind one object; load() swaps everything at once."""

    def __init__(self, data_dir, max_age=None):
        self.dir = data_dir
        self.max_age = dict(MAX_AGE, **(max_age or {}))
        self.a = AsnDB(os.path.join(data_dir, "ip2asn-combined.tsv.gz"))
        self.c = DbipDB(os.path.join(data_dir, "dbip-asn-lite.csv.gz"))
        self.ris, self.ris_origins, self.ris_rows = Intervals(), [], 0
        self.asnames = {}
        self.common = frozenset()
        self.clouds = Intervals()
        self.cloud_names = []
        self.meta = {}
        self.ready = False
        self.loaded = 0
        self.verifier = Verifier(self)
        self._load_lock = threading.Lock()

    # ---- loading
    def _meta(self):
        try:
            with open(os.path.join(self.dir, "meta.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def load(self):
        with self._load_lock:
            meta = self._meta()
            a = AsnDB(os.path.join(self.dir, "ip2asn-combined.tsv.gz"))
            a.load()
            c = DbipDB(os.path.join(self.dir, "dbip-asn-lite.csv.gz"))
            c.load()
            ris, origins, rows = load_ris([os.path.join(self.dir, "riswhoisdump.IPv4.gz"),
                                           os.path.join(self.dir, "riswhoisdump.IPv6.gz")])
            names = load_asnames(os.path.join(self.dir, "asn.txt"))
            clouds, cnames = self._load_clouds(meta)
            self.a, self.c, self.ris, self.ris_origins, self.ris_rows = a, c, ris, origins, rows
            self.asnames, self.clouds, self.cloud_names, self.meta = names, clouds, cnames, meta
            self.common = common_tokens(names)
            self.verifier.load_sources(os.path.join(self.dir, "ranges.json"), meta)
            self.loaded = time.time()
            self.ready = a.ready or rows > 0 or c.ready
            describe_asn_cached.cache_clear()

    def _load_clouds(self, meta):   # freshness is checked per lookup (lists may age while loaded)
        try:
            with open(os.path.join(self.dir, "clouds.json")) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return Intervals(), []
        names, items = [], []
        for prov, cidrs in sorted(data.items()):
            names.append(prov)
            idx = len(names) - 1
            for c in cidrs:
                r = _net_range(c)
                if r:
                    items.append((*r, idx))
        return Intervals.build(items), names

    # ---- freshness
    def fetched(self, name, meta=None):
        m = (meta if meta is not None else self.meta).get(name) or {}
        return m.get("fetched") or 0

    def age_ref(self, name, meta=None):
        """The time freshness is measured from: the fetch time, except for
        DB-IP, whose monthly release date counts (re-downloading an old
        release does not make it new). Never fetched -> 0."""
        m = (meta if meta is not None else self.meta).get(name) or {}
        if not m.get("fetched"):
            return 0
        if name == "dbip":
            return m.get("published_ts") or m["fetched"]
        return m["fetched"]

    def fresh(self, name, kind, meta=None):
        t = self.age_ref(name, meta)
        return bool(t) and time.time() - t <= self.max_age[kind]

    def ages(self):
        """{source: {"age_h": hours or None, "fresh": bool, "error": str}} for status pages."""
        now = time.time()
        out = {}
        for name, m in sorted(self.meta.items()):
            kind = ("bgp" if name in ("iptoasn", "ris4", "ris6") else "asnames" if name == "asnames"
                    else "dbip" if name == "dbip" else "clouds" if name.startswith("cloud:") else "crawlers")
            t = self.age_ref(name)
            out[name] = {"fetched": m.get("fetched") or None, "age_h": round((now - t) / 3600, 1) if t else None,
                         "fresh": bool(t) and now - t <= self.max_age[kind], "published": m.get("published"),
                         "age_from": "release" if name == "dbip" and m.get("published_ts") else "fetch",
                         "error": m.get("error") or ""}
        return out

    # ---- lookups
    def asn(self, ip):
        """Best-effort origin ASN (source A, else B) for rate limiting only."""
        a = self.a.asn(ip) if ip else None
        if a is None and ip:
            o = self.ris.get(ip)
            a = self.ris_origins[o][0] if o is not None else None
        return a

    def asns(self, ip):
        """Every origin ASN any source reports (for 'is this inside the operator's network?' gates)."""
        out = set()
        if not ip:
            return out
        a = self.a.asn(ip)
        if a:
            out.add(a)
        o = self.ris.get(ip)
        if o is not None:
            out.update(self.ris_origins[o])
        return out

    def range_info(self, ip):
        return self.a.range_info(ip)

    def votes(self, ip):
        """Fresh origin-AS votes: [(source, (asn, ...))], RIS first (it can
        carry several origins for one prefix). Stale or silent sources do not vote."""
        fa = self.fresh("iptoasn", "bgp")
        fb = self.fresh("ris4" if ":" not in (ip or "") else "ris6", "bgp")
        fc = self.fresh("dbip", "dbip")
        a = self.a.asn(ip) if ip and self.a.ready else None
        o = self.ris.get(ip) if ip else None
        b = self.ris_origins[o] if o is not None else ()
        c = self.c.asn(ip) if ip and self.c.ready else None
        raw = {"a": a, "b": list(b), "c": c, "a_fresh": fa, "b_fresh": fb, "c_fresh": fc}
        v = []
        if fb and b:
            v.append(("ris", tuple(b)))
        if fa and a is not None:
            v.append(("iptoasn", (a,)))
        if fc and c is not None:
            v.append(("dbip", (c,)))
        return v, raw

    def tally(self, votes):
        """Majority over the fresh votes. -> dict(asn, asns, agree, dissent, moas, exact)
        or None when no strict majority of at least two sources exists.
        A source supports candidate X if it names X, or an ASN of the same
        registry holder. Ties between candidates: more exact matches; then,
        if two exact matches tie (a prefix RIS sees with two origins, iptoasn
        naming one and DB-IP the other), iptoasn's pick, as before DB-IP
        existed; then the RIS origin (RIS is first in `votes`). A source that
        names another origin RIS also sees for the prefix is not a dissent
        ("moas"): both origins really announce it."""
        a_pick = next((s[0] for src, s in votes if src == "iptoasn"), None)
        if len(votes) < 2:
            return None
        cands = []
        for _, s in votes:
            cands += [x for x in s if x not in cands]
        best = None
        for pref, x in enumerate(cands):
            agree, exact, used = [], 0, []
            for src, s in votes:
                if x in s:
                    agree.append(src); exact += 1; used.append(x)
                else:
                    y = next((y for y in s if self.same_holder(x, y)), None)
                    if y is not None:
                        agree.append(src); used.append(y)
            key = (len(agree), exact, exact >= 2 and x == a_pick, -pref)
            if best is None or key > best[0]:
                best = (key, x, agree, used, exact)
        (k, *_), x, agree, used, exact = best
        if k < 2 or k * 2 <= len(votes):
            return None
        if exact >= 2 and exact * 2 > len(votes):
            used = [x]   # the exact matches alone are a majority: plain consensus on one ASN
        seen = {y for src, s in votes if src in agree for y in s}
        rest = [(src, list(s)) for src, s in votes if src not in agree]
        return {"asn": x, "asns": sorted(set(used), key=lambda y: (y != x, y)), "agree": agree, "exact": exact,
                "dissent": [(src, s) for src, s in rest if not seen & set(s)],
                "moas": [(src, s) for src, s in rest if seen & set(s)]}

    @staticmethod
    def _vote_text(t):
        who = " and ".join(SOURCE_LABEL[s] for s in t["agree"])
        txt = f"{who} agree on the origin AS"
        if t["moas"]:
            txt += "; " + ", ".join(f"{SOURCE_LABEL[s]} names AS{'/AS'.join(map(str, a))}" for s, a in t["moas"]) \
                + ", the other origin RIS sees for this prefix"
        if t["dissent"]:
            txt += "; " + ", ".join(f"{SOURCE_LABEL[s]} says AS{'/AS'.join(map(str, a))}" for s, a in t["dissent"]) + " (outvoted)"
        return txt

    def describe_ip(self, ip):
        """-> dict(asn, name, label, kind, status, why, cc, provider, a, b, c,
        votes, dissent, ...). kind: cloud | hosting | isp | unknown;
        status: verified | unverified | unknown. asn is set only when the
        origin is confirmed (a strict majority, at least two fresh sources)."""
        votes, res = self.votes(ip)
        ci = self.clouds.get(ip) if ip else None
        provider = self.cloud_names[ci] if ci is not None else None
        if provider and not self.fresh(f"cloud:{provider}", "clouds"):
            provider = None   # a stale list says nothing about today
        t = self.tally(votes)
        res.update(provider=provider, votes={s: list(a) for s, a in votes},
                   dissent=[{"source": s, "asns": a} for s, a in (t["dissent"] if t else [])],
                   moas=[{"source": s, "asns": a} for s, a in (t["moas"] if t else [])])
        consensus = t["asn"] if t and len(t["asns"]) == 1 else None
        if provider:
            d = self.describe_asn(consensus) if consensus else {}
            res.update(asn=consensus, name=provider, label=provider, kind="cloud", status="verified",
                       cc=d.get("cc", ""), raw=d.get("raw", ""),
                       why=f"in {provider}'s published IP ranges")
            return res
        if consensus is not None:
            d = self.describe_asn(consensus)
            # second cross-check: does an agreeing source's AS name match the registry list?
            # (iptoasn's when it is in the majority, else DB-IP's)
            desc = (self.a.names if "iptoasn" in t["agree"] else self.c.names).get(consensus, ("", ""))[1]
            reg = self.asnames.get(consensus)
            name_ok = bool(reg) and names_agree(desc, reg, self.common)
            res.update(asn=consensus, name=d["name"], cc=d["cc"], raw=d["raw"], kind=d["kind"])
            if name_ok and d["status"] == "verified":
                res.update(status="verified", why=self._vote_text(t) + "; name from the registry", label=d["label"])
            else:
                res.update(status="unverified", kind="isp" if d["kind"] == "cloud" else d["kind"],
                           why=self._vote_text(t) + ", but its name could not be confirmed (registry list stale or different)",
                           label=f"{d['name']} (unverified)")
            return res
        if t:
            # e.g. COMCAST-22909 vs COMCAST-7922: the sources pick different ASNs of one organisation
            ds = [self.describe_asn(y) for y in t["asns"]]
            db = ds[0]
            kinds = {x["kind"] for x in ds}
            kind = "cloud" if kinds == {"cloud"} else ("isp" if "cloud" in kinds else db["kind"])
            ok = all(x["status"] == "verified" for x in ds)
            label = db["label"] if ok and kind == db["kind"] else f"{db['name']} (unverified)"
            res.update(asn=t["asn"], name=db["name"], label=label, kind=kind, status="verified" if ok else "unverified",
                       cc=db["cc"], raw=db["raw"],
                       why=(", ".join(f"{SOURCE_LABEL[s]} says AS{'/AS'.join(map(str, a))}" for s, a in votes
                                      if s in t["agree"])
                            + "; the registry lists them under the same holder"
                            + ("; " + ", ".join(f"{SOURCE_LABEL[s]} says AS{'/AS'.join(map(str, a))}"
                                                for s, a in t["dissent"]) + " (outvoted)" if t["dissent"] else "")))
            return res
        if len(votes) >= 2:
            res.update(asn=None, name="", label="unverified network (sources disagree)", kind="unknown",
                       status="unverified", cc="", raw="",
                       why="; ".join(f"{SOURCE_LABEL[s]} says AS{'/AS'.join(map(str, a))}" for s, a in votes))
            return res
        fresh_n = sum(1 for k in ("a_fresh", "b_fresh", "c_fresh") if res[k])
        if votes:
            d = self.describe_asn(votes[0][1][0])
            res.update(asn=None, name=d["name"], label=f"{d['name']} (unverified)", kind="unknown", status="unverified",
                       cc=d["cc"], raw=d["raw"],
                       why=(f"only one fresh source ({SOURCE_LABEL[votes[0][0]]}) knows this IP" if fresh_n >= 2
                            else "network data is stale; one source only"))
            return res
        stale = fresh_n == 0
        res.update(asn=None, name="", label="unknown network" + (" (data stale)" if stale else ""), kind="unknown",
                   status="unknown", cc="", raw="", why="network data is stale" if stale else "not announced in BGP")
        return res

    def same_holder(self, x, y):
        """Two ASNs registered to the same organisation (registry list only)."""
        rx, ry = self.asnames.get(x), self.asnames.get(y)
        if not (rx and ry):
            return False
        if " ".join(rx[1].upper().split()) == " ".join(ry[1].upper().split()):
            return True
        hx, hy = (re.split(r"[-_]", r[0].upper(), maxsplit=1)[0] for r in (rx, ry))
        if len(hx) >= 4 and hx == hy and not hx.startswith("AS"):
            return True
        return bool((_tokens(rx[1]) & _tokens(ry[1])) - self.common)

    def describe_asn(self, asn):
        return describe_asn_cached(self, asn, (self.loaded, int(time.time() // 3600)))


@functools.lru_cache(maxsize=4096)
def describe_asn_cached(ni, asn, _gen):
    """Name and kind of an ASN (not of an IP). status=verified when the name
    comes from a fresh registry list."""
    if not asn:
        return {"asn": None, "name": "unknown network", "label": "unknown or unverified network", "kind": "unknown",
                "status": "unknown", "cc": "", "raw": ""}
    reg = ni.asnames.get(asn)
    reg_fresh = ni.fresh("asnames", "asnames")
    a_cc, a_desc = ni.a.names.get(asn) or ni.c.names.get(asn) or ("", "")
    raw = f"{reg[0]} - {reg[1]}" if reg else a_desc
    cc = (reg[2] if reg else "") or a_cc
    org = (reg[1] if reg else (a_desc.split(" - ", 1)[1] if " - " in a_desc else a_desc)).strip() or f"AS{asn}"
    prov = PROVIDERS.get(asn)
    curated_ok = bool(prov and reg and _PROV_RX[asn].search(raw))
    name = prov[0] if curated_ok else org
    text = raw or org
    if curated_ok and prov[2]:
        kind = "cloud"
    elif curated_ok:
        kind = "isp"
    elif RESIDENTIAL_RE.search(text):
        kind = "isp"
    elif HOSTING_RE.search(text):
        kind = "hosting"
    else:
        kind = "isp"
    status = "verified" if reg and reg_fresh else "unverified"
    if status == "verified":
        label = name if kind == "cloud" else f"{name} (hosting, unverified)" if kind == "hosting" else f"{name} (ISP)"
    else:
        label = f"{name} (unverified)"
        if kind == "cloud":
            kind = "isp"   # no fresh registry confirmation: never 'cloud'
    return {"asn": asn, "name": name[:60], "label": label[:80], "kind": kind, "status": status, "cc": cc, "raw": raw[:120]}


VERIFIED = ("range", "rdns")   # the only crawler checks that count


def claim_text(label, operator, verify):
    """Public wording for a crawler claim."""
    who = f"{operator} {label}" if operator and operator.lower() not in (label or "").lower() else (label or operator or "?")
    if verify in VERIFIED:
        return f"{who} (verified: {'published IP range' if verify == 'range' else 'forward-confirmed reverse DNS'})"
    if verify == "spoofed":
        return f"claims to be {who} (failed: not in {operator or 'its'} published ranges / DNS)"
    if verify == "pending":
        return f"claims to be {who} (check pending)"
    return f"claims to be {who} (unverified)"


# ------------------------------------------------------------------- UA classes
# kind: ai | search | bot | tool | browser | unknown
# verify: names of published range lists and/or ("rdns", suffixes, operator ASNs), or None
# (None = the operator publishes no way to check: the claim stays "unverified").

# Reverse DNS is only looked up when the client IP is inside the operator's own
# networks: their reverse zones are run by the operator, never by the client,
# so an attacker cannot make us query a DNS server they control (which would
# reveal our resolver) by sending a bot user agent from their own IP block.
AWS = frozenset({16509, 14618, 8987})
APPLE = frozenset({714, 6185})
GOOGLE = frozenset({15169, 396982, 19527, 36040, 36492})
MSFT = frozenset({8075, 8068, 8069, 3598})
YANDEX = frozenset({13238, 208722})
BAIDU = frozenset({55967, 38365, 4134, 4837, 23724, 4808, 9808, 58466})
HUAWEI = frozenset({136907, 55990, 131444, 206798, 265443, 200756})

UA_RULES = [
    # --- AI crawlers, AI search, AI agents acting for a user
    (r"GPTBot", "GPTBot", "OpenAI", "ai", ["openai-gptbot"]),
    (r"ChatGPT-User", "ChatGPT-User", "OpenAI", "ai", ["openai-chatgpt-user"]),
    (r"OAI-SearchBot", "OAI-SearchBot", "OpenAI", "ai", ["openai-searchbot"]),
    (r"ChatGPT[ -]Agent|OpenAI[ -]Operator", "ChatGPT Agent", "OpenAI", "ai", ["openai-chatgpt-user"]),
    (r"Claude-User", "Claude-User", "Anthropic", "ai", ["anthropic-bots"]),
    (r"Claude-SearchBot", "Claude-SearchBot", "Anthropic", "ai", ["anthropic-bots"]),
    (r"ClaudeBot", "ClaudeBot", "Anthropic", "ai", ["anthropic-bots"]),
    (r"anthropic-ai|Claude-Web", "anthropic-ai", "Anthropic", "ai", ["anthropic-bots"]),
    (r"Perplexity-User", "Perplexity-User", "Perplexity", "ai", ["perplexity-user"]),
    (r"PerplexityBot", "PerplexityBot", "Perplexity", "ai", ["perplexitybot"]),
    (r"Google-CloudVertexBot", "Google-CloudVertexBot", "Google", "ai", ["google-special", "google-user"]),
    (r"Google-Extended|Google-NotebookLM|GoogleAgent", "Google AI fetcher", "Google", "ai", ["google-user", "google-special"]),
    (r"Gemini|Google-Gemini", "Gemini", "Google", "ai", ["google-user"]),
    (r"CCBot", "CCBot", "Common Crawl", "ai", ["ccbot", ("rdns", (".crawl.commoncrawl.org",), AWS)]),
    (r"Bytespider", "Bytespider", "ByteDance", "ai", None),
    (r"TikTokSpider", "TikTokSpider", "ByteDance", "ai", None),
    (r"Amazonbot", "Amazonbot", "Amazon", "ai", [("rdns", (".crawl.amazonbot.amazon",), AWS)]),
    (r"Applebot-Extended", "Applebot-Extended", "Apple", "ai", ["applebot", ("rdns", (".applebot.apple.com",), APPLE)]),
    (r"meta-externalagent|meta-externalfetcher|FacebookBot", "Meta AI crawler", "Meta", "ai", None),
    (r"cohere-ai|cohere-training-data-crawler", "Cohere", "Cohere", "ai", None),
    (r"MistralAI-User", "MistralAI-User", "Mistral", "ai", ["mistral-user"]),
    (r"DuckAssistBot", "DuckAssistBot", "DuckDuckGo", "ai", ["duckduckbot"]),
    (r"YouBot", "YouBot", "You.com", "ai", None),
    (r"Diffbot", "Diffbot", "Diffbot", "ai", None),
    (r"AI2Bot|Ai2Bot-Dolma", "AI2Bot", "Allen AI", "ai", None),
    (r"DeepSeekBot|DeepSeek", "DeepSeek", "DeepSeek", "ai", None),
    (r"xAI|Grok", "Grok", "xAI", "ai", None),
    (r"PanguBot", "PanguBot", "Huawei", "ai", None),
    (r"Timpibot", "Timpibot", "Timpi", "ai", None),
    (r"ImagesiftBot", "ImagesiftBot", "Imagesift", "ai", None),
    (r"omgili", "omgili", "Webz.io", "ai", None),
    (r"Kangaroo Bot", "Kangaroo Bot", "Kangaroo LLM", "ai", None),
    (r"iaskspider", "iaskspider", "iAsk", "ai", None),
    (r"Manus", "Manus", "Manus", "ai", None),
    (r"Devin", "Devin", "Cognition", "ai", None),
    (r"Firecrawl", "Firecrawl", "Firecrawl", "ai", None),
    (r"\bJina\b|jina-reader", "Jina Reader", "Jina AI", "ai", None),
    (r"LinkupBot|Exa(bot)?/|ExaBot", "AI search crawler", None, "ai", None),
    # --- search engines
    (r"Googlebot|Google-InspectionTool|GoogleOther|Storebot-Google|AdsBot-Google", "Googlebot", "Google", "search",
     ["googlebot", "google-special", ("rdns", (".googlebot.com", ".google.com", ".googleusercontent.com"), GOOGLE)]),
    (r"bingbot|BingPreview|msnbot", "bingbot", "Microsoft", "search", ["bingbot", ("rdns", (".search.msn.com",), MSFT)]),
    (r"Applebot", "Applebot", "Apple", "search", ["applebot", ("rdns", (".applebot.apple.com",), APPLE)]),
    (r"YandexBot|YandexMobileBot|Yandex[A-Za-z]*/", "YandexBot", "Yandex", "search", [("rdns", (".yandex.ru", ".yandex.net", ".yandex.com"), YANDEX)]),
    (r"Baiduspider", "Baiduspider", "Baidu", "search", [("rdns", (".baidu.com", ".baidu.jp"), BAIDU)]),
    (r"DuckDuckBot", "DuckDuckBot", "DuckDuckGo", "search", ["duckduckbot"]),
    (r"PetalBot", "PetalBot", "Huawei", "search", [("rdns", (".petalsearch.com",), HUAWEI)]),
    (r"SeznamBot", "SeznamBot", "Seznam", "search", None),
    (r"Yeti/", "Naver Yeti", "Naver", "search", None),
    (r"Sogou", "Sogou", "Sogou", "search", None),
    (r"MojeekBot", "MojeekBot", "Mojeek", "search", None),
    (r"Qwantbot|Qwant", "Qwantbot", "Qwant", "search", None),
    (r"Slurp", "Yahoo Slurp", "Yahoo", "search", None),
    # --- other bots: SEO, previews, monitors, scanners, archives
    (r"AhrefsBot|AhrefsSiteAudit", "AhrefsBot", "Ahrefs", "bot", None),
    (r"SemrushBot", "SemrushBot", "Semrush", "bot", None),
    (r"MJ12bot", "MJ12bot", "Majestic", "bot", None),
    (r"DotBot", "DotBot", "Moz", "bot", None),
    (r"BLEXBot|DataForSeoBot|Barkrowler|serpstatbot|SEOkicks|SiteAuditBot", "SEO crawler", None, "bot", None),
    (r"facebookexternalhit|facebookcatalog", "facebookexternalhit", "Meta", "bot", None),
    (r"Twitterbot", "Twitterbot", "X", "bot", None),
    (r"Slackbot|Slack-ImgProxy", "Slackbot", "Slack", "bot", None),
    (r"Discordbot", "Discordbot", "Discord", "bot", None),
    (r"TelegramBot", "TelegramBot", "Telegram", "bot", None),
    (r"WhatsApp", "WhatsApp", "Meta", "bot", None),
    (r"LinkedInBot", "LinkedInBot", "LinkedIn", "bot", None),
    (r"redditbot", "redditbot", "Reddit", "bot", None),
    (r"archive\.org_bot|ia_archiver|Wayback", "Internet Archive", "Internet Archive", "bot", None),
    (r"UptimeRobot|Pingdom|StatusCake|Better ?Uptime|Uptime-Kuma", "uptime monitor", None, "bot", None),
    (r"CensysInspect|censys", "Censys", "Censys", "bot", None),
    (r"zgrab|masscan|Nmap|Nuclei|Expanse|InternetMeasurement|Palo Alto|ModatScanner|l9explore|Odin", "scanner", None, "bot", None),
    (r"HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium", "headless browser", None, "tool", None),
    # --- HTTP libraries and CLIs (agents often show up as these)
    (r"^curl/", "curl", None, "tool", None),
    (r"^Wget", "Wget", None, "tool", None),
    (r"python-requests", "python-requests", None, "tool", None),
    (r"python-httpx", "httpx", None, "tool", None),
    (r"aiohttp", "aiohttp", None, "tool", None),
    (r"Python-urllib", "Python-urllib", None, "tool", None),
    (r"Go-http-client", "Go-http-client", None, "tool", None),
    (r"node-fetch|undici|^node$|axios|got \(", "Node.js client", None, "tool", None),
    (r"okhttp", "okhttp", None, "tool", None),
    (r"^Java/|Apache-HttpClient", "Java client", None, "tool", None),
    (r"libwww-perl|LWP::", "Perl LWP", None, "tool", None),
    (r"PostmanRuntime", "Postman", None, "tool", None),
    (r"HTTPie", "HTTPie", None, "tool", None),
    (r"Deno/", "Deno", None, "tool", None),
    (r"^Bun/", "Bun", None, "tool", None),
    (r"Scrapy", "Scrapy", None, "tool", None),
    (r"reqwest|hyper/", "Rust client", None, "tool", None),
    (r"bot\b|crawler|spider|scraper|fetcher", None, None, "bot", None),
]
UA_RULES = [(re.compile(p, re.I), *rest) for p, *rest in UA_RULES]
BROWSER_RE = re.compile(r"Mozilla/5\.0 .*(Chrome|Firefox|Safari|Edg|OPR)/", re.I)
BOTNAME_RE = re.compile(r"([A-Za-z][\w.-]*(?:bot|crawler|spider|fetcher|scraper))", re.I)


@functools.lru_cache(maxsize=8192)
def classify_ua(ua):
    """-> dict(label, operator, kind, verify). Cached; callers must not mutate."""
    ua = ua or ""
    if not ua.strip():
        return {"label": "(no user-agent)", "operator": None, "kind": "unknown", "verify": None}
    for rx, label, op, kind, ver in UA_RULES:
        if rx.search(ua):
            if label is None:
                m = BOTNAME_RE.search(ua)
                label = m.group(1)[:40] if m else "unnamed bot"
            return {"label": label, "operator": op, "kind": kind, "verify": ver}
    if BROWSER_RE.search(ua):
        fam = "Firefox" if "Firefox/" in ua else "Edge" if "Edg/" in ua else "Chrome" if "Chrome/" in ua else "Safari"
        return {"label": f"{fam} browser", "operator": None, "kind": "browser", "verify": None}
    first = re.split(r"[\s/;(]", ua.strip(), 1)[0][:40] or "unknown"
    return {"label": first, "operator": None, "kind": "unknown", "verify": None}


# --------------------------------------------------------------- verification

CF_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]


class RangeSet:
    """Small CIDR set (crawler lists): flattened, one bisect per lookup."""

    def __init__(self, cidrs):
        self.n = 0
        items = []
        for c in cidrs:
            r = _net_range(c)
            if r:
                items.append((*r, True))
                self.n += 1
        self.iv = Intervals.build(items)

    def __contains__(self, ip):
        return bool(self.iv.get(ip))

    def __len__(self):
        return self.n


class Verifier:
    """Decides whether a request that *claims* to be a known bot really is.
    Verified only by: the operator's own published IP list (fresh: fetched
    within MAX_AGE['crawlers']) -> "range", or forward-confirmed reverse DNS
    under the operator's own domain -> "rdns". Otherwise:
    "spoofed" (a check was possible and failed), "pending" (rDNS in flight),
    "claimed" (no way to check today, e.g. no list published or list stale).
    Being inside the operator's ASN is NOT verification (anyone can rent a VM
    there, and ASN data can be wrong)."""

    def __init__(self, ni):
        self.ni = ni
        self.sources = {}
        self.fetched = {}
        self.cloudflare = RangeSet(CF_FALLBACK)
        self._cache = collections.OrderedDict()
        self._lock = threading.Lock()
        self._pool = concurrent.futures.ThreadPoolExecutor(4, thread_name_prefix="rdns")
        self.rdns_cache = collections.OrderedDict()  # ip -> (ts, hostname or "" or None=pending)
        self.rdns_max = 20000
        self._pending = 0
        self.max_pending = 64
        self.lookups = 0
        self.gen = 0

    def load_sources(self, path, meta):
        if not (path and os.path.exists(path)):
            return
        with open(path) as f:
            data = json.load(f)
        src, fetched = {}, {}
        for k, v in data.items():
            t = (meta.get(f"crawler:{k}") or {}).get("fetched") or 0
            fetched[k] = t
            if v:
                src[k] = RangeSet(v)
        self.sources, self.fetched = src, fetched
        if len(src.get("cloudflare", [])) >= 10:
            self.cloudflare = src["cloudflare"]
        with self._lock:
            self._cache.clear()
            self.gen += 1

    def source_fresh(self, name):
        t = self.fetched.get(name) or 0
        return bool(t) and time.time() - t <= self.ni.max_age["crawlers"]

    def is_cloudflare(self, ip):
        return ip in self.cloudflare

    def verify(self, ip, verify_spec):
        if not verify_spec:
            return "claimed"
        if not self.ni.ready and any(not isinstance(sp, str) for sp in verify_spec):
            return "pending"   # network data still loading: decide later, do not cache
        key = (ip, id(verify_spec))
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < 6 * 3600:
                return hit[1]
        result = None
        checks_possible = False
        pending = False
        for spec in verify_spec:
            if isinstance(spec, str):
                rs = self.sources.get(spec)
                if rs is None or not len(rs) or not self.source_fresh(spec):
                    continue   # no list, or a stale one: proves nothing either way
                checks_possible = True
                if ip in rs:
                    result = "range"; break
            elif spec[0] == "rdns":
                checks_possible = True
                if not (self.ni.asns(ip) & spec[2]):
                    continue   # not the operator's network: fake claim, and no DNS query
                r = self.fcrdns(ip, spec[1])
                if r is True:
                    result = "rdns"; break
                if r is None:
                    pending = True
        if result is None:
            result = "pending" if pending else ("spoofed" if checks_possible else "claimed")
        if result != "pending":
            with self._lock:
                self._cache[key] = (now, result)
                while len(self._cache) > 50000:
                    self._cache.popitem(last=False)
        return result

    def _put(self, key, val):
        with self._lock:
            self.rdns_cache[key] = val
            self.rdns_cache.move_to_end(key)
            while len(self.rdns_cache) > self.rdns_max:
                self.rdns_cache.popitem(last=False)

    def cached_reverse(self, ip):
        """PTR from the cache only (never triggers a lookup)."""
        hit = self.rdns_cache.get(ip)
        return hit[1] if hit else None

    def _submit(self, fn, *args):
        with self._lock:
            if self._pending >= self.max_pending:
                return None
            self._pending += 1
            self.lookups += 1

        def run():
            try:
                return fn(*args)
            finally:
                with self._lock:
                    self._pending -= 1
        return self._pool.submit(run)

    def reverse(self, ip, wait=0.0):
        """Cached PTR lookup of a client IP; never blocks longer than `wait`
        seconds; at most max_pending lookups queued (else: None = pending)."""
        now = time.time()
        hit = self.rdns_cache.get(ip)
        if hit and (now - hit[0] < 86400) and hit[1] is not None:
            return hit[1]
        if hit and hit[1] is None and now - hit[0] < 60:
            return None   # in flight
        self._put(ip, (now, None))
        fut = self._submit(self._ptr, ip)
        if fut is None:
            with self._lock:
                self.rdns_cache.pop(ip, None)
            return None
        if wait:
            try:
                return fut.result(timeout=wait)
            except concurrent.futures.TimeoutError:
                return None
        return None

    def _ptr(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            name = ""
        self._put(ip, (time.time(), name[:253]))
        return name

    def forward(self, name, wait=2.0):
        """Forward lookup with a timeout (owner view only)."""
        fut = self._submit(socket.getaddrinfo, name, None)
        if fut is None:
            return None
        try:
            return sorted({a[4][0] for a in fut.result(timeout=wait)})
        except Exception:
            return None

    def fcrdns(self, ip, suffixes):
        """Forward-confirmed reverse DNS. True / False / None (pending).
        Forward lookups only for names under the operator's own suffixes."""
        name = self.reverse(ip)
        if name is None:
            return None
        if not name or not name.lower().endswith(tuple(suffixes)):
            return False
        key = ("fwd", ip, name)
        hit = self.rdns_cache.get(key)
        if hit is None or (hit[1] is None and time.time() - hit[0] > 60):
            self._put(key, (time.time(), None))
            if self._submit(self._fwd, ip, name, key) is None:
                with self._lock:
                    self.rdns_cache.pop(key, None)
            return None
        return hit[1]

    def _fwd(self, ip, name, key):
        try:
            addrs = {a[4][0] for a in socket.getaddrinfo(name, None)}
            ok = ip in addrs
        except OSError:
            ok = False
        self._put(key, (time.time(), ok))
