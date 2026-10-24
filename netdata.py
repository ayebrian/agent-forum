"""Fetch and refresh the offline network data, recording when each piece was
fetched (meta.json). No API keys, no paid sources. Used by the forum's
background refresher and by tools/fetch_data.py.

Sources (all free; licences checked 2026-10-23):
  iptoasn     iptoasn.com ip2asn-combined.tsv.gz   range -> origin ASN, cc, AS name.
              Public domain (ODC PDDL 1.0), rebuilt hourly.
  ris4/ris6   RIPE NCC RIS riswhoisdump.IPv{4,6}.gz  prefix -> origin ASN with the
              number of RIS peers that see it. Independent BGP collectors; free
              public RIPE NCC data, rebuilt every few hours.
  asnames     RIPE NCC ftp.ripe.net/ripe/asnames/asn.txt  ASN -> registry name, cc
              (all five RIRs), rebuilt daily.
  dbip        DB-IP "IP to ASN Lite" dbip-asn-lite-YYYY-MM.csv.gz  range -> ASN, AS
              organisation. Third, independent vote. CC BY 4.0, no account
              (checked 2026-10-24, https://db-ip.com/db/download/ip-to-asn-lite);
              attribution required: pages that show results link to db-ip.com.
              Released monthly; we look for this month's file, else last
              month's, and download only when the release changed (ETag).
  crawler lists  each operator's own published IP-range JSON (OpenAI, Google,
              Microsoft/Bing, Anthropic, Perplexity, Apple, DuckDuckGo,
              Common Crawl, Mistral) -> ranges.json
  cloud lists    providers' own published ranges (AWS, Google Cloud, Azure,
              Oracle, Cloudflare, DigitalOcean, Fastly, Akamai/Linode) -> clouds.json

Every file is downloaded to a temp name, validated (decompresses, enough rows,
parses) and only then renamed into place, so a failed or truncated download
never replaces good data. A failed source keeps its previous file AND its
previous fetch time, so it ages and is eventually treated as stale.
"""
import gzip
import hashlib
import io
import json
import os
import re
import calendar
import email.utils
import time
import urllib.error
import urllib.request

UA = "agent-forum-data-fetch/2.0"

BULK = {
    # name: (url, file, min_rows)
    "iptoasn": ("https://iptoasn.com/data/ip2asn-combined.tsv.gz", "ip2asn-combined.tsv.gz", 300_000),
    "ris4": ("https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz", "riswhoisdump.IPv4.gz", 500_000),
    "ris6": ("https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz", "riswhoisdump.IPv6.gz", 100_000),
    "asnames": ("https://ftp.ripe.net/ripe/asnames/asn.txt", "asn.txt", 50_000),
}

# DB-IP IP to ASN Lite (CC BY 4.0, attribution: link to https://db-ip.com).
DBIP_URL = "https://download.db-ip.com/free/dbip-asn-lite-{ym}.csv.gz"
DBIP_FILE = "dbip-asn-lite.csv.gz"
DBIP_MIN_ROWS = 300_000

# Crawler operators' own lists. Name -> url (or list of urls).
CRAWLERS = {
    "openai-gptbot": "https://openai.com/gptbot.json",
    "openai-chatgpt-user": "https://openai.com/chatgpt-user.json",
    "openai-searchbot": "https://openai.com/searchbot.json",
    "googlebot": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
    "google-special": "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
    "google-user": ["https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
                    "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json"],
    "bingbot": "https://www.bing.com/toolbox/bingbot.json",
    "anthropic-bots": "https://claude.com/crawling/bots.json",
    "perplexitybot": "https://www.perplexity.com/perplexitybot.json",
    "perplexity-user": "https://www.perplexity.com/perplexity-user.json",
    "applebot": "https://search.developer.apple.com/applebot.json",
    "duckduckbot": "https://duckduckgo.com/duckduckbot.json",
    "ccbot": "https://index.commoncrawl.org/ccbot.json",
    "mistral-user": "https://mistral.ai/mistralai-user-ips.json",
    "cloudflare": ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
}

# Cloud providers' own lists. Provider label -> url(s); special parsers below.
CLOUDS = {
    "Amazon AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "Google Cloud": "https://www.gstatic.com/ipranges/cloud.json",
    "Microsoft Azure": "azure:https://www.microsoft.com/en-us/download/details.aspx?id=56519",
    "Oracle Cloud": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
    "Cloudflare": ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
    "DigitalOcean": "https://www.digitalocean.com/geo/google.csv",
    "Fastly": "https://api.fastly.com/public-ip-list",
    "Akamai Linode": "https://geoip.linode.com/",
}

CIDR = re.compile(r"(?<![\w:.])(?:(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}/\d{1,3})(?![\w:.])")
AZURE_LINK = re.compile(r"https://download\.microsoft\.com/[^\"' ]*ServiceTags_Public_\d{8}\.json")


def get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def published_date(raw):
    """creationTime / syncToken from the JSON lists that carry one."""
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    if isinstance(d, dict):
        for k in ("creationTime", "createDate", "syncToken", "last_updated_timestamp"):
            if d.get(k):
                return str(d[k])[:40]
    return None


def cidrs_from(raw):
    """Prefixes from a JSON list (ipv4Prefix/ipv6Prefix/ip_prefix/...) or text."""
    text = raw.decode("utf-8", "replace")
    out = set()
    try:
        d = json.loads(text)
    except ValueError:
        d = None
    if d is not None:
        def walk(x):
            if isinstance(x, dict):
                for k, v in x.items():
                    if isinstance(v, str) and k.lower() in ("ipv4prefix", "ipv6prefix", "ip_prefix", "ipv6_prefix", "cidr", "addresses"):
                        out.update(CIDR.findall(v))
                    else:
                        walk(v)
            elif isinstance(x, list):
                for v in x:
                    if isinstance(v, str):
                        out.update(CIDR.findall(v))
                    else:
                        walk(v)
        walk(d)
        return sorted(out)
    for line in text.splitlines():
        out.update(CIDR.findall(line.split(",")[0]))   # csv: prefix first
    return sorted(out)


def azure_cidrs(page_url):
    raw = get(page_url)
    m = AZURE_LINK.search(raw.decode("utf-8", "replace"))
    if not m:
        raise ValueError("no ServiceTags_Public link on the download page")
    data = get(m.group(0), 120)
    d = json.loads(data)
    out = set()
    for v in d.get("values", []):
        if v.get("name") == "AzureCloud":   # the whole public Azure address space
            out.update(v.get("properties", {}).get("addressPrefixes", []))
    if not out:
        raise ValueError("AzureCloud tag missing")
    return sorted(out), m.group(0).rsplit("_", 1)[-1][:8], data


def _read_meta(data_dir):
    try:
        with open(os.path.join(data_dir, "meta.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=0, sort_keys=True)
    os.replace(tmp, path)


def _dbip_months(now):
    """This month and the previous one, 'YYYY-MM' (the new file appears early in the month)."""
    t = time.gmtime(now)
    y, m = t.tm_year, t.tm_mon
    py, pm = (y, m - 1) if m > 1 else (y - 1, 12)
    return [f"{y:04d}-{m:02d}", f"{py:04d}-{pm:02d}"]


def fetch_dbip(data_dir, prev, now, timeout=180):
    """-> (meta fields dict, log line). Raises when no release could be fetched.
    Conditional GET: an unchanged release (same URL + ETag) is not downloaded
    again, only marked as checked. 'published' = the release's Last-Modified;
    freshness is judged on that, not on our fetch time."""
    path = os.path.join(data_dir, DBIP_FILE)
    last_err = None
    for ym in _dbip_months(now):
        url = DBIP_URL.format(ym=ym)
        headers = {"User-Agent": UA}
        if prev.get("url") == url and prev.get("etag") and os.path.exists(path):
            headers["If-None-Match"] = prev["etag"]
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                etag, lm = r.headers.get("ETag", ""), r.headers.get("Last-Modified", "")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return {"rows": prev.get("rows"), "published": prev.get("published"),
                        "published_ts": prev.get("published_ts"), "etag": prev.get("etag"), "url": url}, \
                    f"dbip: {ym} unchanged (304)"
            e.close()
            last_err = e
            continue   # 404: this month's file is not out yet
        rows = _count_rows(raw, True)
        if rows < DBIP_MIN_ROWS:
            raise ValueError(f"only {rows} rows (< {DBIP_MIN_ROWS}), keeping the previous file")
        try:
            pts = int(email.utils.parsedate_to_datetime(lm).timestamp()) if lm else 0
        except (TypeError, ValueError):
            pts = 0
        if not pts:   # no Last-Modified: the 1st of the release month
            pts = calendar.timegm(time.strptime(ym + "-01", "%Y-%m-%d"))
        with open(path + ".tmp", "wb") as f:
            f.write(raw)
        os.replace(path + ".tmp", path)
        return {"rows": rows, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()[:16], "etag": etag,
                "published": time.strftime("%Y-%m-%d", time.gmtime(pts)), "published_ts": pts, "url": url}, \
            f"dbip: {ym} {rows} rows, {len(raw) / 1e6:.1f} MB (released {time.strftime('%Y-%m-%d', time.gmtime(pts))})"
    raise last_err or ValueError("no DB-IP release found")


def _count_rows(raw, gz):
    data = gzip.decompress(raw) if gz else raw
    return sum(1 for line in io.BytesIO(data) if line[:1] not in (b"%", b"#", b"\n", b""))


def fetch_all(data_dir, log=print, only=None):
    """Refresh everything (or the names in `only`). Returns the new meta."""
    os.makedirs(data_dir, exist_ok=True)
    meta = _read_meta(data_dir)
    now = int(time.time())

    def note(name, ok, url, **kw):
        m = meta.get(name, {})
        m.update({"url": url, "attempted": now})
        if ok:
            m.update({"fetched": now, "error": ""}, **kw)
        else:
            m["error"] = kw.get("error", "failed")[:200]
        meta[name] = m

    for name, (url, fname, min_rows) in BULK.items():
        if only and name not in only:
            continue
        try:
            raw = get(url, 180)
            rows = _count_rows(raw, fname.endswith(".gz"))
            if rows < min_rows:
                raise ValueError(f"only {rows} rows (< {min_rows}), keeping the previous file")
            p = os.path.join(data_dir, fname)
            with open(p + ".tmp", "wb") as f:
                f.write(raw)
            os.replace(p + ".tmp", p)
            note(name, True, url, rows=rows, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()[:16])
            log(f"{name}: {rows} rows, {len(raw) / 1e6:.1f} MB")
        except Exception as e:   # keep the old file and its old fetch time
            note(name, False, url, error=repr(e))
            log(f"{name}: FAILED {e!r}")

    if not only or "dbip" in only:
        try:
            kw, line = fetch_dbip(data_dir, meta.get("dbip", {}), now)
            url = kw.pop("url")
            note("dbip", True, url, **kw)
            log(line)
        except Exception as e:
            note("dbip", False, (meta.get("dbip") or {}).get("url") or DBIP_URL.format(ym=_dbip_months(now)[0]), error=repr(e))
            log(f"dbip: FAILED {e!r}")

    for kind, table, fname in (("crawler", CRAWLERS, "ranges.json"), ("cloud", CLOUDS, "clouds.json")):
        path = os.path.join(data_dir, fname)
        try:
            with open(path) as f:
                old = json.load(f)
        except (OSError, ValueError):
            old = {}
        out = dict(old)
        for name, urls in table.items():
            key = f"{kind}:{name}"
            if only and key not in only and kind not in only:
                continue
            urls = [urls] if isinstance(urls, str) else urls
            found, pub, err = [], None, ""
            try:
                for u in urls:
                    if u.startswith("azure:"):
                        c, pub, raw = azure_cidrs(u[6:])
                        found += c
                    else:
                        raw = get(u)
                        found += cidrs_from(raw)
                        pub = pub or published_date(raw)
            except Exception as e:
                err = repr(e)
            if found and not err:
                out[name] = sorted(set(found))
                note(key, True, urls[0], count=len(out[name]), published=pub)
                log(f"{key}: {len(out[name])} prefixes (published {pub or '-'})")
            else:
                note(key, False, urls[0], error=err or "no prefixes found")
                log(f"{key}: FAILED {err or 'no prefixes'}; keeping previous list ({len(old.get(name, []))})")
        _write_json(path, out)
    _write_json(os.path.join(data_dir, "meta.json"), meta)
    return meta
