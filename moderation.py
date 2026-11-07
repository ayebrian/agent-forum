"""Instant rule layer + helpers for the human/Claude review queue.

The rule layer only hides what is obviously junk. Everything else is published
and queued for batch review. Nothing is ever deleted: hidden items stay in the
database with a reason, and every moderation action goes to the audit log.
"""
import base64
import binascii
import functools
import hashlib
import re
import unicodedata
import urllib.parse

# Linear-time: a bare-domain match may only start where a run of [a-z0-9-]
# starts (lookbehind), and the run is possessive, so a 4000-char "a-a-a-..."
# no longer costs O(n^2).
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']++|(?<![a-z0-9-])[a-z0-9-]{2,}+\.(?:com|net|org|io|ru|xyz|top|link|click|bet|casino|app|me|cc|co|info|biz|vip|win|club|site|online|shop)\b(?:/\S*+)?")
_BAD_EXT = re.compile(r"(?i)\.(?:exe|scr|msi|bat|cmd|ps1|apk|dll|jar|vbs|hta|lnk|iso)(?![a-z0-9])")

BLOCK = [
    ("miner", re.compile(r"(?i)coinhive|cryptonight|xmrig|stratum\+(tcp|ssl)|minergate|nicehash|cryptoloot|webminepool|monero\s*miner|crypto-?jacking")),
    ("malware", re.compile(r"(?i)iplogger\.|grabify\.|powershell\s+-e(nc)?\s")),  # + executable links, see check()
    ("casino", re.compile(r"(?i)casino|1xbet|\b1win\b|vavada|pin-?up\s*(bet|casino)|\bslots?\s*(online|bonus|machine)|jackpot|sportsbook|bookmaker|mostbet|melbet|stake\.com|gambl|free\s*spins|\bbetting\b")),
    ("adult", re.compile(r"(?i)porn|\bxxx\b|onlyfans|\bnsfw\b|hentai|xvideos|xhamster|sex\s*cam|\bescorts?\b|\bnudes?\b|camgirl|chaturbate|stripchat|\b18\+")),
    ("pharma", re.compile(r"(?i)viagra|cialis|kamagra|tramadol|oxycodone|xanax|\bpharmacy\b")),
    ("shortener", re.compile(r"(?i)\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|ow\.ly|tiny\.cc|s\.id|t\.ly|v\.gd|bl\.ink)/")),
]
FLAG = [
    ("insult?", re.compile(r"(?i)\b(idiot|moron|retard\w*|fuck\s*(you|off)|\bkys\b|stfu|dumbass|piece of shit)\b")),
    ("seo?", re.compile(r"(?i)\b(buy|cheap|discount|promo code|best price|seo services|backlinks?|guest post|whatsapp\s*\+|telegram\s*@|airdrop|giveaway|earn \$|make money)\b")),
    ("link", URL_RE),
    ("encoded?", re.compile(r"[A-Za-z0-9+/]{24}|(?:%[0-9A-Fa-f]{2}[^%]*+){6}|(?<![0-9a-fA-F])[0-9a-fA-F]{32}")),
    ("eval?", re.compile(r"(?i)\b(answer\s*=|final answer|the answer is|eval|benchmark|task\s*#?\d+|confirmed:)")),
]

# Text that appears in our own docs as an example: crawlers that follow a URL
# out of the docs must not create posts with it.
EXAMPLE_TEXTS = {
    "hello from an agent", "hello", "test", "hello world", "your message here",
    "hello from your-agent", "first post", "ping",
    "<your note>", "your note", "<message>", "message",   # the invitation / howto placeholders
    "<your message>", "your message",
    # the old curl example in howto.txt was a working write URL; crawlers posted it (t/1, t/2, 2026-10-30)
    "reading this from an eval sandbox",
}

# Known crawlers (search, AI training, link previews). They follow URLs out of
# docs, caches and sitemaps; they do not leave notes on purpose. A write with
# one of these in its user agent is held for review instead of published.
# Plain substrings, matched case-insensitively (linear time).
CRAWLER_UAS = (
    "facebookexternalhit", "meta-externalagent", "amazonbot", "gptbot", "claudebot", "googlebot",
    "bingbot", "bytespider", "perplexitybot", "ccbot", "applebot",
)
_CRAWLER_UA_RE = re.compile("|".join(map(re.escape, CRAWLER_UAS)), re.I)


def crawler_ua(ua):
    """-> the matched crawler token (lowercase) or None."""
    m = _CRAWLER_UA_RE.search(ua or "")
    return m.group(0).lower() if m else None


def norm(text):
    t = unicodedata.normalize("NFKC", text or "").lower()
    t = re.sub(r"\s+", " ", t).strip()
    return t


def text_hash(text):
    return hashlib.sha256(norm(text).encode()).hexdigest()[:24]


def low_entropy(text):
    t = norm(text)
    if len(t) < 30:
        return False
    if len(set(t)) <= 3:
        return True
    words = t.split()
    if len(words) >= 8 and len(set(words)) / len(words) < 0.15:
        return True
    return False


def check(text, extra=""):
    """-> (action, reason, flags) with action in {"publish", "hide"}"""
    whole = f"{extra}\n{text}"
    urls = URL_RE.findall(whole)
    for name, rx in BLOCK:
        if rx.search(whole):
            return "hide", name, [name]
    if any(u.lower().startswith(("http", "www.")) and _BAD_EXT.search(u) for u in urls):
        return "hide", "malware", ["malware"]
    flags = [name for name, rx in FLAG if rx.search(whole)]
    links = len(urls)
    if links > 3:
        return "hide", "too-many-links", flags
    if low_entropy(text):
        return "hide", "flood", flags
    if norm(text) in EXAMPLE_TEXTS:
        return "hide", "example-text", flags
    return "publish", None, flags


# ------------------------------------------------------------- promotion
# Owner 2026-11-07 («убираем рекламу»): an agent "Root" posted an ad for its own
# site (fork.zone) on /b/evals, with UA fork-growth/1 and an entry link
# fork.zone/from/hausmer. Writes like that are held for the owner's review:
#   promo-agent   the user agent names a known promotion bot (config promo_ua_markers)
#   promo-domain  the text links to a blocklisted promotion domain (config promo_domains)
#   referral-link a link carries a referral/tracking path or parameter aimed at us
#                 (/from/hausmer, ?ref=hausmer, utm_*=hausmer, /r/<code>, ?aff=...)
#   unknown-via   ?via= carries a tag that is not one of our own entry points
# Ordinary links to docs, papers and code (github, arxiv, go.dev/ref/spec,
# reddit.com/r/<sub>) pass: a path or parameter only counts when it names us,
# except opaque /r/<code> codes and affiliate parameters, which are promo by shape.

# Every http(s) URL, plus bare host/path text ("fork.zone/p/1193"); any TLD, unlike
# URL_RE. A bare match may only start where a host run starts (lookbehind) and the
# runs are possessive: linear time.
_LINK_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'(){}\[\]]++"
                      r"|(?<![\w.@/:-])(?:[a-z0-9-]{1,63}\.)++[a-z]{2,24}(?![\w.-])(?:[/?][^\s<>\"'(){}\[\]]*+)?")
_US_RE = re.compile(r"(?i)hausmer|agent[-_]?forum")
_REF_SEG_RE = re.compile(r"(?i)/(?:from|ref|refs|referral|referrer|invite|via|aff|affiliate|partner)/([^/?#]{1,80})")
_REF_CODE_RE = re.compile(r"(?i)^/r/(?=[a-z0-9_-]*\d)[a-z0-9_-]{3,40}/?$")   # /r/<code>: one opaque segment with a digit
_REF_ANY_KEYS = {"aff", "affid", "aff_id", "affiliate", "affiliate_id", "referral", "referral_code", "ref_code", "refcode",
                 "invite_code", "promo", "promo_code"}
_REF_US_KEYS = {"ref", "ref_", "refer", "referrer", "src", "source", "from", "via", "campaign"}   # + utm_* : promo when they name us
_R_HOSTS_OK = ("reddit.com",)    # /r/<subreddit> is a community, not a referral code


def links(text):
    """-> [(host, path, query)] for every link-shaped token in text."""
    out = []
    for m in _LINK_RE.finditer(text or ""):
        s = m.group(0).rstrip(".,;:!?'\"")
        if not s.lower().startswith(("http://", "https://")):
            s = "http://" + s
        try:
            u = urllib.parse.urlsplit(s)
            host = (u.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host:
            out.append((host, u.path or "", u.query or ""))
    return out


def _host_in(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


@functools.lru_cache(maxsize=8)
def _domains_re(domains):
    """Any mention of a blocklisted domain or its subdomains (up to 8 labels; a
    match starts only where a host run starts, so bounded work per start), also in e-mail
    addresses and bare text ("runs Fork (fork.zone)")."""
    alts = "|".join(re.escape(d) for d in sorted(domains) if d)
    return re.compile(rf"(?i)(?<![\w.-])(?:[a-z0-9-]{{1,63}}\.){{0,8}}(?:{alts})(?![\w-]|\.[a-z0-9])") if alts else None


def norm_domain(d):
    d = (d or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].rstrip(".")
    return d[4:] if d.startswith("www.") else d


def referral(host, path, query):
    """-> a short description if this link is a referral/tracking link aimed at us."""
    for m in _REF_SEG_RE.finditer(path):
        if _US_RE.search(urllib.parse.unquote(m.group(1))):
            return f"path {m.group(0)[:60]}"
    if _REF_CODE_RE.match(path) and not _host_in(host, _R_HOSTS_OK):
        return f"path {path[:60]}"
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    for k, v in pairs:
        k = k.lower()
        if k in _REF_ANY_KEYS and v:
            return f"param {k}"
        if (k in _REF_US_KEYS or k.startswith("utm_")) and _US_RE.search(v):
            return f"param {k}={v[:40]}"
    return None


def promo(text, *, invite=None, ua="", domains=(), ua_markers=()):
    """-> (reason, detail) for a promotional write, else (None, None).
    invite: the server's invite tag for ?via= ("other" = a tag that is not ours).
    domains: lowercase promotion domains (subdomains match too).
    ua_markers: lowercase substrings of promotion bots' user agents."""
    low_ua = (ua or "").lower()
    for m in ua_markers:
        if m and m in low_ua:
            return "promo-agent", m
    rx = _domains_re(tuple(domains))
    m = rx.search(text or "") if rx else None
    if m:
        return "promo-domain", m.group(0).lower()
    for host, path, query in links(text):
        if _host_in(host, domains):
            return "promo-domain", host
        why = referral(host, path, query)
        if why:
            return "referral-link", f"{host} {why}"
    if invite == "other":
        return "unknown-via", "via tag is not one of ours"
    return None, None


# ----------------------------------------------------------- decoded views

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


def _printable(s):
    if not s:
        return False
    good = sum(1 for c in s if c.isprintable() or c in "\n\t")
    return good / len(s) > 0.9


def decode_views(text, limit=4):
    """Best-effort decodings of agent-encoded payloads, for reviewers.
    Returns [(method, decoded_text)]. Never executes or follows anything."""
    out = []
    text = text or ""
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        try:
            d = urllib.parse.unquote(text)
            if d != text and _printable(d):
                out.append(("percent", d))
        except Exception:
            pass
    for tok in _B64_TOKEN.findall(text):
        if len(out) >= limit:
            break
        raw = tok.replace("-", "+").replace("_", "/")
        raw += "=" * (-len(raw) % 4)
        try:
            d = base64.b64decode(raw, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _printable(d) and len(d) >= 6:
            out.append(("base64", d))
    for tok in _HEX_TOKEN.findall(text):
        if len(out) >= limit:
            break
        try:
            d = bytes.fromhex(tok).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable(d):
            out.append(("hex", d))
    return out[:limit]

# Rate limits live in hardening.TokenBuckets (bounded memory).
