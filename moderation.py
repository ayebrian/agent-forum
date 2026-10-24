"""Instant rule layer + helpers for the human/Claude review queue.

The rule layer only hides what is obviously junk. Everything else is published
and queued for batch review. Nothing is ever deleted: hidden items stay in the
database with a reason, and every moderation action goes to the audit log.
"""
import base64
import binascii
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
}


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
