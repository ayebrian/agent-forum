"""Hardening shared by every listener.

- security headers on every response (strict CSP, no Server header)
- a bounded HTTP server: global and per-peer connection caps
- slowloris-safe request reading: one deadline for the whole request head,
  a byte budget for it, request-line limit, requests with a body are never
  kept alive (the body is not read)
- token buckets with bounded memory
- a single-flight TTL cache with bounded size and concurrency
- JSON that is safe even if someone embeds it in HTML
- visible rendering of invisible, bidi and tag characters

Python 3.11+ stdlib only.
"""
import collections
import io
import json
import re
import socket
import socketserver
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
PERMISSIONS = ("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), "
               "payment=(), usb=(), browsing-topics=()")
SECURITY_HEADERS = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", PERMISSIONS),
)
_SEC_BLOCK = "".join(f"{k}: {v}\r\n" for k, v in SECURITY_HEADERS)
BUSY_RESPONSE = ("HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 "Content-Length: 5\r\nRetry-After: 5\r\nCache-Control: no-store\r\nConnection: close\r\n"
                 + _SEC_BLOCK + "\r\nbusy\n").encode()

# ------------------------------------------------------------- error log

_elog = {"t": 0.0, "n": 0, "dropped": 0}
_elog_lock = threading.Lock()


def elog(msg):
    """stderr, at most 20 lines per minute (an attacker must not be able to fill the disk)."""
    now = time.monotonic()
    with _elog_lock:
        if now - _elog["t"] > 60:
            if _elog["dropped"]:
                print(f"[elog] {_elog['dropped']} messages dropped in the last minute", file=sys.stderr, flush=True)
            _elog.update(t=now, n=0, dropped=0)
        if _elog["n"] >= 20:
            _elog["dropped"] += 1
            return
        _elog["n"] += 1
    print(str(msg)[:500], file=sys.stderr, flush=True)


# ---------------------------------------------------------- token buckets

class TokenBuckets:
    """Token buckets keyed by strings. Memory is bounded: least recently used
    keys are evicted past max_keys (an evicted key just starts full again)."""

    def __init__(self, max_keys=100_000):
        self.b = collections.OrderedDict()   # key -> (tokens, t)
        self.lock = threading.Lock()
        self.max_keys = max_keys

    def take(self, rules, now=None, cost=1.0):
        """rules: iterable of (key, burst, refill_per_second) or None (skipped).
        Takes `cost` from every bucket only if all of them have it.
        -> (ok, retry_after_s, key_that_failed)"""
        now = time.monotonic() if now is None else now
        with self.lock:
            new = []
            for rule in rules:
                if rule is None:
                    continue
                key, burst, rate = rule
                st = self.b.get(key)
                tokens = burst if st is None else min(burst, st[0] + (now - st[1]) * rate)
                if tokens < cost:
                    return False, max(1, int((cost - tokens) / rate + 0.999)), key
                new.append((key, tokens - cost))
            for key, tokens in new:
                self.b[key] = (tokens, now)
                self.b.move_to_end(key)
            while len(self.b) > self.max_keys:
                self.b.popitem(last=False)
        return True, 0, None

    def __len__(self):
        return len(self.b)


# ------------------------------------------------------- single flight

class Busy(Exception):
    pass


class SingleFlight:
    """TTL cache where at most one thread recomputes a key and at most
    `max_concurrent` recomputations run at once. While a key is being
    recomputed, other callers get the previous value if there is one."""

    def __init__(self, max_entries=128, max_concurrent=2, max_bytes=None):
        self.d = collections.OrderedDict()   # key -> (t, value)
        self.inflight = {}
        self.lock = threading.Lock()
        self.sem = threading.BoundedSemaphore(max_concurrent)
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.gen = 0

    def get(self, key, ttl, fn, *, allow=None, wait=10.0, size=None):
        now = time.monotonic()
        with self.lock:
            hit = self.d.get(key)
            if hit and now - hit[0] < ttl:
                self.d.move_to_end(key)
                return hit[1]
            ev = self.inflight.get(key)
            leader = ev is None
            if leader:
                if allow is not None and not allow():
                    if hit:
                        return hit[1]
                    raise Busy("rate limited")
                ev = self.inflight[key] = threading.Event()
        if not leader:
            if hit:
                return hit[1]
            ev.wait(wait)
            with self.lock:
                hit = self.d.get(key)
            if hit:
                return hit[1]
            raise Busy("timeout")
        try:
            if not self.sem.acquire(timeout=wait):
                if hit:
                    return hit[1]
                raise Busy("busy")
            try:
                gen = self.gen
                val = fn()
            finally:
                self.sem.release()
            if size is None or self.max_bytes is None or size(val) <= self.max_bytes:
                with self.lock:
                    if gen == self.gen:
                        self.d[key] = (time.monotonic(), val)
                        self.d.move_to_end(key)
                        while len(self.d) > self.max_entries:
                            self.d.popitem(last=False)
            return val
        finally:
            with self.lock:
                self.inflight.pop(key, None)
            ev.set()

    def invalidate(self):
        with self.lock:
            self.gen += 1
            self.d.clear()


# ------------------------------------------------------ unicode safety

_CTRL = "\x00-\x08\x0b-\x1f\x7f-\x9f"
_BIDI = "؜‎‏‪-‮⁦-⁩"
_ZW = ("­͏ᅟᅠ឴឵᠋-᠏​‌⁠-⁤⁪-⁯"
       "⠀ㅤ﻿ﾠ￹-￻")
_TAGS = "\U000e0000-\U000e007f\U000e0100-\U000e01ef"
_TEXT_RE = re.compile(f"[{_CTRL}{_BIDI}{_ZW}{_TAGS}‍  ]")
_JSON_RE = re.compile(f"[<>&{_CTRL}{_BIDI}{_ZW}{_TAGS}‍  ]")
_STRICT_EXTRA = re.compile(f"[{_BIDI}{_ZW}{_TAGS}‍︀-️]")


def _u(c):
    return f"[U+{ord(c):04X}]"


def _emojiish(c):
    return bool(c) and (unicodedata.category(c) in ("So", "Sk") or c in "️⃣" or 0x1F3FB <= ord(c) <= 0x1F3FF)


def vis_text(s):
    """For bodies: control, bidi, zero-width, tag and line-separator characters
    become visible [U+XXXX] markers. A zero-width joiner between two emoji is
    kept (emoji sequences). Newlines and tabs stay."""
    if not s:
        return ""

    def sub(m):
        c = m.group(0)
        if c == "‍":
            i = m.start()
            if i > 0 and i + 1 < len(s) and _emojiish(s[i - 1]) and _emojiish(s[i + 1]):
                return c
        return _u(c)
    return _TEXT_RE.sub(sub, s)


def vis_strict(s):
    """For names, subjects, keys, labels, user agents, paths: every character
    that is invisible, formatting, unassigned, private-use or an unusual space
    becomes a visible [U+XXXX] marker. Newlines too."""
    s = "" if s is None else str(s)
    if s.isascii():
        return re.sub(r"[\x00-\x1f\x7f]", lambda m: _u(m.group(0)), s)
    out = []
    for c in s:
        cat = unicodedata.category(c)
        if (cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") or (cat == "Zs" and c != " ")
                or _STRICT_EXTRA.match(c)):
            out.append(_u(c))
        else:
            out.append(c)
    return "".join(out)


def strip_invisible(s):
    """For the Slack digest: drop invisible/bidi/tag characters entirely."""
    return _TEXT_RE.sub(lambda m: "" if m.group(0) not in "\n\t" else m.group(0), s or "")


_CONFUSABLE_SCRIPTS = {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC", "GEORGIAN", "LISU"}


def name_flags(s):
    """Visible warnings for names that may impersonate someone."""
    s = s or ""
    if s.isascii():
        return []
    flags = []
    scripts = set()
    for c in s:
        if c.isalpha():
            n = unicodedata.name(c, "")
            scripts.add(n.split(" ", 1)[0] if n else "?")
    if len(scripts & _CONFUSABLE_SCRIPTS) >= 2:
        flags.append("mixed scripts")
    if unicodedata.normalize("NFKC", s) != s:
        flags.append("look-alike letters")
    if vis_strict(s) != s:
        flags.append("invisible characters")
    return flags


# ----------------------------------------------------------------- JSON

def _jesc(m):
    o = ord(m.group(0))
    if o > 0xFFFF:
        o -= 0x10000
        return "\\u%04x\\u%04x" % (0xD800 + (o >> 10), 0xDC00 + (o & 0x3FF))
    return "\\u%04x" % o


def dumps(obj, indent=None):
    """json.dumps whose output never contains < > & or invisible/bidi
    characters (they are \\u-escaped; the parsed value is unchanged)."""
    s = json.dumps(obj, ensure_ascii=False, indent=indent, separators=None if indent else (",", ":"))
    return _JSON_RE.sub(_jesc, s)


# ------------------------------------------------------- HTTP plumbing

class _Abort(ConnectionAbortedError):
    pass


class _DeadlineRaw(io.RawIOBase):
    """Socket reader that enforces the handler's deadline and byte budget on
    every recv, so a client that trickles bytes cannot hold a thread."""

    def __init__(self, sock, handler):
        self.sock, self.h = sock, handler

    def readable(self):
        return True

    def readinto(self, b):
        h = self.h
        left = h._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request deadline")
        if h._budget <= 0:
            raise _Abort("request head too large")
        self.sock.settimeout(min(left, h.io_timeout))
        n = self.sock.recv_into(b, min(len(b), h._budget))
        h._budget -= n
        return n


ERR_TEXT = {400: "bad request", 403: "forbidden", 404: "not found", 405: "method not allowed",
            408: "request timeout", 411: "length required", 413: "payload too large", 414: "URL too long",
            417: "expectation failed", 431: "request headers too large", 500: "internal error",
            501: "method not supported", 503: "busy", 505: "HTTP version not supported"}


class HardenedHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""
    default_request_version = "HTTP/1.0"
    io_timeout = 10.0
    head_timeout = 10.0
    max_request_line = 32768
    max_head_bytes = 65536
    max_requests_per_conn = 100
    extra_headers = ()

    # --- connection setup: our own reader, no socket.makefile (fd leaks)
    def setup(self):
        self.connection = self.request
        self.connection.settimeout(self.io_timeout)
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        except OSError:
            pass
        self._deadline = time.monotonic() + self.head_timeout
        self._budget = self.max_head_bytes
        self.rfile = io.BufferedReader(_DeadlineRaw(self.connection, self), 8192)
        self.wfile = socketserver._SocketWriter(self.connection)
        self._nreq = 0
        self.has_body = False

    def allow_body(self, n):
        """Called by handlers that do read a (small) body."""
        self._deadline = time.monotonic() + self.io_timeout
        self._budget = n + 1

    def handle_one_request(self):
        self._deadline = time.monotonic() + self.head_timeout
        self._budget = self.max_head_bytes
        self.command, self.request_version, self.requestline = "", self.default_request_version, ""
        try:
            self.raw_requestline = self.rfile.readline(self.max_request_line + 1)
            if len(self.raw_requestline) > self.max_request_line:
                self.close_connection = True
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            words = self.raw_requestline.split()
            if len(words) != 3 or not words[1].startswith(b"/"):
                # HTTP/0.9 (no headers in reply), absolute-form, asterisk-form: refuse.
                self.close_connection = True
                self.send_error(400)
                return
            if not self.parse_request():
                self.close_connection = True
                return
        except (OSError, ValueError):
            self.close_connection = True
            return
        self._nreq += 1
        if self._nreq >= self.max_requests_per_conn:
            self.close_connection = True
        te = self.headers.get("Transfer-Encoding")
        cl = (self.headers.get("Content-Length") or "").strip()
        self.has_body = bool(te) or cl not in ("", "0")
        if self.has_body:
            self.close_connection = True   # the body is never read as a next request
        mname = "do_" + self.command
        if not hasattr(self, mname):
            self.send_error(501)
            return
        self.connection.settimeout(self.io_timeout)
        work = getattr(self.server, "work", None)
        if work is not None and not work.acquire(timeout=self.io_timeout):
            self.send_error(503)
            return
        try:
            getattr(self, mname)()
            self.wfile.flush()
        except OSError:
            self.close_connection = True
        finally:
            if work is not None:
                work.release()

    def handle_expect_100(self):
        self.close_connection = True
        self.send_error(417)
        return False

    # --- responses: no Server header, security headers everywhere
    def send_response(self, code, message=None):
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.0"
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def end_headers(self):
        csp = getattr(self, "csp", None)   # a handler may widen CSP for one response (house 3 only)
        self.csp = None                    # ... and only that one (keep-alive reuses the handler)
        for k, v in SECURITY_HEADERS:
            self.send_header(k, csp if (csp and k == "Content-Security-Policy") else v)
        for k, v in self.extra_headers:
            self.send_header(k, v)
        super().end_headers()

    def send_error(self, code, message=None, explain=None):
        """Plain text, never reflects the request."""
        self.close_connection = True
        body = f"{code} {ERR_TEXT.get(code, 'error')}\n".encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *a):
        pass

    def log_error(self, *a):
        pass


class BoundedHTTPServer(ThreadingHTTPServer):
    """One thread per connection, but at most max_conns connections in total
    and max_per_peer from one peer address (trusted proxies are exempt from the
    per-peer cap). Over the cap: an immediate 503 and close. Reading a request
    head happens outside the work limit, so slow clients do not hold a slot."""
    daemon_threads = True
    request_queue_size = 128
    allow_reuse_address = True

    def __init__(self, addr, handler, *, max_conns=256, max_per_peer=32, trusted_peers=(), max_active=0):
        self.address_family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        # At most max_active requests are processed at once; the rest wait
        # blocked (not runnable), which keeps the GIL from convoying under load.
        self.work = threading.BoundedSemaphore(max_active) if max_active else None
        self.max_conns, self.max_per_peer, self.trusted_peers = max_conns, max_per_peer, set(trusted_peers)
        self._clock = threading.Lock()
        self._active = 0
        self._peers = {}
        self.rejected = 0
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        peer = client_address[0] if client_address else ""
        with self._clock:
            n = self._peers.get(peer, 0)
            over = self._active >= self.max_conns or (peer not in self.trusted_peers and n >= self.max_per_peer)
            if not over:
                self._active += 1
                self._peers[peer] = n + 1
            else:
                self.rejected += 1
        if over:
            try:
                request.settimeout(0.2)
                request.sendall(BUSY_RESPONSE)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        t = threading.Thread(target=self._run, args=(request, client_address, peer), daemon=True)
        try:
            t.start()
        except RuntimeError:   # cannot start a thread: shed load
            self._release(peer)
            self.shutdown_request(request)

    def _release(self, peer):
        with self._clock:
            self._active -= 1
            n = self._peers.get(peer, 1) - 1
            if n <= 0:
                self._peers.pop(peer, None)
            else:
                self._peers[peer] = n

    def _run(self, request, client_address, peer):
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._release(peer)

    def handle_error(self, request, client_address):
        elog(f"listener error: {sys.exc_info()[1]!r}"[:300])

    @property
    def active(self):
        return self._active
