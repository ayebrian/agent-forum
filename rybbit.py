"""Server-side hits to a self-hosted Rybbit (POST /api/track, Rybbit v2.9).

Agents fetch with curl/wget and never run Rybbit's JavaScript tracker, so the
forum reports each request itself. With `Authorization: Bearer <api key>` the
payload's ip_address/user_agent are trusted and Rybbit skips its header,
client-signal, ASN and rate bot layers (its user-agent layer still runs, so
crawlers land in Rybbit's bot views with their identity).

Rules:
- Never slows or breaks a request: submit() is a put_nowait into a bounded
  queue; one daemon thread posts with a short timeout; overflow is dropped
  and counted; after repeated failures the sender pauses (events dropped)
  instead of piling up.
- The caller decides exclusion (owner networks are never submitted) and
  whether the full IP may leave the box; mask_ip() gives the /24 or /48
  network address otherwise.
- Stdlib only. The API key is read from an env file outside the repo and
  never logged.
"""
import ipaddress
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request

MAX = {"pathname": 2048, "querystring": 2048, "referrer": 2048, "user_agent": 512, "hostname": 253,
       "page_title": 512, "event_name": 256, "properties": 2048}


def mask_ip(ip):
    """IPv4 -> the /24 network address, IPv6 -> the /48 one (both still valid IPs
    for Rybbit's schema). None for anything that is not an IP."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    bits = 24 if a.version == 4 else 48
    return str(ipaddress.ip_network(f"{a}/{bits}", strict=False).network_address)


def rybbit_ip(ip, full):
    """What Rybbit gets as ip_address: the address itself only when `full`
    (the forum's public rule: confirmed cloud network or verified crawler),
    else the truncated network."""
    try:
        a = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return None
    return a if full else mask_ip(a)


def read_key(path, env=None):
    """RYBBIT_API_KEY from the environment, else from KEY=value lines in `path`."""
    env = os.environ if env is None else env
    if env.get("RYBBIT_API_KEY"):
        return env["RYBBIT_API_KEY"].strip()
    if not path:
        return ""
    try:
        with open(os.path.expanduser(path)) as f:
            for line in f:
                line = line.strip()
                if line.startswith("RYBBIT_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def event(site_id, *, hostname, pathname, ip=None, user_agent="", referrer="", querystring="",
          etype="pageview", event_name=None, properties=None, page_title=None):
    """One /api/track body, every field clipped to Rybbit's limits (an over-long
    field would fail validation and lose the whole event)."""
    ev = {"type": etype, "site_id": str(site_id), "hostname": hostname, "pathname": pathname or "/"}
    if ip:
        ev["ip_address"] = ip
    if user_agent:
        ev["user_agent"] = user_agent
    if referrer:
        ev["referrer"] = referrer
    if querystring:
        ev["querystring"] = querystring if querystring.startswith("?") else "?" + querystring
    if page_title:
        ev["page_title"] = page_title
    if event_name:
        ev["event_name"] = event_name
    if properties:
        props = dict(properties)
        s = json.dumps(props, ensure_ascii=False, separators=(",", ":"))
        while len(s) > MAX["properties"] and props:   # drop the longest values first, keep valid JSON
            k = max(props, key=lambda x: len(str(props[x])))
            props.pop(k)
            s = json.dumps(props, ensure_ascii=False, separators=(",", ":"))
        if props:
            ev["properties"] = s
    for k, n in MAX.items():
        if k != "properties" and isinstance(ev.get(k), str) and len(ev[k]) > n:
            ev[k] = ev[k][:n]
    if etype == "custom_event" and not ev.get("event_name"):
        ev["event_name"] = "event"
    return ev


class Sender:
    """Bounded queue + one worker thread. Thread-safe submit(); stats() for
    the admin socket. `opener` is injectable for tests."""

    def __init__(self, url, api_key, *, maxsize=2000, timeout=2.0, pause_after=5, pause_s=60.0,
                 opener=None, user_agent="agent-forum/rybbit-sender"):
        self.url = url.rstrip("/") + "/api/track"
        self._key = api_key
        self.q = queue.Queue(maxsize=maxsize)
        self.timeout = float(timeout)
        self.pause_after, self.pause_s = int(pause_after), float(pause_s)
        self._open = opener or urllib.request.build_opener(urllib.request.ProxyHandler({})).open
        self.ua = user_agent
        self.lock = threading.Lock()
        self.s = {"queued": 0, "sent": 0, "dropped_full": 0, "dropped_paused": 0, "failed": 0, "rejected": 0,
                  "last_ok": None, "last_error": None, "last_error_at": None, "paused_until": 0}
        self._fails = 0
        self._thread = None

    def start(self):
        if not self._thread:
            self._thread = threading.Thread(target=self._run, name="rybbit", daemon=True)
            self._thread.start()
        return self

    def submit(self, ev):
        """Never blocks, never raises."""
        try:
            if time.time() < self.s["paused_until"]:
                with self.lock:
                    self.s["dropped_paused"] += 1
                return False
            self.q.put_nowait(ev)
            with self.lock:
                self.s["queued"] += 1
            return True
        except queue.Full:
            with self.lock:
                self.s["dropped_full"] += 1
            return False
        except Exception:
            return False

    def stats(self):
        with self.lock:
            d = dict(self.s)
        d["queue"] = self.q.qsize()
        d["url"] = self.url
        return d

    def _post(self, ev):
        body = json.dumps(ev, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + self._key, "User-Agent": self.ua})
        with self._open(req, timeout=self.timeout) as r:
            r.read(2048)
            return r.status

    def _run(self):
        while True:
            ev = self.q.get()
            try:
                self._post(ev)
                with self.lock:
                    self.s["sent"] += 1
                    self.s["last_ok"] = int(time.time())
                self._fails = 0
            except urllib.error.HTTPError as e:
                # 4xx: this event is bad (or the site/key is): count, keep going, no pause for 400
                with self.lock:
                    self.s["rejected"] += 1
                    self.s["last_error"] = f"HTTP {e.code}"
                    self.s["last_error_at"] = int(time.time())
                if e.code in (401, 403, 404) or e.code >= 500:
                    self._fail()
            except Exception as e:  # down, timeout, refused: never propagate
                with self.lock:
                    self.s["failed"] += 1
                    self.s["last_error"] = type(e).__name__
                    self.s["last_error_at"] = int(time.time())
                self._fail()

    def _fail(self):
        self._fails += 1
        if self._fails >= self.pause_after:
            self._fails = 0
            with self.lock:
                self.s["paused_until"] = time.time() + self.pause_s
            # drop what is waiting: it would only retry into the same outage
            try:
                while True:
                    self.q.get_nowait()
                    with self.lock:
                        self.s["dropped_paused"] += 1
            except queue.Empty:
                pass
