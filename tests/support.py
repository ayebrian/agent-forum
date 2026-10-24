"""Test support: throwaway forum instances (own temp dir, own ports, synthetic
network data, fake Tailscale LocalAPI) and small raw-HTTP helpers. Nothing here
touches the real data dir or any external host."""
import csv
import gzip
import http.client
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = "https://agents.example"

# Documentation ranges (RFC 5737 / 3849), classified like real ones would be.
RESIDENTIAL_V4 = "203.0.113.77"            # "Example Residential Broadband" -> isp
RESIDENTIAL_V6 = "2001:db8:abcd:1234::77"  # same ASN, IPv6
CLOUD_V4 = "198.51.100.20"                 # "Example Hosting Cloud Servers" -> cloud
COLOMBIA_V4 = "192.0.2.44"                 # "Colombia Telecomunicaciones" -> isp (regression: COLO)
CF_EDGE = "173.245.48.5"                   # inside Cloudflare's published ranges
ASN_ROWS = [
    ("192.0.2.0", "192.0.2.255", 64502, "CO", "COLOMBIA-TEL - Colombia Telecomunicaciones"),
    ("198.51.100.0", "198.51.100.255", 64501, "ZZ", "EXAMPLE-HOST - Example Hosting Cloud Servers"),
    ("203.0.113.0", "203.0.113.255", 64500, "ZZ", "EXAMPLE-RESI - Example Residential Broadband"),
    ("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 64500, "ZZ", "EXAMPLE-RESI - Example Residential Broadband"),
]
# Second, independent origin source (RIPE RIS dump format): origin, prefix, peers.
RIS_ROWS = [(64502, "192.0.2.0/24", 300), (64501, "198.51.100.0/24", 300), (64500, "203.0.113.0/24", 300),
            (64500, "2001:db8::/32", 300)]
AS_NAMES = {64500: "EXAMPLE-RESI - Example Residential Broadband, ZZ", 64501: "EXAMPLE-HOST - Example Hosting Cloud Servers, ZZ",
            64502: "COLOMBIA-TEL - Colombia Telecomunicaciones, CO"}
CLOUDS = {"Example Cloud": ["198.51.100.0/24"]}    # "the provider's published ranges"


def write_net_data(d, asn_rows=None, ris_rows=None, names=None, clouds=None, ranges=None, fetched=None, skip=(),
                   dbip_rows=None, dbip_published=None):
    """Write every network data file netintel loads, plus meta.json saying
    each was fetched at `fetched` (default: now). `skip` = meta names to leave out.
    dbip_rows (first, last, asn, organisation): the third source, DB-IP; None
    = no DB-IP file at all. dbip_published = its release time (default: `fetched`)."""
    asn_rows = ASN_ROWS if asn_rows is None else asn_rows
    ris_rows = RIS_ROWS if ris_rows is None else ris_rows
    names = AS_NAMES if names is None else names
    clouds = CLOUDS if clouds is None else clouds
    ranges = {} if ranges is None else ranges
    t = int(time.time()) if fetched is None else int(fetched)
    with gzip.open(os.path.join(d, "ip2asn-combined.tsv.gz"), "wt") as f:
        for row in asn_rows:
            f.write("\t".join(map(str, row)) + "\n")
    for fam, fname in ((4, "riswhoisdump.IPv4.gz"), (6, "riswhoisdump.IPv6.gz")):
        with gzip.open(os.path.join(d, fname), "wt") as f:
            f.write("% test dump\n")
            for o, p, n in ris_rows:
                if (":" in p) == (fam == 6):
                    f.write(f"{o}\t{p}\t{n}\n")
    if dbip_rows is not None:
        with gzip.open(os.path.join(d, "dbip-asn-lite.csv.gz"), "wt", newline="") as f:
            w = csv.writer(f)
            for row in dbip_rows:
                w.writerow(row)
    with open(os.path.join(d, "asn.txt"), "w") as f:
        for a, line in sorted(names.items()):
            f.write(f"{a} {line}\n")
    with open(os.path.join(d, "clouds.json"), "w") as f:
        json.dump(clouds, f)
    with open(os.path.join(d, "ranges.json"), "w") as f:
        json.dump(ranges, f)
    meta = {n: {"fetched": t} for n in ("iptoasn", "ris4", "ris6", "asnames")}
    meta.update({f"cloud:{k}": {"fetched": t} for k in clouds})
    meta.update({f"crawler:{k}": {"fetched": t} for k in ranges})
    if dbip_rows is not None:
        meta["dbip"] = {"fetched": t, "published_ts": int(t if dbip_published is None else dbip_published)}
    for n in skip:
        meta.pop(n, None)
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def toml_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml_val(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k} = {toml_val(x)}" for k, x in v.items()) + "}"
    raise TypeError(v)


class FakeTailscaled:
    """Unix-socket LocalAPI stand-in: /localapi/v0/whois?addr=IP:PORT answers
    from a dict {ip: {"login", "name", "tags"}}; unknown IPs get 404."""

    def __init__(self, path):
        self.path, self.idents = path, {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                ip = (q.get("addr") or [""])[0].rsplit(":", 1)[0].strip("[]")
                ident = outer.idents.get(ip)
                if not ident:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"Node": {"ComputedName": ident["name"], "Tags": ident.get("tags") or []},
                                   "UserProfile": {"LoginName": ident["login"]}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        self.srv = S(path, H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class Instance:
    def __init__(self, net=None, **cfg):
        self.dir = tempfile.mkdtemp(prefix="aft-")
        self.port, self.oport = free_port(), free_port()
        write_net_data(self.dir, **(net or {}))
        self.ts = FakeTailscaled(os.path.join(self.dir, "ts.sock"))
        conf = {"site_name": "agents.example", "site_url": SITE, "listen": f"127.0.0.1:{self.port}",
                "owner_listen": f"127.0.0.1:{self.oport}", "owner_allow": ["owner@github"], "data_dir": self.dir,
                "tailscale_socket": os.path.join(self.dir, "ts.sock"), "digest_interval_s": 86400,
                "net_auto_refresh": False}
        conf.update(cfg)
        self.cfg = conf
        path = os.path.join(self.dir, "config.toml")
        with open(path, "w") as f:
            for k, v in conf.items():
                f.write(f"{k} = {toml_val(v)}\n")
        env = dict(os.environ, AGENT_FORUM_CONFIG=path, PYTHONDONTWRITEBYTECODE="1")
        self.log = open(os.path.join(self.dir, "server.log"), "w")
        self.proc = subprocess.Popen([sys.executable, "-u", os.path.join(REPO, "forum.py")], env=env, cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        self.sock = os.path.join(self.dir, "admin.sock")
        t0 = time.time()
        while time.time() - t0 < 20:
            if self.proc.poll() is not None:
                raise RuntimeError("server died:\n" + open(os.path.join(self.dir, "server.log")).read())
            if os.path.exists(self.sock):
                try:
                    st = json.loads(self.admin("GET", "/stats")[1])
                    if st.get("asn_db_rows"):
                        return
                except OSError:
                    pass
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    # --- clients
    def get(self, path, ip=None, headers=None, method="GET", body=None, port=None, source=None, timeout=10):
        h = dict(headers or {})
        if ip:
            h["X-Real-IP"] = ip
        c = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=timeout,
                                       source_address=(source, 0) if source else None)
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            data = r.read()
            return r.status, r.getheaders(), data
        finally:
            c.close()

    def owner(self, path, source, headers=None, method="GET", body=None):
        return self.get(path, headers=headers, method=method, body=body, port=self.oport, source=source)

    def admin(self, method, path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(self.sock)
        s.sendall(f"{method} {path} HTTP/1.1\r\nHost: admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        return int(head.split(b" ", 2)[1]), body.decode("utf-8", "replace")

    def raw(self, payload, source="127.0.0.1", read_timeout=5.0, chunks=None, delay=0.0):
        """Send raw bytes; return everything the server sends until it closes
        (or read_timeout). -> (bytes, closed_by_server, seconds)"""
        s = socket.socket()
        s.bind((source, 0))
        s.settimeout(read_timeout)
        t0 = time.time()
        s.connect(("127.0.0.1", self.port))
        for part in (chunks or [payload]):
            try:
                s.sendall(part)
            except OSError:
                break
            if delay:
                time.sleep(delay)
        data, closed = b"", False
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    closed = True
                    break
                data += chunk
        except (socket.timeout, TimeoutError):
            pass
        except ConnectionResetError:
            closed = True
        s.close()
        return data, closed, time.time() - t0

    def pid(self):
        return self.proc.pid

    def rss_kb(self):
        with open(f"/proc/{self.proc.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        return 0

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.ts.stop()
        self.log.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def hdrs(headers):
    """[(k, v)] -> {lowercase k: [v, ...]}"""
    out = {}
    for k, v in headers:
        out.setdefault(k.lower(), []).append(v)
    return out


def qs(**kw):
    return urllib.parse.urlencode(kw, quote_via=urllib.parse.quote)
