#!/usr/bin/env python3
"""End-to-end check of the deploy kit without touching /etc: runs the real
nginx binary as the current user on 127.0.0.1:<port> in front of a throwaway
app, once per mode.

  cloudflare  deploy/nginx/*.conf/*.inc as is; in the test copy 127.0.0.1
              plays a Cloudflare edge and 127.0.0.2 a client that bypasses it
  direct      files rendered by deploy/nginx/render.py from the app config
              (edge = "direct"); clients connect straight to nginx

Usage: python3 tests/nginx_e2e.py [cloudflare|direct]"""
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import Instance, free_port, qs  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"
H = {"Host": "agents.example.com"}
ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""), flush=True)


def req(port, path, source="127.0.0.1", headers=None, method="GET", body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5, source_address=(source, 0))
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        c.close()


def raw_closed(port, source, payload):
    """True if nginx closes without sending a byte (444)."""
    s = socket.socket()
    s.bind((source, 0))
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    s.sendall(payload)
    try:
        data = s.recv(100)
    except ConnectionResetError:
        data = b""
    s.close()
    return data == b""


def start_nginx(d, vhost_glob):
    for t in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
        os.makedirs(os.path.join(d, t), exist_ok=True)
    with open(os.path.join(d, "nginx.conf"), "w") as f:
        f.write(f"""
pid {d}/nginx.pid;
error_log {d}/error.log;
events {{ worker_connections 512; }}
http {{
    default_type application/octet-stream;
    access_log off;
    client_body_temp_path {d}/body; proxy_temp_path {d}/proxy; fastcgi_temp_path {d}/fastcgi;
    uwsgi_temp_path {d}/uwsgi; scgi_temp_path {d}/scgi;
    include {vhost_glob};
}}
""")
    args = ["-p", d, "-c", os.path.join(d, "nginx.conf"), "-e", os.path.join(d, "error.log")]
    t = subprocess.run([NGINX, "-t", *args], capture_output=True, text=True)
    check("nginx -t accepts the vhost", t.returncode == 0, t.stderr[-400:])
    ng = subprocess.Popen([NGINX, *args, "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    return ng


def common_checks(app, port, client, visitor_ip, extra_headers):
    """Checks that hold in both modes. client = source address of the test
    client; visitor_ip = what the app must record for it."""
    spoof = {"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8", "Forwarded": "for=9.9.9.9",
             "True-Client-IP": "8.8.4.4", "Tailscale-User-Login": "owner@github", **extra_headers}
    st, h, body = req(port, "/post?" + qs(board="sandbox", text="through nginx, spoofed headers", format="json"),
                      source=client, headers={**H, **spoof})
    check("write through the proxy works", st == 200, (st, body[:120]))
    if st == 200:
        item = json.loads(app.admin("GET", f"/item/{json.loads(body)['id']}.json")[1])
        check(f"app records {visitor_ip}; spoofed X-Real-IP/XFF/Forwarded/True-Client-IP ignored",
              item["ip"] == visitor_ip, item["ip"])
    check("security headers pass through", h.get("content-security-policy", "").startswith("default-src 'none'"))
    check("no nginx version in Server header", not re.search(r"nginx/\d", h.get("server", "")), h.get("server"))
    check("HSTS added for this host", "max-age=15552000" in h.get("strict-transport-security", ""))
    st, h, body = req(port, "/", source=client, headers=H, method="POST", body=b"x" * 900)
    check("POST: app answers 405, body never forwarded", st == 405, st)
    st, h, body = req(port, "/", source=client, headers=H, method="POST", body=b"x" * 5000)
    check("body over 1k refused by nginx (413)", st == 413, st)
    st, h, body = req(port, "/ips", source=client, headers=H)
    check("owner routes do not exist through the proxy", st == 404, st)


def flood_and_down(app, port, flood_kw, other_kw):
    hdr429 = None
    for _ in range(120):
        st, h, body = req(port, "/robots.txt", **flood_kw)
        if st == 429 and b"few seconds" in body:
            hdr429 = h
    check("nginx limit_req answers 429 under a flood", hdr429 is not None)
    check("nginx 429 carries CSP + nosniff", hdr429 is not None and "default-src 'none'" in hdr429.get("content-security-policy", "")
          and hdr429.get("x-content-type-options") == "nosniff")
    check("other visitors unaffected", req(port, "/robots.txt", **other_kw)[0] == 200)
    app.proc.terminate()
    app.proc.wait(5)
    st, h, body = req(port, "/", **other_kw)
    check("app down: 503 plain text with CSP", st == 503 and b"temporarily unavailable" in body
          and "default-src 'none'" in h.get("content-security-policy", ""), (st, body[:80]))
    check("app down page has no nginx/version/paths", not re.search(rb"nginx|/home/|/etc/|\d+\.\d+\.\d+\.\d+", body), body[:200])


def cloudflare_mode():
    print("== cloudflare mode (deploy/nginx as is)")
    app = Instance()
    d = tempfile.mkdtemp(prefix="afng-")
    port = free_port()
    ng = None
    try:
        src = os.path.join(REPO, "deploy", "nginx")
        for f in ("agents-common.inc", "agents-headers.inc"):
            t = open(os.path.join(src, f)).read().replace("/etc/nginx/", d + "/")
            t = t.replace("/var/log/nginx/agents.error.log", d + "/error.log").replace("127.0.0.1:8795", f"127.0.0.1:{app.port}")
            open(os.path.join(d, f), "w").write(t)
        conf = open(os.path.join(src, "agent-forum.conf")).read().replace("/etc/nginx/", d + "/")
        conf = conf.replace("    listen 80;\n    listen [::]:80;", f"    listen 127.0.0.1:{port};")
        open(os.path.join(d, "vhost.conf"), "w").write(conf)
        # stand-in for the Cloudflare range files: 127.0.0.1 is "Cloudflare"
        open(os.path.join(d, "agents-cf-geo.inc"), "w").write("127.0.0.1/32 1;\n")
        open(os.path.join(d, "agents-cf-realip.inc"), "w").write("set_real_ip_from 127.0.0.1/32;\n")
        ng = start_nginx(d, os.path.join(d, "vhost.conf"))
        check("direct (non-Cloudflare) peer: connection closed, no response (444)",
              raw_closed(port, "127.0.0.2", b"GET / HTTP/1.1\r\nHost: agents.example.com\r\nCF-Connecting-IP: 203.0.113.9\r\n\r\n"))
        common_checks(app, port, "127.0.0.1", "203.0.113.77", {"CF-Connecting-IP": "203.0.113.77"})
        flood_and_down(app, port, {"headers": {**H, "CF-Connecting-IP": "198.51.100.77"}},
                       {"headers": {**H, "CF-Connecting-IP": "198.51.100.78"}})
    finally:
        if ng:
            ng.terminate()
            ng.wait(5)
        app.stop()
        shutil.rmtree(d, ignore_errors=True)


def direct_mode():
    print("== direct mode (rendered by deploy/nginx/render.py, edge = \"direct\")")
    app = Instance(edge="direct", direct_listen="127.0.0.1", site_name="agents.example.com")
    d = tempfile.mkdtemp(prefix="afng-")
    port = free_port()
    ng = None
    try:
        build = os.path.join(d, "build")
        r = subprocess.run([sys.executable, os.path.join(REPO, "deploy", "nginx", "render.py"),
                            "--config", os.path.join(app.dir, "config.toml"), "--out", build,
                            "--etc", os.path.join(build, "nginx"), "--logs", d, "--test-port", str(port)],
                           capture_output=True, text=True)
        check("render.py renders direct mode", r.returncode == 0, r.stderr)
        text = "".join(open(os.path.join(root, f)).read() for root, _, fs in os.walk(build) for f in fs)
        text = re.sub(r"#[^\n]*", "", text)   # directives only
        check("rendered files: no real_ip, no Cloudflare allowlist", not re.search(r"real_ip|agents_via_cf|cf-geo", text))
        check("rendered files: limit_req + limit_conn per visitor and per site",
              all(x in text for x in ("zone=agentsd_ip", "zone=agentsd_site ", "agentsd_conn 20", "agentsd_site_conn 512")))
        ng = start_nginx(d, os.path.join(build, "conf.d", "*.conf"))
        check("unknown Host: connection closed, no response (444)",
              raw_closed(port, "127.0.0.2", b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"))
        # The client is 127.0.0.2 talking straight to nginx; every header that claims another address is spoofed.
        common_checks(app, port, "127.0.0.2", "127.0.0.2", {"CF-Connecting-IP": "203.0.113.77", "X-Client-IP": "7.7.7.7"})
        # a client coming from a Cloudflare-looking hop gains nothing either: CF-Connecting-IP is never read
        st, h, body = req(port, "/post?" + qs(board="sandbox", text="claims to be behind cloudflare", format="json"),
                          source="127.0.0.3", headers={**H, "CF-Connecting-IP": "203.0.113.78"})
        item = json.loads(app.admin("GET", f"/item/{json.loads(body)['id']}.json")[1]) if st == 200 else {}
        check("CF-Connecting-IP ignored in direct mode", item.get("ip") == "127.0.0.3", item.get("ip"))
        flood_and_down(app, port, {"source": "127.0.0.4", "headers": H}, {"source": "127.0.0.5", "headers": H})
    finally:
        if ng:
            ng.terminate()
            ng.wait(5)
        app.stop()
        shutil.rmtree(d, ignore_errors=True)


modes = sys.argv[1:] or ["cloudflare", "direct"]
if "cloudflare" in modes:
    cloudflare_mode()
if "direct" in modes:
    direct_mode()
print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
