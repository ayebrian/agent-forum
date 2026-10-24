#!/usr/bin/env python3
"""Render the nginx files for the deploy mode set in config.toml (`edge`),
the single switch:

  edge = "cloudflare"  the Cloudflare kit in deploy/nginx/ as is
  edge = "direct"      no CDN: nginx binds direct_listen (the container IP),
                       visitor = TCP peer, TLS from Let's Encrypt on this box,
                       limit_req/limit_conn are the flood defence

Usage: render.py [--config config.toml] [--out deploy/nginx/build]
                 [--etc /etc/nginx] [--logs /var/log/nginx] [--test-port N]
Writes OUT/conf.d/* and OUT/nginx/* and prints the install commands.
--test-port is for tests/nginx_e2e.py: plain HTTP on 127.0.0.1:N, no TLS."""
import argparse
import ipaddress
import os
import shutil
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CF_CONF = "agent-forum.conf"
DIRECT_CONF = "agent-forum.direct.conf"
CF_INCS = ("agents-common.inc", "agents-headers.inc", "agents-cf-geo.inc", "agents-cf-realip.inc")

ap = argparse.ArgumentParser()
ap.add_argument("--config", default=os.environ.get("AGENT_FORUM_CONFIG", os.path.join(REPO, "config.toml")))
ap.add_argument("--out", default=os.path.join(HERE, "build"))
ap.add_argument("--etc", default="/etc/nginx")
ap.add_argument("--logs", default="/var/log/nginx")
ap.add_argument("--test-port", type=int)
a = ap.parse_args()

cfg = {"edge": "cloudflare", "site_name": "agents.example.com", "listen": "127.0.0.1:8795", "direct_listen": ""}
with open(a.config, "rb") as f:
    cfg.update(tomllib.load(f))
edge, name = cfg["edge"], cfg["site_name"]
if edge not in ("cloudflare", "direct"):
    sys.exit('edge must be "cloudflare" or "direct"')
up_host = cfg["listen"].rsplit(":", 1)[0].strip("[]")
try:
    if not ipaddress.ip_address(up_host).is_loopback:
        raise ValueError
except ValueError:
    sys.exit("listen (the app) must be a loopback address; nginx is the only thing in front of it")

shutil.rmtree(a.out, ignore_errors=True)
os.makedirs(os.path.join(a.out, "conf.d"))
os.makedirs(os.path.join(a.out, "nginx"))

if edge == "cloudflare":
    if a.test_port:
        sys.exit("--test-port is for direct mode (tests/nginx_e2e.py checks the Cloudflare kit as is)")
    shutil.copy(os.path.join(HERE, CF_CONF), os.path.join(a.out, "conf.d", CF_CONF))
    for inc in CF_INCS:
        shutil.copy(os.path.join(HERE, inc), os.path.join(a.out, "nginx", inc))
    other = DIRECT_CONF
else:
    addrs = cfg["direct_listen"]
    addrs = [addrs] if isinstance(addrs, str) else list(addrs)
    addrs = [x.strip().strip("[]") for x in addrs if x and x.strip()]
    if not addrs:
        sys.exit('direct mode needs direct_listen = "<container IP>" in config.toml')
    for x in addrs:
        try:
            ip = ipaddress.ip_address(x)
        except ValueError:
            sys.exit(f"direct_listen: {x!r} is not a literal IP address")
        if ip.is_unspecified:
            sys.exit("direct_listen: never a wildcard (0.0.0.0 / ::); bind the container IP")
        if ip.is_loopback and not a.test_port:
            sys.exit("direct_listen: a loopback address is not reachable from outside")

    def lst(port, extra=""):
        if a.test_port:
            return f"    listen 127.0.0.1:{a.test_port}{extra};\n"
        return "".join(f"    listen {f'[{x}]' if ':' in x else x}:{port}{extra};\n" for x in addrs)

    head = f"""# {name}, DIRECT mode (no Cloudflare in front). Rendered by deploy/nginx/render.py
# from config.toml (edge = "direct"); edit the template or config, not this file.
# Visitor = TCP peer. No real_ip, no Cloudflare allowlist; CF-Connecting-IP and
# all other forwarding headers are dropped before the app.

limit_req_zone  $binary_remote_addr zone=agentsd_ip:10m        rate=10r/s;
limit_req_zone  $server_name        zone=agentsd_site:1m       rate=300r/s;
limit_conn_zone $binary_remote_addr zone=agentsd_conn:10m;
limit_conn_zone $server_name        zone=agentsd_site_conn:1m;

# Unknown Host on these addresses: close without a byte.
server {{
{lst(80, " default_server")}    server_name _;
    return 444;
}}
"""
    if a.test_port:
        servers = f"""
server {{
{lst(80)}    server_name {name};
    include {a.etc}/agents-direct-common.inc;
}}
"""
    else:
        servers = f"""
# Unknown SNI: no certificate is shown at all.
server {{
{lst(443, " ssl default_server")}    server_name _;
    ssl_reject_handshake on;
}}

server {{
{lst(80)}    server_name {name};
    server_tokens off;
    client_header_timeout 10s;
    location / {{
        limit_req zone=agentsd_ip burst=40 nodelay;
        limit_conn agentsd_conn 20;
        return 301 https://{name}$request_uri;
    }}
}}

server {{
{lst(443, " ssl")}    http2 on;
    server_name {name};
    ssl_certificate     /etc/letsencrypt/live/{name}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{name}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:agentsd_tls:5m;
    ssl_session_tickets off;
    include {a.etc}/agents-direct-common.inc;
}}
"""
    with open(os.path.join(a.out, "conf.d", DIRECT_CONF), "w") as f:
        f.write(head + servers)
    tpl = open(os.path.join(HERE, "direct", "agents-direct-common.inc")).read()
    tpl = tpl.replace("{{UPSTREAM}}", cfg["listen"]).replace("{{ETC}}", a.etc).replace("{{LOGS}}", a.logs)
    with open(os.path.join(a.out, "nginx", "agents-direct-common.inc"), "w") as f:
        f.write(tpl)
    shutil.copy(os.path.join(HERE, "agents-headers.inc"), os.path.join(a.out, "nginx", "agents-headers.inc"))
    other = CF_CONF

print(f"mode: {edge} ({name}) -> {a.out}")
if edge == "direct" and not a.test_port:
    print(f"first time only (before nginx serves {name}): sudo certbot certonly --standalone -d {name} "
          "--pre-hook 'systemctl stop nginx' --post-hook 'systemctl start nginx'")
print(f"sudo rm -f {a.etc}/conf.d/{other}            # the other mode's vhost, if present")
print(f"sudo cp {a.out}/conf.d/* {a.etc}/conf.d/ && sudo cp {a.out}/nginx/* {a.etc}/")
print("sudo nginx -t && sudo systemctl reload nginx")
