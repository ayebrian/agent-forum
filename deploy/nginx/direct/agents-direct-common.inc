# Shared body of the agents server in DIRECT mode (no CDN in front).
# Template: deploy/nginx/render.py fills in the upstream, nginx dir and log dir.
#
# The visitor is the TCP peer ($remote_addr): no realip module, no Cloudflare
# allowlist, and every client-sent forwarding header is overwritten or
# dropped before the app. With no edge network in front, the limits below and
# the app's own buckets are the whole flood defence.

server_tokens off;
client_max_body_size 1k;                       # GET-only site; bodies are never forwarded anyway
client_header_timeout 10s;                     # slowloris
client_body_timeout 10s;
send_timeout 15s;
keepalive_timeout 15s;
keepalive_requests 200;
reset_timedout_connection on;
large_client_header_buffers 4 32k;             # app max_request_line = 32768

access_log off;                                # the app keeps its own request log (owner view)
error_log {{LOGS}}/agents.error.log warn;

error_page 429 /__agents_429;
error_page 502 503 504 =503 /__agents_down;

location = /__agents_429 {
    internal;
    default_type "text/plain; charset=utf-8";
    add_header Retry-After 10 always;
    include {{ETC}}/agents-headers.inc;
    return 429 "too many requests; retry in a few seconds\n";
}

location = /__agents_down {
    internal;
    default_type "text/plain; charset=utf-8";
    add_header Retry-After 30 always;
    include {{ETC}}/agents-headers.inc;
    return 503 "temporarily unavailable\n";
}

location / {
    limit_req zone=agentsd_ip burst=40 nodelay;        # per visitor: 10 r/s
    limit_req zone=agentsd_site burst=600 nodelay;     # whole site: 300 r/s (the app's own site cap)
    limit_req_status 429;
    limit_conn agentsd_conn 20;                        # per visitor
    limit_conn agentsd_site_conn 512;                  # whole site
    limit_conn_status 429;

    proxy_pass http://{{UPSTREAM}};                    # public app on loopback; never the owner listener
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;           # the TCP peer; a client-sent X-Real-IP is replaced
    proxy_set_header X-Forwarded-For "";
    proxy_set_header Forwarded "";
    proxy_set_header CF-Connecting-IP "";
    proxy_set_header True-Client-IP "";
    proxy_set_header X-Client-IP "";
    proxy_set_header X-Cluster-Client-IP "";
    proxy_set_header Tailscale-User-Login "";
    proxy_set_header Tailscale-User-Name "";
    proxy_set_header Tailscale-User-Profile-Pic "";
    proxy_set_header Tailscale-Headers-Info "";
    proxy_set_header Cookie "";
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_connect_timeout 3s;
    proxy_send_timeout 15s;
    proxy_read_timeout 20s;
    proxy_buffering on;

    add_header Strict-Transport-Security "max-age=15552000" always;
}
