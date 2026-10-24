# Shared body of the agents.example.com server blocks. Goes to /etc/nginx/.

# Not a Cloudflare edge: close the connection without a byte.
if ($agents_via_cf = 0) {
    return 444;
}

# Visitor address from CF-Connecting-IP, believed only from Cloudflare edges.
include /etc/nginx/agents-cf-realip.inc;       # set_real_ip_from <cidr>;
real_ip_header CF-Connecting-IP;
real_ip_recursive off;

server_tokens off;
client_max_body_size 1k;                       # GET-only site; bodies are never forwarded anyway
client_header_timeout 10s;                     # slowloris
client_body_timeout 10s;
send_timeout 15s;
keepalive_timeout 30s;
large_client_header_buffers 4 32k;             # app max_request_line = 32768 (Cloudflare itself caps URLs near 16 KB)

access_log off;                                # the app keeps its own request log (owner view); no second copy of visitor IPs
error_log /var/log/nginx/agents.error.log warn;

# nginx's own answers (rate limit, app down): short text, same security headers as the app.
error_page 429 /__agents_429;
error_page 502 503 504 =503 /__agents_down;

location = /__agents_429 {
    internal;
    default_type "text/plain; charset=utf-8";
    add_header Retry-After 10 always;
    include /etc/nginx/agents-headers.inc;
    return 429 "too many requests; retry in a few seconds\n";
}

location = /__agents_down {
    internal;
    default_type "text/plain; charset=utf-8";
    add_header Retry-After 30 always;
    include /etc/nginx/agents-headers.inc;
    return 503 "temporarily unavailable\n";
}

location / {
    limit_req zone=agents_req burst=40 nodelay;    # app's own buckets are finer (5 r/s, burst 60, per IP/ASN/UA)
    limit_req_status 429;
    limit_conn agents_conn 20;
    limit_conn_status 429;

    proxy_pass http://127.0.0.1:8795;              # public app only; never the owner listener
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;       # the visitor (after real_ip); the app trusts it from loopback only
    # Nothing else that could carry a claimed address or identity reaches the app.
    proxy_set_header X-Forwarded-For "";
    proxy_set_header Forwarded "";
    proxy_set_header CF-Connecting-IP "";
    proxy_set_header True-Client-IP "";
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

    add_header Strict-Transport-Security "max-age=15552000" always;   # this host only (no includeSubDomains)
}
