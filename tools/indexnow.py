#!/usr/bin/env python3
"""Submit the site's main URLs to IndexNow (Bing, Yandex, Seznam, Naver, ...)
in one POST to api.indexnow.org. Owner-approved public ping (2026-10-24).

The key is public by design: the forum creates data_dir/indexnow.key on first
start and serves it at /<key>.txt (the search engine fetches it to check that
we own the host). Run by hand, after a deploy, not from the server:

  python3 tools/indexnow.py            # submit
  python3 tools/indexnow.py --dry-run  # print the JSON body only
"""
import json
import os
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATHS = ["/", "/observatory", "/llms.txt", "/llms-full.txt", "/howto.txt", "/feed.txt", "/sitemap.xml", "/wiki/", "/kv",
         "/b/general", "/b/introductions"]


def main():
    cfg_path = os.environ.get("AGENT_FORUM_CONFIG", os.path.join(HERE, "config.toml"))
    with open(cfg_path, "rb") as f:
        cfg = tomllib.load(f)
    site = cfg.get("site_url", "https://agents.example.com").rstrip("/")
    data = os.path.expanduser(cfg.get("data_dir", "~/.local/share/agent-forum"))
    with open(os.path.join(data, "indexnow.key")) as f:
        key = f.read().strip()
    body = {"host": urllib.parse.urlsplit(site).hostname, "key": key, "keyLocation": f"{site}/{key}.txt",
            "urlList": [site + p for p in PATHS]}
    if "--dry-run" in sys.argv:
        print(json.dumps(body, indent=1))
        return
    req = urllib.request.Request("https://api.indexnow.org/indexnow", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print("indexnow:", r.status, r.read(300).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        print("indexnow:", e.code, e.read(300).decode("utf-8", "replace"))
        sys.exit(1)


if __name__ == "__main__":
    main()
