#!/usr/bin/env python3
"""Local flood test against a throwaway instance with the production limits.
Nothing external is touched. Prints p50/p95/p99 latency, status mix, server
RSS. Usage: python3 tests/flood.py [--n 5000] [--threads 64]"""
import argparse
import collections
import http.client
import ipaddress
import json
import multiprocessing as mp
import os
import random
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import Instance, qs  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=5000)
ap.add_argument("--threads", type=int, default=64)
a = ap.parse_args()
R = random.Random(1)


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] if xs else 0


def _client(port, jobs, threads, q):
    lat, st = [], collections.Counter()
    lock = threading.Lock()
    it = iter(jobs)

    def worker():
        c = None
        while True:
            with lock:
                job = next(it, None)
            if job is None:
                break
            path, ip, ua = job
            t0 = time.perf_counter()
            code = "conn-error"
            for attempt in (1, 2):
                try:
                    if c is None:
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                    c.request("GET", path, headers={"X-Real-IP": ip, "User-Agent": ua})
                    r = c.getresponse()
                    r.read()
                    code = r.status
                    if r.getheader("Connection", "").lower() == "close":
                        c.close()
                        c = None
                    break
                except (OSError, http.client.HTTPException):
                    if c:
                        c.close()
                    c = None
            dt = time.perf_counter() - t0
            with lock:
                lat.append(dt)
                st[code] += 1
    ts = [threading.Thread(target=worker) for _ in range(threads)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    q.put((lat, st))


def run(f, jobs, conns):
    """jobs: (path, ip[, ua]). conns keep-alive connections, spread over 8
    client processes so the client's own GIL does not distort latency."""
    jobs = [j if len(j) == 3 else (*j, "flood-test/1.0") for j in jobs]
    procs = min(8, conns)
    q = mp.Queue()
    ps = [mp.Process(target=_client, args=(f.port, jobs[i::procs], max(1, conns // procs), q)) for i in range(procs)]
    t0 = time.perf_counter()
    [p.start() for p in ps]
    res = [q.get() for _ in ps]
    [p.join() for p in ps]
    lat = sum((r[0] for r in res), [])
    st = sum((r[1] for r in res), collections.Counter())
    return lat, st, time.perf_counter() - t0


def report(name, f, lat, st, secs, rss0):
    rss = f.rss_kb()
    print(f"{name}: {len(lat)} req in {secs:.1f} s = {len(lat) / secs:.0f} req/s | p50 {pct(lat, .5) * 1000:.1f} ms "
          f"p95 {pct(lat, .95) * 1000:.1f} ms p99 {pct(lat, .99) * 1000:.1f} ms max {max(lat) * 1000:.0f} ms | "
          f"status {dict(st)} | RSS {rss0 // 1024}->{rss // 1024} MB", flush=True)


f = Instance()   # production defaults from forum.py DEFAULTS
try:
    seed_ips = [f"198.51.100.{i}" for i in range(1, 60)]
    for i in range(40):
        f.get("/post?" + qs(board="general", name=f"seed{i}", text=f"seed thread {i} with some words in it {R.random()}"), ip=seed_ips[i])
        f.get(f"/wiki/Seed{i}?" + qs(edit=f"seed page {i} {R.random()}"), ip=seed_ips[i])
    time.sleep(1.5)
    print("rss at start:", f.rss_kb() // 1024, "MB")
    paths = ["/", "/b/general", "/t/1", "/t/5", "/wiki/", "/wiki/Seed3", "/feed.txt", "/api/posts.json", "/kv",
             "/api/observatory.json?window=24h", "/api/observatory.json?window=1h", "/observatory", "/static/site.css",
             "/howto.txt", "/api/wiki.json", "/api/search.json?q=seed"]
    crowd = [str(ipaddress.ip_address("203.0.113.0") + R.randrange(256)) if R.random() < .5 else
             str(ipaddress.ip_address("198.51.100.0") + R.randrange(256)) for _ in range(512)]

    uas = [f"Mozilla/5.0 agent-{i} (compatible; ExampleBot/{i}.0)" for i in range(128)]
    people = [(ip, R.choice(uas)) for ip in crowd]

    rss0 = f.rss_kb()
    lat, st, secs = run(f, [(R.choice(paths), *R.choice(people)) for _ in range(2000)], 4)
    report("0 baseline, 4 concurrent, 512 clients", f, lat, st, secs, rss0)

    time.sleep(6)   # let the global bucket refill
    rss0 = f.rss_kb()
    lat, st, secs = run(f, [(R.choice(paths), *R.choice(people)) for _ in range(a.n)], a.threads)
    report("A mixed reads, 512 clients x 128 UAs, flat out", f, lat, st, secs, rss0)

    rss0 = f.rss_kb()
    lat, st, secs = run(f, [(R.choice(paths), "203.0.113.250") for _ in range(a.n)], a.threads)
    report("B one IP flooding", f, lat, st, secs, rss0)

    rss0 = f.rss_kb()
    jobs = [(f"/?bust={R.random()}", str(ipaddress.ip_address("2001:db8::") + (R.getrandbits(48) << 64)))
            for _ in range(a.n * 4)]
    lat, st, secs = run(f, jobs, a.threads)
    report(f"C {a.n * 4} distinct IPv6 /64s, cache-busting", f, lat, st, secs, rss0)

    rss0 = f.rss_kb()
    lat, st, secs = run(f, [(f"/post?{qs(board='sandbox', text=f'flood write {i} {R.random()}')}", *R.choice(people)) for i in range(a.n // 5)], a.threads)
    report("D write flood, 512 clients", f, lat, st, secs, rss0)

    # E: slowloris from 20 untrusted peers x 10 sockets while a crowd reads
    held = []
    for peer in range(20):
        for _ in range(10):
            s = socket.socket()
            s.bind((f"127.0.1.{peer + 1}", 0))
            s.settimeout(2)
            try:
                s.connect(("127.0.0.1", f.port))
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
                held.append(s)
            except OSError:
                s.close()
    rss0 = f.rss_kb()
    time.sleep(6)
    lat, st, secs = run(f, [(R.choice(paths), *R.choice(people)) for _ in range(a.n // 2)], 16)
    report(f"E reads during slowloris ({len(held)} half-open sockets)", f, lat, st, secs, rss0)
    for s in held:
        s.close()
    stats = json.loads(f.admin("GET", "/stats")[1])
    print("server stats:", {k: stats[k] for k in ("hits", "uas", "dropped", "limited", "limiter_keys", "connections", "rejected_connections")})
    print("db size:", sum(os.path.getsize(os.path.join(f.dir, x)) for x in os.listdir(f.dir) if x.startswith("forum.sqlite3")) // 1024, "kB")
    print("final RSS:", f.rss_kb() // 1024, "MB")
finally:
    f.stop()
