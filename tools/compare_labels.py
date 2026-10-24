#!/usr/bin/env python3
"""Compare network / crawler labels: an old revision vs the current code.
Prints counts only (no IP addresses), so the output can be pasted anywhere.

  --old-rev 38493a0   the pre-8f0ba39 method (iptoasn only + curated names +
                      word regex, ASN counted as crawler proof)
  --old-rev 8f0ba39   any revision that already has NetIntel (iptoasn + RIS
                      must agree): compares describe_ip() old vs new, e.g. the
                      effect of the third source (DB-IP, 2 of 3).

Usage: compare_labels.py <data_dir> [--old-rev 38493a0] [--sample 20000] [--db forum.sqlite3]
"""
import argparse
import importlib.util
import ipaddress
import json
import os
import random
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import netintel  # noqa: E402


def load_old(rev):
    src = subprocess.run(["git", "-C", HERE, "show", f"{rev}:netintel.py"], check=True, capture_output=True, text=True).stdout
    d = tempfile.mkdtemp(prefix="old-netintel-")
    p = os.path.join(d, "netintel_old.py")
    with open(p, "w") as f:
        f.write(src)
    spec = importlib.util.spec_from_file_location("netintel_old", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def norm(s):
    return " ".join((s or "").lower().replace("(isp)", "").replace("(unverified)", "").split())


def sample_ips(ni, n4, n6, seed=1):
    rnd = random.Random(seed)
    out = []
    for v, n in ((4, n4), (6, n6)):
        st, en, _ = ni.a.tables[v]
        if not len(st):
            continue
        for _ in range(n):
            i = rnd.randrange(len(st))
            x = rnd.randint(st[i], en[i])
            out.append(str(ipaddress.ip_address(x)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir")
    ap.add_argument("--old-rev", default="38493a0")
    ap.add_argument("--sample", type=int, default=20000)
    ap.add_argument("--db")
    a = ap.parse_args()
    old = load_old(a.old_rev)
    if hasattr(old, "NetIntel"):
        return compare_netintel(old, a)
    oa = old.AsnDB(os.path.join(a.data_dir, "ip2asn-combined.tsv.gz"))
    oa.load()
    ov = old.Verifier(os.path.join(a.data_dir, "ranges.json"), oa)
    ni = netintel.NetIntel(a.data_dir)
    ni.load()

    def compare(ips, title):
        c = Counter()
        for ip in ips:
            od = oa.describe(oa.asn(ip))
            nd = ni.describe_ip(ip)
            o_full = od["kind"] == "cloud"
            n_full = nd["kind"] == "cloud" and nd["status"] == "verified"
            c["total"] += 1
            nn = nd["name"] or ""
            if not nn or nd["status"] != "verified":
                pass   # counted below as unverified / unknown
            elif norm(od["name"]) == norm(nn):
                pass
            elif (od["asn"] == nd["asn"] and ni.asnames.get(nd["asn"])
                  and netintel.names_agree(od.get("raw") or od["name"], ni.asnames[nd["asn"]], ni.common)):
                c["name reworded (same holder)"] += 1
            elif od["asn"] == nd["asn"] and not ni.a.names.get(od["asn"], ("", ""))[1].count(" "):
                c["name reworded (old had only the AS handle)"] += 1
            else:
                c["network name changed (different holder or AS)"] += 1
            if nd["status"] != "verified":
                c[f"now {nd['status']} (old showed a confident name)" if od["asn"] else f"now {nd['status']}"] += 1
            if nd["label"].startswith("unverified network"):
                c["sources disagree on origin AS"] += 1
            okind = od["kind"]
            nkind = nd["kind"]
            if okind != nkind:
                c[f"kind {okind} -> {nkind}"] += 1
            if o_full and not n_full:
                c["public IP: full -> masked"] += 1
            if n_full and not o_full:
                c["public IP: masked -> full (" + ("provider's published range" if nd.get("provider") else "curated hosting AS") + ")"] += 1
            if od["asn"] and nd["asn"] and od["asn"] != nd["asn"]:
                c["ASN changed"] += 1
        print(f"\n== {title}")
        for k, v in sorted(c.items(), key=lambda x: (x[0] != "total", -x[1])):
            print(f"  {k}: {v}")
        return c

    # 1. the live test set (crawler list IPs, cloud IPs, residential aggregates)
    with open(os.path.join(a.data_dir, "ranges.json")) as f:
        ranges = json.load(f)
    test_ips = []
    for src, cidrs in ranges.items():
        if src != "cloudflare":
            for cidr in cidrs[:3]:
                n = ipaddress.ip_network(cidr, strict=False)
                test_ips.append((src, str(n.network_address + (1 if n.num_addresses > 2 else 0))))
    compare([ip for _, ip in test_ips], f"crawler IPs from operators' published lists ({len(test_ips)})")

    # crawler verification, old vs new, per claimed UA (same IPs, plus each claim from a foreign cloud IP)
    uas = {"GPTBot": "GPTBot/1.2", "ClaudeBot": "ClaudeBot/1.0", "Claude-User": "Claude-User/1.0", "bingbot": "bingbot/2.0",
           "Googlebot": "Googlebot/2.1", "PerplexityBot": "PerplexityBot/1.0", "Bytespider": "Bytespider",
           "meta-externalagent": "meta-externalagent/1.1", "MistralAI-User": "MistralAI-User/1.0"}
    vc = Counter()
    probe = [ip for _, ip in test_ips] + sample_ips(ni, 300, 0, seed=7)
    for name, ua in uas.items():
        ospec = old.classify_ua(ua)["verify"]
        nspec = netintel.classify_ua(ua)["verify"]
        for ip in probe:
            o = ov.verify(ip, ospec) if ospec else "claimed"
            n = ni.verifier.verify(ip, nspec) if nspec else "claimed"
            o_ok, n_ok = o in ("range", "rdns", "asn"), n in netintel.VERIFIED
            if o_ok != n_ok or (o == "claimed") != (n == "claimed"):
                vc[f"{name}: {o} -> {n}"] += 1
    print("\n== crawler verification changes (claimed UA x test IPs)")
    for k, v in sorted(vc.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")

    # 2. random routed addresses
    compare(sample_ips(ni, a.sample, a.sample // 4), f"random routed addresses ({a.sample} v4 + {a.sample // 4} v6)")

    # 3. curated names that the registry contradicts
    print("\n== old curated names vs registry today")
    for asn, name in sorted(old.PROVIDERS.items()):
        reg = ni.asnames.get(asn)
        if asn not in netintel.PROVIDERS or netintel.PROVIDERS[asn][0] != name:
            print(f"  AS{asn}: old '{name}' -> registry '{reg[0] + ' - ' + reg[1] if reg else '?'}'"
                  f"{' (was treated as cloud)' if asn in old.HOSTING_ASNS else ''}")

    # 4. the dev forum's own request log (counts only)
    if a.db and os.path.exists(a.db):
        con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
        ips = [r[0] for r in con.execute("SELECT DISTINCT ip FROM hits WHERE ip IS NOT NULL")]
        compare(ips, f"distinct IPs in the dev forum's request log ({len(ips)})")


def full(d):
    return d["kind"] == "cloud" and d["status"] == "verified"


def compare_netintel(old, a):
    """Old NetIntel (same data dir; it ignores files it does not know) vs new."""
    oni = old.NetIntel(a.data_dir)
    oni.load()
    ni = netintel.NetIntel(a.data_dir)
    ni.load()
    print(f"old {a.old_rev}: {oni.a.loaded_rows} iptoasn rows, {oni.ris_rows} RIS prefixes; "
          f"new: + {ni.c.loaded_rows} DB-IP rows (DB-IP fresh: {ni.fresh('dbip', 'dbip')})")

    def compare(ips, title):
        c = Counter()
        for ip in ips:
            od, nd = oni.describe_ip(ip), ni.describe_ip(ip)
            c["total"] += 1
            c[f"fresh votes: {len(nd.get('votes') or {})}"] += 1
            if od["label"] != nd["label"]:
                c["label changed"] += 1
            ov, nv = od["status"] == "verified", nd["status"] == "verified"
            if ov and not nv:
                c[f"confident -> {nd['status']}"] += 1
            if nv and not ov:
                c[f"{od['status']} -> confident"] += 1
            if ov and nv and od["asn"] != nd["asn"]:
                c["confident, ASN changed"] += 1
            if od["label"].startswith("unverified network") and not nd["label"].startswith("unverified network"):
                c["'sources disagree' resolved by the 3rd vote"] += 1
            if nd["label"].startswith("unverified network") and not od["label"].startswith("unverified network"):
                c["now 'sources disagree'"] += 1
            if nd.get("dissent"):
                c["2 vs 1 (dissent recorded, owner view)"] += 1
                c["  dissenting source: " + "+".join(x["source"] for x in nd["dissent"])] += 1
            if full(od) and not full(nd):
                c["public IP: full -> masked"] += 1
            if full(nd) and not full(od):
                c["public IP: masked -> full"] += 1
            if od["kind"] != nd["kind"]:
                c[f"kind {od['kind']} -> {nd['kind']}"] += 1
        print(f"\n== {title}")
        for k, v in sorted(c.items(), key=lambda x: (x[0] != "total", x[0].startswith("fresh"), -x[1])):
            print(f"  {k}: {v}")
        return c

    with open(os.path.join(a.data_dir, "ranges.json")) as f:
        ranges = json.load(f)
    test_ips = []
    for src, cidrs in ranges.items():
        if src != "cloudflare":
            for cidr in cidrs[:3]:
                n = ipaddress.ip_network(cidr, strict=False)
                test_ips.append(str(n.network_address + (1 if n.num_addresses > 2 else 0)))
    compare(test_ips, f"crawler IPs from operators' published lists ({len(test_ips)})")
    vc = Counter()
    probe = test_ips + sample_ips(ni, 300, 0, seed=7)
    for ua in ("GPTBot/1.2", "ClaudeBot/1.0", "Claude-User/1.0", "bingbot/2.0", "Googlebot/2.1", "PerplexityBot/1.0",
               "MistralAI-User/1.0", "CCBot/2.0", "Applebot/0.1"):
        ospec, nspec = old.classify_ua(ua)["verify"], netintel.classify_ua(ua)["verify"]
        for ip in probe:
            o = oni.verifier.verify(ip, ospec) if ospec else "claimed"
            n = ni.verifier.verify(ip, nspec) if nspec else "claimed"
            vc["same" if o == n else f"{ua}: {o} -> {n}"] += 1
    print("\n== crawler verification (claimed UA x test IPs), old vs new")
    for k, v in sorted(vc.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")
    compare(sample_ips(ni, a.sample, a.sample // 4), f"random routed addresses ({a.sample} v4 + {a.sample // 4} v6)")
    if a.db and os.path.exists(a.db):
        con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
        ips = [r[0] for r in con.execute("SELECT DISTINCT ip FROM hits WHERE ip IS NOT NULL")]
        compare(ips, f"distinct IPs in the dev forum's request log ({len(ips)})")


if __name__ == "__main__":
    main()
