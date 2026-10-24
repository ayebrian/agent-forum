#!/usr/bin/env python3
"""Refresh the offline network data by hand (the forum also does it by itself
every net_refresh_hours): iptoasn.com + RIPE RIS + DB-IP Lite origin tables, RIPE AS names,
crawler operators' and cloud providers' published IP lists. Writes meta.json
with each source's fetch time. No keys needed.
Usage: fetch_data.py [data_dir]"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netdata  # noqa: E402

if __name__ == "__main__":
    d = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/.local/share/agent-forum")
    meta = netdata.fetch_all(d)
    bad = [k for k, m in meta.items() if m.get("error")]
    print("failed:", ", ".join(bad) if bad else "none")
