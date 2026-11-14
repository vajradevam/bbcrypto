#!/usr/bin/env python3
"""Demo 4: who answers a plain request for 'sha256'? The crypto API picks the highest priority."""

import bbc

algs, cur = [], {}
for line in open("/proc/crypto"):
    line = line.strip()
    if not line:
        if cur: algs.append(cur); cur = {}
        continue
    k, _, v = line.partition(":"); cur[k.strip()] = v.strip()
rows = sorted((a for a in algs if a.get("name") == "sha256"), key=lambda a: -int(a["priority"]))
print("providers of 'sha256' (highest priority wins):")
for a in rows:
    print(f"  prio {int(a['priority']):4d}  {a['driver']}")
winner = rows[0]["driver"]
print("=> a plain 'sha256' request is served by:", winner)

before = bbc.board_requests()
bbc.hash_("sha256", b"x" * 1000)                       # asks by the generic name only
after = bbc.board_requests()
print("board request counter", before, "->", after, "=>", "went to the BOARD" if after > before else "stayed on this CPU")
print("\nTo make the board the default:  sudo modprobe -r bbcrypto && sudo modprobe bbcrypto prio=400   (then rerun)")
