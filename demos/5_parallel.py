#!/usr/bin/env python3
"""Demo 5: many callers at once. The driver keeps several commands on the USB wire and matches replies by tag."""
import hashlib, os, threading, time
import bbc

jobs = [os.urandom(20_000) for _ in range(64)]
res = [None] * len(jobs)
def work(i): res[i] = bbc.hash_("sha256-bbcrypto", jobs[i])

b0 = bbc.board_requests(); t = time.time()
th = [threading.Thread(target=work, args=(i,)) for i in range(len(jobs))]
[x.start() for x in th]; [x.join() for x in th]
dt = time.time() - t
ok = all(res[i] == hashlib.sha256(jobs[i]).digest() for i in range(len(jobs)))
print(f"{len(jobs)} concurrent hashes of 20 KB: all correct = {ok}, {dt:.2f} s, "
      f"{len(jobs)*20_000/dt/1e6:.2f} MB/s, board requests +{bbc.board_requests()-b0}")
