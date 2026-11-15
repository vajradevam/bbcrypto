#!/usr/bin/env python3
"""Demo 10: how fast is the board compared with this PC's CPU? (spoiler: a lot slower, USB 2.0 is the limit)"""
import hashlib, os, time
import bbc

def mbps(fn, size, reps):
    t = time.time()
    for _ in range(reps): fn()
    return size * reps / (time.time() - t) / 1e6

key, iv = os.urandom(16), os.urandom(16)
print(f"{'operation':28}{'size':>10}{'board MB/s':>13}{'CPU MB/s':>11}")
for size in (1024, 16384, 131072):   # one AF_ALG request must fit the socket buffer (~200 KiB)
    d = os.urandom(size); reps = max(3, 400_000 // size)
    rows = [
        ("sha256", lambda: bbc.hash_("sha256-bbcrypto", d), lambda: hashlib.sha256(d).digest()),
        ("aes-128-cbc encrypt", lambda: bbc.cipher("cbc-aes-bbcrypto", key, iv, d, bbc.ENCRYPT),
                                lambda: bbc.cipher("cbc(aes-generic)", key, iv, d, bbc.ENCRYPT)),
        ("aes-128-ctr encrypt", lambda: bbc.cipher("ctr-aes-bbcrypto", key, iv, d, bbc.ENCRYPT),
                                lambda: bbc.cipher("ctr(aes-generic)", key, iv, d, bbc.ENCRYPT)),
    ]
    if size <= 16384:
        n12 = iv[:12]
        rows.append(("aes-128-gcm seal", lambda: bbc.aead("gcm-aes-bbcrypto", key, n12, b"", d, bbc.ENCRYPT),
                     lambda: bbc.aead("gcm_base(ctr(aes-generic),ghash-generic)", key, n12, b"", d, bbc.ENCRYPT)))
    for name, board, cpu in rows:
        print(f"{name:28}{size:>10}{mbps(board, size, reps):>13.2f}{mbps(cpu, size, reps):>11.1f}")
print("\n(CPU column = the kernel's generic C implementation through the same AF_ALG path, not AES-NI)")
