#!/usr/bin/env python3
"""Demo 1: hash data on the BeagleBone and check it against Python's own hashlib (on this PC's CPU)."""
import hashlib, hmac, os, time
import bbc

data = os.urandom(100_000)
before = bbc.board_requests()

t = time.time(); board = bbc.hash_("sha256-bbcrypto", data); tb = time.time() - t
t = time.time(); local = hashlib.sha256(data).digest(); tl = time.time() - t
print(f"sha256 of {len(data)} random bytes")
print(f"  board : {board.hex()}   ({tb*1000:.1f} ms)")
print(f"  local : {local.hex()}   ({tl*1000:.1f} ms)")
print("  ->", "MATCH" if board == local else "MISMATCH")

key = b"secret-key"
h_board = bbc.hash_("hmac-sha256-bbcrypto", b"hello", key)
h_local = hmac.new(key, b"hello", hashlib.sha256).digest()
print("hmac-sha256('hello') board == local:", h_board == h_local)

sha1 = bbc.hash_("sha1-bbcrypto", b"abc")
print("sha1('abc') =", sha1.hex(), "(NIST: a9993e364706816aba3e25717850c26c9cd0d89d)")

after = bbc.board_requests()
print(f"driver stats: board requests {before} -> {after} (these hashes really went over USB)")
