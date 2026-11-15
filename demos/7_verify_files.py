#!/usr/bin/env python3
"""Demo 7: like `sha256sum` / `sha256sum -c`, but the hashing is done by the BeagleBone.
   7_verify_files.py hash DIR > manifest      write "<sha256>  <path>" for every file under DIR
   7_verify_files.py check manifest           re-hash and report OK / CHANGED / MISSING
   7_verify_files.py                          self-test: builds a small tree, hashes it, modifies a file, checks"""
import os, sys, tempfile
import bbc

def digest(path):
    with open(path, "rb") as f:
        return bbc.hash_stream("sha256-bbcrypto", iter(lambda: f.read(16384), b"")).hex()

def walk(root):
    for d, _, files in sorted(os.walk(root)):
        for n in sorted(files):
            yield os.path.join(d, n)

def check(lines):
    bad = 0
    for line in lines:
        h, _, p = line.rstrip("\n").partition("  ")
        try: ok = digest(p) == h
        except FileNotFoundError: print("MISSING", p); bad += 1; continue
        print("OK     " if ok else "CHANGED", p); bad += not ok
    return bad

if len(sys.argv) == 3 and sys.argv[1] == "hash":
    for p in walk(sys.argv[2]): print(digest(p) + "  " + p)
elif len(sys.argv) == 3 and sys.argv[1] == "check":
    sys.exit(1 if check(open(sys.argv[2])) else 0)
else:
    with tempfile.TemporaryDirectory() as d:
        for i in range(4):
            open(f"{d}/file{i}.txt", "wb").write(os.urandom(50_000 * (i + 1)))
        manifest = [digest(p) + "  " + p + "\n" for p in walk(d)]
        before = bbc.board_requests()
        print("1) fresh tree:"); check(manifest)
        open(f"{d}/file1.txt", "ab").write(b"!")                  # someone appends one byte
        os.remove(f"{d}/file3.txt")
        print("2) after tampering with file1 and deleting file3:"); check(manifest)
        print(f"board requests used: {bbc.board_requests() - before}")
