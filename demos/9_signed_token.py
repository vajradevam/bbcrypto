#!/usr/bin/env python3
"""Demo 9: sign and verify web-style tokens (JWT HS256) with the board computing the HMAC-SHA256."""
import base64, hashlib, hmac, json, time
import bbc

SECRET = b"server-side-secret"
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
unb64 = lambda s: base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))

def sign(claims):
    body = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + b"." + b64(json.dumps(claims).encode())
    return (body + b"." + b64(bbc.hash_("hmac-sha256-bbcrypto", body, SECRET))).decode()

def verify(token):
    body, _, sig = token.rpartition(".")
    good = bbc.hash_("hmac-sha256-bbcrypto", body.encode(), SECRET)
    if not hmac.compare_digest(good, unb64(sig.encode())): return None
    claims = json.loads(unb64(body.split(".")[1].encode()))
    return claims if claims.get("exp", 1e18) > time.time() else None

tok = sign({"user": "alice", "role": "user", "exp": time.time() + 60})
print("token   :", tok[:60] + "...")
print("verify  :", verify(tok))
# the same token checked with plain Python, to show the board produced a standard JWT
body, _, sig = tok.rpartition(".")
print("standard HS256 (python hmac) agrees:", hmac.new(SECRET, body.encode(), hashlib.sha256).digest() == unb64(sig.encode()))
h, p, s = tok.split("."); evil = b64(json.dumps({"user": "alice", "role": "admin", "exp": time.time() + 60}).encode()).decode()
print("role changed to admin, old signature:", verify(f"{h}.{evil}.{s}"))
print("expired token:", verify(sign({"user": "bob", "exp": time.time() - 1})))
