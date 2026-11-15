#!/usr/bin/env python3
"""Demo 8: a small file encryptor. AES-GCM runs on the board, 16 KiB at a time; the key comes from a passphrase.
   8_encrypt_file.py enc IN OUT      8_encrypt_file.py dec IN OUT      (passphrase: env PASS, default 'demo')
   8_encrypt_file.py                 self-test: roundtrip, wrong passphrase, flipped bit, truncated file
Each chunk is bound to its position and to 'is this the last chunk', so reordering or truncation is detected too."""
import errno, hashlib, os, struct, sys, tempfile
import bbc

MAGIC, CH = b"BBC1", 16384

def key_for(salt):
    return hashlib.scrypt(os.environ.get("PASS", "demo").encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

def aad(i, last): return struct.pack(">I?", i, last)
def nonce(fid, i): return fid + struct.pack(">I", i)

def encrypt(src, dst):
    salt, fid = os.urandom(16), os.urandom(8)
    key = key_for(salt)
    data = open(src, "rb").read()
    chunks = [data[i:i + CH] for i in range(0, len(data), CH)] or [b""]
    with open(dst, "wb") as out:
        out.write(MAGIC + salt + fid)
        for i, c in enumerate(chunks):
            sealed = bbc.aead("gcm-aes-bbcrypto", key, nonce(fid, i), aad(i, i == len(chunks) - 1), c, bbc.ENCRYPT)
            out.write(struct.pack(">I", len(sealed)) + sealed)

def decrypt(src, dst):
    blob = open(src, "rb").read()
    assert blob[:4] == MAGIC, "not a bbcrypto file"
    salt, fid, pos = blob[4:20], blob[20:28], 28
    key = key_for(salt)
    parts, i = [], 0
    while pos < len(blob):
        n = struct.unpack(">I", blob[pos:pos + 4])[0]; sealed = blob[pos + 4:pos + 4 + n]; pos += 4 + n
        parts.append(bbc.aead("gcm-aes-bbcrypto", key, nonce(fid, i), aad(i, pos >= len(blob)), sealed, bbc.DECRYPT))
        i += 1
    open(dst, "wb").write(b"".join(parts))

def attempt(label, fn):
    try: fn(); print(f"  {label}: decrypted")
    except OSError as e: print(f"  {label}: REJECTED ({errno.errorcode.get(e.errno, e)})")
    except AssertionError as e: print(f"  {label}: REJECTED ({e})")

if len(sys.argv) == 4 and sys.argv[1] in ("enc", "dec"):
    (encrypt if sys.argv[1] == "enc" else decrypt)(sys.argv[2], sys.argv[3])
else:
    d = tempfile.mkdtemp(); p, e, o = f"{d}/plain", f"{d}/enc", f"{d}/out"
    open(p, "wb").write(os.urandom(100_000))
    encrypt(p, e); print(f"encrypted 100000 bytes -> {os.path.getsize(e)} bytes")
    decrypt(e, o); print("  roundtrip identical:", open(o, "rb").read() == open(p, "rb").read())
    os.environ["PASS"] = "wrong"; attempt("wrong passphrase", lambda: decrypt(e, o)); os.environ["PASS"] = "demo"
    blob = bytearray(open(e, "rb").read()); blob[500] ^= 1; open(f"{d}/flip", "wb").write(blob)
    attempt("one bit flipped", lambda: decrypt(f"{d}/flip", o))
    full = open(e, "rb").read(); cut = 28 + 4 + CH + 16
    open(f"{d}/cut", "wb").write(full[:cut]); attempt("file cut after chunk 1", lambda: decrypt(f"{d}/cut", o))
