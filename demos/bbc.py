"""Tiny helpers shared by the demos: talk to the kernel crypto API over AF_ALG sockets by driver name."""
import glob, socket, struct
from typing import Iterable

SOL_ALG = 279
ALG_SET_KEY, ALG_SET_IV, ALG_SET_OP, ALG_SET_AEAD_ASSOCLEN, ALG_SET_AEAD_AUTHSIZE = 1, 2, 3, 4, 5
ENCRYPT = 1
DECRYPT = 0


def board_requests() -> int | None:
    """How many requests the driver has sent to the board so far (from its sysfs file)."""
    for f in glob.glob("/sys/bus/usb/drivers/bbcrypto/*/stats"):
        for line in open(f):
            if line.startswith("requests"):
                return int(line.split()[1])
    return None


def hash_(driver: str, data: bytes, key: bytes | None = None) -> bytes:
    """Digest of `data` using the algorithm implementation named `driver` (e.g. 'sha256-bbcrypto')."""
    typ = "hash"
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind((typ, driver))
    if key is not None:
        s.setsockopt(SOL_ALG, ALG_SET_KEY, key)
    op, _ = s.accept()
    op.sendall(data)
    out = op.recv(64)
    op.close(); s.close()
    return out


def cipher(driver: str, key: bytes, iv: bytes | None, data: bytes, op: int) -> bytes:
    """AES via an skcipher driver such as 'cbc-aes-bbcrypto'. op = ENCRYPT or DECRYPT."""
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("skcipher", driver))
    s.setsockopt(SOL_ALG, ALG_SET_KEY, key)
    o, _ = s.accept()
    anc = [(SOL_ALG, ALG_SET_OP, struct.pack("I", op))]
    if iv:
        anc.append((SOL_ALG, ALG_SET_IV, struct.pack("I", len(iv)) + iv))
    o.sendmsg([data], anc)
    out = o.recv(len(data))            # exactly the output size: a bigger buffer makes the kernel wait for more input
    o.close(); s.close()
    return out


def aead(driver: str, key: bytes, iv: bytes, aad: bytes, data: bytes, op: int, tag: int = 16) -> bytes:
    """GCM. encrypt: data=plaintext -> ciphertext||tag.  decrypt: data=ciphertext||tag -> plaintext (OSError EBADMSG if forged)."""
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", driver))
    s.setsockopt(SOL_ALG, ALG_SET_KEY, key)
    s.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, tag)
    o, _ = s.accept()
    anc = [(SOL_ALG, ALG_SET_OP, struct.pack("I", op)),
           (SOL_ALG, ALG_SET_IV, struct.pack("I", len(iv)) + iv),
           (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", len(aad)))]
    o.sendmsg([aad + data], anc)
    n = len(aad) + len(data) + (tag if op == ENCRYPT else -tag)   # exact output size, see cipher()
    out = o.recv(n)
    o.close(); s.close()
    return out[len(aad):]


def hash_stream(driver: str, chunks: Iterable[bytes], key: bytes | None = None) -> bytes:
    """Digest of data given piece by piece (any size, e.g. a big file). Each piece is a separate USB command batch."""
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("hash", driver))
    if key is not None:
        s.setsockopt(SOL_ALG, ALG_SET_KEY, key)
    op, _ = s.accept()
    prev = None
    for c in chunks:                       # hold back one piece so the last send can omit MSG_MORE
        if prev is not None:
            op.send(prev, socket.MSG_MORE)
        prev = c
    op.send(prev or b"")
    out = op.recv(64)
    op.close(); s.close()
    return out
