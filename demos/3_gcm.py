#!/usr/bin/env python3
"""Demo 3: AES-GCM (authenticated encryption). A forged or modified message is rejected."""
import errno, os
import bbc

key, iv = os.urandom(16), os.urandom(12)
aad, msg = b"header: user=alice", b"transfer 100 EUR to bob"

sealed = bbc.aead("gcm-aes-bbcrypto", key, iv, aad, msg, bbc.ENCRYPT)       # ciphertext || 16-byte tag
print("sealed by board :", sealed.hex())
ref = bbc.aead("gcm_base(ctr(aes-generic),ghash-generic)", key, iv, aad, msg, bbc.ENCRYPT)
print("PC software GCM gives the same bytes:", sealed == ref)
print("board opens it  :", bbc.aead("gcm-aes-bbcrypto", key, iv, aad, sealed, bbc.DECRYPT))

forged = bytearray(sealed); forged[3] ^= 1                                   # attacker flips one bit
try:
    bbc.aead("gcm-aes-bbcrypto", key, iv, aad, bytes(forged), bbc.DECRYPT)
    print("forged message accepted  <-- BAD")
except OSError as e:
    print("flipped bit  ->", "rejected (EBADMSG: authentication failed)" if e.errno == errno.EBADMSG else e)

try:
    bbc.aead("gcm-aes-bbcrypto", key, iv, b"header: user=mallory", sealed, bbc.DECRYPT)
    print("wrong header accepted  <-- BAD")
except OSError as e:
    print("changed header ->", "rejected (EBADMSG)" if e.errno == errno.EBADMSG else e)
