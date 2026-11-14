#!/usr/bin/env python3
"""Demo 2: AES-CBC on the board's hardware engine; the PC's own in-kernel AES decrypts it (and the reverse)."""
import os
import bbc

key, iv = os.urandom(32), os.urandom(16)          # AES-256
msg = (b"BeagleBone hardware encrypts this message. " * 40)[:1024]

ct = bbc.cipher("cbc-aes-bbcrypto", key, iv, msg, bbc.ENCRYPT)       # on the board
print("plaintext :", msg[:44], "...")
print("ciphertext:", ct[:24].hex(), "...  (encrypted by the board)")

back = bbc.cipher("cbc(aes-generic)", key, iv, ct, bbc.DECRYPT)      # decrypted by this PC's kernel
print("PC kernel decrypts the board's ciphertext correctly:", back == msg)

ct2 = bbc.cipher("cbc(aes-generic)", key, iv, msg, bbc.ENCRYPT)      # encrypted by the PC
print("board ciphertext == PC ciphertext:", ct == ct2)
back2 = bbc.cipher("cbc-aes-bbcrypto", key, iv, ct2, bbc.DECRYPT)   # decrypted by the board
print("board decrypts the PC's ciphertext correctly:", back2 == msg)

# FIPS-197 known answer, AES-128 ECB
k = bytes.fromhex("000102030405060708090a0b0c0d0e0f"); p = bytes.fromhex("00112233445566778899aabbccddeeff")
print("FIPS-197 vector:", bbc.cipher("ecb-aes-bbcrypto", k, None, p, bbc.ENCRYPT).hex(), "(expected 69c4e0d86a7b0430d8cdb78070b4c55a)")
