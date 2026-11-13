# bbcrypto - USB crypto accelerator for the kernel crypto API

A BeagleBone Black plugged into the laptop's USB port executes crypto requests for the laptop.
The laptop kernel module registers algorithms with the crypto API; every operation is sent over a
USB bulk pipe to `bbcryptod` on the board, which runs it through the board's own kernel via AF_ALG
(on the AM335x that is the hardware: `omap-sha256`, `cbc-aes-omap`, ...).

| algorithm        | driver name (use with AF_ALG bind) | API |
|------------------|-------------------------------------|-----|
| sha1             | `sha1-bbcrypto`                     | shash (synchronous) |
| sha256           | `sha256-bbcrypto`                   | shash |
| hmac(sha256)     | `hmac-sha256-bbcrypto`              | shash |
| sha1, sha256, hmac(sha256) | `sha1-async-bbcrypto`, `sha256-async-bbcrypto`, `hmac-sha256-async-bbcrypto` | **ahash** (asynchronous; same board sessions) |
| ecb/cbc/ctr(aes) | `ecb-aes-bbcrypto` / `cbc-aes-bbcrypto` / `ctr-aes-bbcrypto` | skcipher, **asynchronous** |
| gcm(aes)         | `gcm-aes-bbcrypto`                  | **aead**, asynchronous, one command per request (aad + data <= 32 KiB) |

Registered at priority 50 (module parameter `prio`), so nothing uses them unless asked by driver
name or `prio` is raised above the in-kernel implementations.

## What the driver is
A loadable Linux USB driver (`struct usb_driver`: id table, probe, disconnect, sysfs) that provides
algorithms to an existing kernel subsystem. Its core is an asynchronous command engine:

```
 crypto request ─► tagged command ─► queue ─► OUT urb ─► board (FunctionFS + AF_ALG)
                                                            │
 crypto completion ◄─ done list ◄─ match by tag ◄─ IN urb ◄─┘   (one IN urb always posted)
```

- up to `window` commands (default 4) are on the wire at once; the board executes them in order, so the
  USB transfer of command N+1 overlaps the crypto of command N;
- replies are matched to commands by tag; a timer resends overdue commands (same tag), and the board
  answers a repeated tag from a 16-entry reply cache instead of executing it twice;
- ciphers are `CRYPTO_ALG_ASYNC`: `encrypt()` returns `-EINPROGRESS`; a large request is cut into
  `chunk`-byte commands (default 16 KiB). ECB, CTR and CBC-*decrypt* chunks are independent and are
  pipelined; CBC-*encrypt* is an inherently serial chain, so it runs one chunk at a time;
- hashes keep the synchronous shash API but run on the same engine, so concurrent callers pipeline;
- several boards can be attached; requests are spread round-robin, hash sessions stay on their board;
- the algorithms stay registered while the module is loaded (the crypto core warns if an algorithm is
  unregistered while a transform exists); with no board attached, requests fail with `-ENODEV`.
- `sysfs`: `stats` (requests, bytes, errors, retries, average latency, in-flight, high-water mark) and
  `ping` (transport-only echo benchmark, see below).

### GCM and how the board does it
The board kernel is built without AF_ALG AEAD support (`CONFIG_CRYPTO_USER_API_AEAD` is off), so
`gcm-aes-omap` cannot be reached from user space. Rather than re-flash a board that has no recovery path,
`bbcryptod` assembles GCM itself: the AES work (hash subkey, tag mask and the CTR keystream) runs on the
AM335x engine through `ecb(aes)` / `ctr(aes)`, and only GHASH is done in software (4-bit table). Tags of
4..16 bytes, any AAD length, forged tags are rejected with `-EBADMSG`. If the board kernel is rebuilt with
AEAD enabled, `do_aead()` can be replaced by one AF_ALG `aead` call.

## Repository layout (everything lives in this directory)

```
proto.h            wire protocol shared by both sides
host/              the Linux kernel module (bbcrypto.c) - runs on the PC
board/             what runs on the BeagleBone: bbcryptod.c (daemon), setup-gadget.sh, OpenRC services,
                   install.sh, build.sh (cross-compile), kernel.config (the board kernel's config)
tests/             afalg_test.c (the functional suite, run against the real board)
tools/             bbcrypt.c (CLI), board_aes.c (hardware proof, runs on the board)
demos/             eleven usage examples (Python + one C) over AF_ALG; `demos/run_all.sh` runs the quick ones
scripts/           deploy-host.sh, deploy-kernel.sh (other machines), fetch-sysroot.sh, bbb-net-up.sh, bbb-internet.sh
docs/ARCHITECTURE.md   how it works, file map
build/             generated, git-ignored: Alpine sysroot (and any kernel trees from deploy-kernel.sh)
```
