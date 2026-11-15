# bbcrypto: architecture, source map, build

bbcrypto makes a BeagleBone Black (BBB) look like a crypto accelerator to any Linux PC. A kernel
module on the PC registers algorithms with the **kernel crypto API**; each request is shipped over
USB to a daemon on the board, which runs it on the AM335x **hardware** AES/SHA engines and sends
the result back.

```
 PC (host)                                                      BeagleBone Black
 ─────────                                                      ────────────────
 openssl / dm-crypt / any caller
   │ AF_ALG socket or in-kernel crypto_alloc_*("sha256")
   ▼
 kernel crypto API ── chooses by name, then by priority (prio=50 default; 400 = preferred)
   ▼
 host/bbcrypto.ko                                                bbcryptod (user space)
   skcipher ecb/cbc/ctr(aes)   ── USB bulk OUT: struct bbc_req ──►  FunctionFS ep1 (async reads)
   ahash/shash sha1,sha256,                                        │ one AF_ALG socket per request
     hmac(sha256)              ◄─ USB bulk IN:  struct bbc_resp ──   ▼
   aead gcm(aes)                                                   board kernel crypto API
                                                                   → omap-aes / omap-sha (hardware)
```

The module does **no crypto**. It is a transport plus an adapter from the crypto-API call
conventions to messages. `bbcryptod` is the other end of that transport.

## Source map

| File | What is in it |
|---|---|
| `proto.h` | **Wire protocol**, shared by both sides: `struct bbc_req` / `struct bbc_resp`, opcodes (`BBC_OP_*`), algorithm ids, limits (32 KiB payload). Read this first. |
| `host/bbcrypto.c` | **The kernel module** (one file, in sections, see below). |
| `host/Makefile` | Kbuild: `make -C host KDIR=<kernel build tree>` produces `bbcrypto.ko`. |
| `board/bbcryptod.c` | **Board daemon**: FunctionFS server, AF_ALG client, GCM glue. |
| `board/setup-gadget.sh` | Runs on the board: adds the vendor interface to the USB gadget (configfs), mounts FunctionFS, starts the daemon. Also the only safe way to restart it. |
| `board/*.openrc`, `install.sh`, `build.sh` | OpenRC services, installer (copies to the board), cross-compile script (armv7 musl). |
| `tests/afalg_test.c` | Main suite (520 checks): known-answer vectors, random lengths, roundtrips, independent software references (`*-generic`), priority, concurrency, unplug rotation. |
| `tools/bbcrypt.c` | CLI: `hash`, `hmac`, `enc/dec ecb|cbc|ctr`, `gcm-enc/gcm-dec`; `-b` = in-kernel instead of the board. |
| `tools/board_aes.c` | Runs on the board: proves the AES engine is the hardware one. |
| `scripts/` | `deploy-host.sh` (build/install module on a real machine), `deploy-kernel.sh` (build+install a whole kernel as an extra boot entry), `fetch-sysroot.sh` (Alpine sysroot for cross-building). |
| `Makefile` | Top-level targets, see "Build". |

### Inside `host/bbcrypto.c` (top to bottom)

1. **Parameters**: `prio`, `window` (commands in flight, 1..8), `chunk` (bytes per command).
2. **Device** (`struct bbc_dev`, refcounted): one per bound board; `bbc_get()` picks a live one.
3. **Commands** (`struct bbc_cmd`): one tagged message; submit/queue/`bbc_send` on the OUT urb.
4. **Reply path** (`bbc_rx_complete`): one IN urb always posted; replies matched to commands by tag.
5. **Workers**: one ordered workqueue does every state change (`pump`, `done`, `timeout`, `fail`).
   A timer resends commands whose reply is overdue; the board answers a repeated tag from its
   reply cache so nothing runs twice.
6. **Sync round trip** (`bbc_xfer`): used by shash and by probe.
7. **Hashes** (shash), **AES modes** (async skcipher, big requests cut into chunks and pipelined),
   **ahash** (async), **gcm(aes)** (async AEAD).
8. **Registration / USB glue**: `bbc_register_algs`, sysfs `stats`/`ping`, `bbc_probe`,
   `bbc_disconnect` (fails every pending request with an error; nothing hangs on unplug).

### Inside `board/bbcryptod.c`

AF_ALG helpers, hash sessions (for the streaming hash ops), per-op handlers (`do_hash`,
`do_cipher`, `do_aead`), a software **GHASH** (the board kernel has no AF_ALG AEAD, so GCM =
hardware `ecb`/`ctr(aes)` + software GHASH), then the serving loop: kernel-AIO reads kept queued
at all times (the AM335x MUSB can drop a packet that arrives with no read queued), a reply cache
for retried tags, a writer thread, and FunctionFS setup in `main`.
