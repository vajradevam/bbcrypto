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

## Exact steps

**0. What you need.** A BeagleBone Black whose kernel has the options in `board/kernel.config` (the ones that
matter: `CRYPTO_DEV_OMAP_AES`, `CRYPTO_DEV_OMAP_SHA`, USB gadget with configfs + FunctionFS, MUSB) and an
OpenRC userland (we use Alpine 3.24) reachable as `root@192.168.7.2` (`scripts/bbb-net-up.sh` gives the PC side of
that link its address). On the PC: gcc, make, clang + lld, curl, and kernel headers for whatever kernel you
load the module into.

**1. Build everything and put the daemon on the board** (the PC is not modified):

```
make                 # module, tests, and the armv7 daemon (downloads an Alpine musl sysroot to build/)
make install-board   # BOARD=192.168.7.2 BOARD_PASS=...: daemon + OpenRC services; originals are kept on the board
```

**2. Install and test on the machine the board is plugged into** (Linux, headers installed):

```
make deploy HOST=user@machine        # builds against that machine's running kernel, installs, loads, tests
make lint typecheck                 # static checks, no hardware needed (see CONTRIBUTING.md, docs/STANDARD.md)
```

If that machine's kernel has no headers or no AF_ALG AEAD, `scripts/deploy-kernel.sh user@machine build|install`
first builds and installs a matching kernel as an extra, one-shot boot entry (see the end of this file).

**3. Use it:** `bbcrypt hash sha256 file`, `bbcrypt gcm-enc ...` (`-b` = same thing in the kernel, to compare), or
any program through AF_ALG by driver name. `insmod bbcrypto.ko prio=400` makes ordinary `sha256`/`aes` requests
use the board. Throughput is about 2.8 MB/s: this is an OS/driver project, not a speed-up.

Everything is rebuilt from a clean checkout; the daemon binary comes out identical to the one on the board.

## Running it
Board: install `board/bbcrypto.openrc` as `/etc/init.d/bbcrypto` and `rc-update add bbcrypto default`; it runs
after the `usbgadget` service and before networking/sshd, so the interface is added at every boot.
Manual control: `rc-service bbcrypto start|stop|restart` (stop unbinds the USB gadget before killing the
daemon; run it detached, the link drops briefly). `setup-gadget.sh` is the older manual equivalent.
Cross-build the daemon: `SYSROOT=<alpine armv7 musl-dev root> board/build.sh`. Module parameters: `prio`, `window` (1..8), `chunk`
(multiple of 16, up to 32768); `window` and `chunk` can be changed at run time.

## Hardware quirks found (all handled)
- AM335x MUSB can drop the first packet of an OUT transfer if no read is queued at that moment. A thread
  looping on `read()` always leaves a gap, which is invisible when the host sends one request at a
  time but constant when requests are pipelined (measured: 59 retries and 0.05 MB/s). The daemon
  therefore queues 12 reads on the endpoint at all times with kernel AIO; a harvester thread reassembles
  split requests and drops pad bytes.
- Rarely a request is dropped without a trace: handled by the retry + reply cache above.
- On 32-bit ARM `io_getevents` takes the old 32-bit timespec even under musl's 64-bit one; passing the
  wrong layout turned a 100 ms wait into a busy loop.
- Never kill `bbcryptod` while the gadget is bound (hung the board's kernel twice): use `setup-gadget.sh`,
  which unbinds the UDC first.
