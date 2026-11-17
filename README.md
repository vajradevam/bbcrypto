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

## Results
(Historical: the early measurements below were taken in a QEMU test bench, which is no longer part of this repo; current testing is `make deploy`.) All measurements are inside the QEMU test bench, i.e. the board reaches the guest through QEMU's xHCI
emulation and libusb pass-through, so absolute transport numbers include that overhead.

**Correctness** - 520 checks (NIST/FIPS/GCM-spec vectors; random comparisons against the in-kernel sha256/sha1/hmac,
`*-aes-generic` and `gcm_base(ctr(aes-generic),ghash-generic)`; sync and async hashes; GCM with 3 key sizes, AAD 0/13/20,
tags 8/12/16 and forged-tag rejection; all key sizes; lengths up to 1 MiB; streamed and cloned hashes): 520 passed, 0
failed, 14,489 requests, 0 errors, 0 retries; stress test 0/150 bad; no lockdep / KASAN /
sleep-in-atomic / WARNING output on a debug kernel.

**Hot-unplug under load** (`unplugtest`, workers rotate through sha256, async sha256, ECB and GCM; the USB device is deauthorized while four threads hammer it, then
reauthorized, twice): in-flight requests fail with an error and nothing hangs; the board comes back as a
new device and requests succeed again; `rmmod` works; no kernel warnings. (This found a real bug: the
first version unregistered the algorithms on disconnect and triggered a crypto-core WARNING.)

**Where the time goes** (`sweeptest`):

| | |
|---|---|
| transport only, 32 KiB echo, window 1 / 2 / 4 | 4.1 / 6.4 / 6.5 MB/s each way |
| transport only, 64-byte echo, window 1 / 8 | 349 / 165 us per command |
| AES-ECB 2 MiB, window 1 / 4, 16 KiB chunks | 2.9 / 4.45 MB/s |
| AES-ECB, 4-8 concurrent callers, window 1 / 4 | 3.0 / 5.55 MB/s |
| AES-CBC encrypt (serial chain) / decrypt (parallel) | 2.9 / 4.5 MB/s |
| SHA-256 64-byte requests, 4-8 callers, window 1 / 4 | ~2000 / ~3000-3400 req/s |

- A window of 2 captures nearly all of the pipelining gain; more adds nothing because the transport saturates.
- Cipher chunks below 16 KiB lose throughput to per-command overhead; 16 and 32 KiB are equivalent.
- Bottleneck analysis: transport alone tops out near 6.5 MB/s; the board's AES alone runs ~17 MB/s; the
  end-to-end 4.5-5.5 MB/s sits below both, so the transport and the board's compute only partly overlap.
  The remaining gap (per-request daemon overhead such as opening a transform and copying buffers) was
  not measured separately. The first
  version serialised "compute" and "send reply" in the daemon; moving reply transmission to its own thread
  raised ECB from 3.9 to 4.45 MB/s (single caller) and 4.65 to 5.55 MB/s (concurrent). The same handoff made
  tiny hash requests ~10% slower on the 1 GHz board.
- The accelerator is slower than the laptop's own CPU (SHA-256 ~1,200 MB/s locally vs ~3 MB/s through the
  board). It is a demonstration of the driver architecture and of offload mechanics, not a speed-up.

**Priority knob** (`modprobe bbcrypto prio=400`, see `demos/4_priority.py`): with `prio=400` the plain names resolve to bbcrypto
(`sha256 sha256-bbcrypto 400` above `sha256-lib 300`), and a stock `sha256` request through AF_ALG with no driver
name increased the board's request counter 1 -> 4.

**Is the AES really done by the hardware engine?** Yes, shown on the board with the same 2 MiB workload:

| implementation | wall time | CPU busy | EDMA completion interrupts |
|---|---|---|---|
| `cbc-aes-omap` (hardware) | ~120 ms | 50% | **64** (one per 32 KiB request) |
| `cbc-aes-neonbs` (NEON software) | ~170 ms | 100% | 0 |
| `cbc(aes-arm)` / `cbc(aes-generic)` | ~280 / ~320 ms | 100% | 0 |

## Known limits
- Developed and tested in the QEMU guest (6.18.60 debug kernel); the module compiles cleanly against the
  laptop's 7.2.2 headers but has not been loaded there.
- GCM requests are limited to 32 KiB of AAD+data (it cannot be chunked like ECB/CTR; larger ones fail with -EINVAL),
  and its GHASH runs in software on the board (see above). No other AEAD modes, no `rfc4106`.
- The "device" is a Linux computer running a daemon, not a fixed-function chip: the USB function is
  implemented in user space (FunctionFS) and the wire protocol is this project's own design.
- The OpenRC service was tested with start, restart and full board reboots. Also install `board/usbgadget.openrc` as `/etc/init.d/usbgadget` (original kept as `/root/usbgadget.orig`): it skips its own UDC bind when the bbcrypto service is enabled, so the host sees one enumeration per boot. With the original script (bind, unbind, rebind) the QEMU guest failed with `can't set config #1, error -32` after a board reboot and never re-probed. With the single bind, a board reboot while the VM runs gives disconnect, then `board 2 ready`, and the suite passed 379/0 afterwards (`run.sh replugtest`, run before GCM/ahash were added).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architecture, source map and build.

## Installing on another machine (real kernel)

Plug the board in (it must already run `bbcryptod`: `make install-board`), then from this checkout:

    make deploy HOST=user@machine            # SUDO_PASS=... if sudo needs a password
    scripts/deploy-host.sh --build-only      # compile against *this* machine's headers, install nothing

It copies the sources over ssh, installs kernel headers if missing (apt/dnf/pacman), builds against the
target's **running** kernel, installs `bbcrypto.ko` into `/lib/modules/<ver>/extra` and runs `depmod`, so
from then on plugging the board autoloads the driver. It then loads the module, waits for the board to
bind, and runs `afalg_test` on the target. The module is unsigned: with Secure Boot on, sign it or
disable Secure Boot. It builds against the running kernel; it does not replace the kernel.

### When the target's kernel has no headers or no AF_ALG AEAD

`scripts/deploy-kernel.sh user@host build` downloads Linux 6.18.60, configures it from the machine's own
distro config (plus `CRYPTO_USER_API_AEAD=m`, no module signing) and compiles it; `... install` installs it
as an **extra, one-shot boot entry** (Arch+UKI/efibootmgr, or Ubuntu+GRUB `grub-reboot`). After the reboot run
`scripts/deploy-host.sh user@host`. Needs `gawk`-free builds (`BUILTIN_MODULE_RANGES` is turned off for Ubuntu).
Ubuntu ships `install algif_aead /bin/false` (CVE-2026-31431); the script loads it with `--ignore-install`.
Verified on Ubuntu 24.04 (UEFI): 520/0 in `afalg_test`, GCM board == in-kernel, `prio=400`, sysfs-unplug
under load (no hang/oops, clean recovery). `bbcrypt enc|dec` takes at most 192 KiB per call (socket buffer).

### What the deploy scripts leave on the target machine
- `~/bbcrypto/`: a mirror of this repo (sources only, re-sent on every deploy). `~/bbcrypto/build/kernel` is the Linux tree from `deploy-kernel.sh`.
- System files only from `deploy-kernel.sh install`: `/boot/*6.18.60-bbcrypto*`, `/lib/modules/6.18.60-bbcrypto/`, and the boot entry (plus `/etc/default/grub` if you change the default yourself).
- From `deploy-host.sh`: `/lib/modules/<ver>/extra/bbcrypto.ko` and `/usr/local/bin/bbcrypt`.
