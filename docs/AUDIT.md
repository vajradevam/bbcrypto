> Historical report from before the QEMU bench (`vm/`) was dropped from the repo; paths `docs/codebase/` and `tests/bbcrypt*` are now `docs/` and `tools/`.

# Audit (read-only, taken at baseline commit f911ae8)

## 1. Inventory
- Languages: C (kernel module, board daemon, tests), Python 3 (demos), POSIX sh/bash (scripts, OpenRC), Makefile. No package manager, no lockfile: the project has no third-party dependencies (Python demos use only the standard library).
- Build tools: kernel kbuild (`host/Makefile`), gcc (tests), clang+lld cross build (`board/build.sh`, armv7 musl), QEMU+busybox (`vm/`).
- Entry points: `bbcrypto.ko` (USB probe `host/bbcrypto.c:1594`), `bbcryptod` (`board/bbcryptod.c` `main`), `tests/afalg_test`, `tests/bbcrypt` (CLI), `demos/*.py`.
- Public interfaces: kernel crypto API algorithm names (`*-bbcrypto`), module parameters `prio`, `window`, `chunk`, sysfs `stats`, USB wire protocol `proto.h`, CLI `bbcrypt`.
- Config / env: `SUDO_PASS`, `SSH_OPTS`, `SKIP_TEST`, `KVER`, `BOARD`, `BOARD_PASS`, `SYSROOT`, `KDIR`, `HOST`.

| Folder | Files | Lines |
|---|---|---|
| host | 2 | 1781 |
| board | 7 | 1070 (excl. 2.4k-line `kernel.config`) |
| tests | 3 | 674 |
| demos | 13 | 418 |
| scripts | 5 | 161 |
| vm | 5 | 5728 (mostly `guest.config`) |
| docs | 1 | 97 |

## 2. Architecture map
`proto.h` (wire format) is included by `host/bbcrypto.c`, `board/bbcryptod.c`, `tests/*`. Direction: `tests`/`demos` -> kernel crypto API (AF_ALG) -> `bbcrypto.ko` -> USB -> `bbcryptod` -> board AF_ALG engines. No cycles. The only cross-module coupling is `proto.h`. Details: `docs/ARCHITECTURE.md`.

## 3. Structure
- Layout matches a small kernel-module project. `proto.h` sits at the root because three components share it (acceptable; an `include/` folder would be tidier).
- `tests/board_aes.c` is built by no Makefile target (hand-run on the board). Not dead: referenced in docs and `deploy-host.sh` excludes.
- `tools/` outside this repo still holds two board setup scripts (not part of the repository).

## 4. Code quality
- **Format**: C is written in a dense one-line style. LLVM-based kernel-style formatting would change ~1,430 lines in 7 files (see BASELINE).
- **Long functions (>50 lines, measured after formatting)**: `bbc_probe` 101, `bbc_rx_complete` 62, `bbc_ah_step` 58 (`host/bbcrypto.c`); `serve` 144, `rx_thread` 91, `main` 67, plus three request handlers of 63-75 lines (`board/bbcryptod.c`); `main` 105, `sweep` 71, `t_gcm` 56 (`tests/afalg_test.c`); `dogcm` 73, `docipher` 61 (`tests/bbcrypt.c`).
- **Large files (>500 lines)**: `host/bbcrypto.c` 1.8k, `board/bbcryptod.c` 0.9k-1.1k, `tests/afalg_test.c` 0.5k-0.7k.
- **Dead code**: `import hashlib` unused in `demos/4_priority.py:3` (pyflakes). Nothing else found (gcc -Wall -Wextra and kernel W=1: 0 warnings).
- **Comments**: stale comments fixed earlier (proto.h, host header). No commented-out code found.
- **Hard-coded**: board IP 192.168.7.2 and default password `beagle` in `board/install.sh:8-9`, `scripts/bbb-*.sh`. These are the Alpine image defaults, documented, and overridable (`BOARD`, `BOARD_PASS`).
- **Error handling**: `tests/bbcrypt.c` ignores `sscanf` result in `hex()` (non-hex input gives garbage key silently). `tests/afalg_test.c` fails (not skips) GCM checks when the kernel lacks AF_ALG AEAD.
- **Typing**: Python demos have no annotations; `demos/bbc.py` (shared helper) is the public part.

## 5. Dependencies
None to pin. Build needs: kernel headers, gcc, clang+lld, an Alpine armv7 sysroot (fetched by `scripts/fetch-sysroot.sh`), QEMU/busybox for the VM path.

## 6. Testing
`tests/afalg_test.c`: 520 checks against the real board (also reachable through the QEMU guest). There is no offline test: every functional test needs the hardware. Skipped tests: none. Weak spot: the board-side parser and GCM path are tested only end to end.

## 7. Tooling (at baseline)
Present: Makefile, `.gitignore`, README, `docs/ARCHITECTURE.md`. Missing: formatter config, linter, `.editorconfig`, pre-commit hook, CI, LICENSE, CONTRIBUTING, CHANGELOG.

## 8. Security and safety
- No secrets committed. `SUDO_PASS` is read from the environment and piped to `sudo -S` through a shell builtin (not visible in `ps`).
- `board/install.sh` disables SSH host key checking (`StrictHostKeyChecking=no`) to the board; acceptable for a direct USB-network link, unsafe elsewhere.
- Crypto: AES via the AM335x engine, SHA via the board; the USB link is not authenticated, so anyone with physical access to the cable can read data. Documented project limit.
- `deploy-*.sh` pipe a generated script into `ssh ... bash -s`; inputs are `%q`-quoted.

## 9. Risk register
| ID | Finding | Sev | Effort | Behavior risk | Action |
|---|---|---|---|---|---|
| A1 | Unformatted C (7 files) | low | S | none | apply clang-format (done) |
| A2 | Unused import `demos/4_priority.py:3` | low | S | none | remove (done) |
| A3 | No LICENSE/CONTRIBUTING/CHANGELOG/.editorconfig/CI | med | S | none | add (done) |
| A4 | No lint/format/typecheck targets | med | S | none | add (done) |
| A5 | `bbc_probe`, `serve`, `afalg_test main` too long | med | L | high | not changed, see FINDINGS |
| A6 | `hex()` ignores bad input (`tests/bbcrypt.c`) | low | S | low | FINDINGS |
| A7 | afalg_test fails instead of skipping GCM without AEAD | low | S | low | FINDINGS |
| A8 | Magic numbers (32768, 16384, window 8...) | low | M | low | FINDINGS |
| A9 | Public Python helper without annotations | low | S | none | annotate `bbc.py` (done) |
