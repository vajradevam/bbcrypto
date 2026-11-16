# Findings left for a human (not changed: behavior risk or large effort)

| Sev | Item | Why not changed |
|---|---|---|
| med | Long functions: `bbc_probe` 101 lines, `serve` 144, `rx_thread` 91, `afalg_test main` 105 (full list in AUDIT.md) | Splitting kernel-probe and daemon code changes control flow in hardware-sensitive paths; the board has no recovery path (no SD/UART), so a bad daemon is expensive. Do it with the board attached to a recoverable setup. |
| med | No offline tests: every functional test needs the hardware | A mock `bbcryptod` over a pipe (the daemon already has `serve(in_fd, out_fd)`) would allow CI to run the suite. |
| low | `tests/bbcrypt.c` `hex()` ignores non-hex input | Would change CLI error behavior; add validation and an error message. |
| low | `tests/afalg_test.c` fails (not skips) GCM checks on kernels without AF_ALG AEAD (e.g. Ubuntu blocks `algif_aead`) | Changes test semantics; add a probe + SKIP. |
| low | Magic numbers (32768, 16384, window 8, 192 KiB) repeated in host, daemon and tests | Putting them in `proto.h` is a cross-component change that needs a board redeploy. |
| low | `board/install.sh` default password `beagle`, host key checking off | Board image default on a direct USB link; override with `BOARD_PASS`. |
| low | Python demos use `int \| None` syntax (needs Python 3.10+) | Fine on Ubuntu 24.04 and Arch; note for older distros. |
| info | No Python formatter (black/ruff not installed) | Style kept consistent by `.editorconfig` only. |
| info | `bbcryptod.c` only compiles with musl headers, so CI cannot compile it without the sysroot download | `make board` covers it locally. |
| info | The board daemon was NOT reinstalled after formatting: disassembly is identical (verified), so no redeploy needed. | |
