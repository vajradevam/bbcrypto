# Standard for bbcrypto (short and checkable)

## 1. Layout
`host/` kernel module · `board/` board daemon, services, kernel config · `tests/` C tests · `tools/` CLI and hardware proof · `demos/` Python/C usage examples · `scripts/` deploy and setup helpers · `docs/` documentation and audit reports · `proto.h` wire format shared by host, board and tests.

## 2. Naming
C: `snake_case` functions and variables, `UPPER_CASE` macros and constants, driver symbols prefixed `bbc_`, protocol symbols `BBC_`. Python: PEP 8 (`snake_case`, demos numbered `N_topic.py`). Shell: lowercase files with `.sh`, env vars UPPER_CASE. Branches: `type/short-name` (`chore/`, `fix/`, `feat/`). Commits: imperative, one logical change.

## 3. Formatting
C: `.clang-format` (Linux-style braces, tabs of 8, 100 columns, includes not reordered). Check: `make lint`. Apply: `make format`. Python/shell: 4/2 spaces per `.editorconfig`, no formatter enforced (none installed in the toolchain).

## 4. Typing and documentation
Every non-static C function and every Python helper in `demos/bbc.py` has a type signature (C: prototypes; Python: annotations) and a one-line doc comment saying what it does and what it returns. Comments explain why. Every source file starts with a header comment: purpose and how to run it. SPDX header on C files.

## 5. Errors and logging
Kernel: return negative errno, never BUG; log with `dev_err/dev_warn`, no logging on hot paths. Daemon/tests: print to stderr, non-zero exit. Python: let `OSError` propagate (callers decide); never swallow errors.

## 6. Configuration and secrets
Config by environment variable or module parameter, documented at the top of the script. No passwords in files; the board's default image password may appear only as an overridable default. `SUDO_PASS` only via environment.

## 7. Dependencies
No third-party runtime dependencies. A new build-time tool must be listed in the README and `make setup`.

## 8. Tests
Functional tests live in `tests/afalg_test.c` (need the board: `make test`/`make deploy`). Every new algorithm or driver path adds checks there. Static checks (`make lint typecheck`) must pass without hardware and run in CI.

## 9. Limits (guidance, enforced in review, not by tool)
Function ≤ 50 lines, file ≤ 800 lines for new code, nesting ≤ 3, parameters ≤ 5. Existing exceptions are listed in `FINDINGS.md`. Compiler: `-Wall -Wextra` clean; kernel build `W=1` clean.

## 10. Definition of done
- [ ] `make lint typecheck build` pass
- [ ] `make deploy HOST=...` (or `make test`): 0 failed
- [ ] new behavior has a test; public interface documented
- [ ] README / ARCHITECTURE / CHANGELOG updated
- [ ] no secrets, no generated files committed
