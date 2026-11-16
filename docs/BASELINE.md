# Baseline vs final

| Metric | Before (f911ae8) | After |
|---|---|---|
| Functional tests (`make deploy`, d153, real board) | 520 passed, 0 failed | 520 passed, 0 failed |
| Kernel module build (laptop headers 7.2.2, W=1) | OK, 0 warnings | OK, 0 warnings |
| Board daemon cross build (clang armv7 musl) | OK | OK (same disassembly) |
| gcc `-Wall -Wextra` warnings (tests, demos) | 0 | 0 |
| clang-format violations | 7 files / 1,434 changed lines | 0 |
| pyflakes | 1 (unused import) | 0 |
| `bash -n` | 0 errors | 0 errors |
| mypy / type errors | not applicable (no annotations, mypy not installed) | |
| Coverage | not measurable (kernel + hardware) | |
| Files tracked | 40 | 54 |
| Lines (excl. kernel.config, guest.config) | ~4,200 | |
