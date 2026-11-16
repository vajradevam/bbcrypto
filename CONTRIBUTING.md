# Contributing

- Setup: `make setup` (enables the pre-commit hook). Tools: gcc, clang + clang-format, pyflakes, kernel headers.
- Standard: `docs/STANDARD.md`. Format with `make format`; check with `make lint typecheck`.
- Functional tests need the BeagleBone: `make deploy HOST=user@machine` (real kernel with the module). It must report 0 failed.
- Branches `type/short-name`; one logical change per commit; add a check to `tests/afalg_test.c` for any new driver behavior.
- Never load the module on a machine whose kernel you cannot afford to crash; use the VM or a test machine.
