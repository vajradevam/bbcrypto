# Develop here, test on the machine the BeagleBone is plugged into (make deploy).
# The module is built against KDIR (default: this machine's running kernel headers) and is only
# ever loaded by `make deploy` on the target machine.
#
#   make setup      enable the pre-commit hook (make lint typecheck)
#   make build      same as make: module + tests + board daemon
#   make format     apply .clang-format to the C sources
#   make lint       format check (C), pyflakes (Python), bash -n (shell)    [no hardware needed]
#   make typecheck  compile the C tests/demos with -Wall -Wextra -Werror, byte-compile the Python demos (bbcryptod needs the musl sysroot: make board)
#   make            module + tests + board daemon
#   make deploy HOST=user@machine   build+install the driver on another machine over ssh, run the suite there
#   make install-board   copy bbcryptod + OpenRC services to the board and restart them
KDIR     ?= /lib/modules/$(shell uname -r)/build    # kernel build tree to compile the module against
CLANG    ?= clang
