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

all: host tests board
build: all

CSRC := tests/afalg_extra.h host/bbcrypto.c board/bbcryptod.c tests/afalg_test.c tools/bbcrypt.c tools/board_aes.c demos/6_hash.c proto.h
SH   := $(wildcard scripts/*.sh board/*.sh board/*.openrc demos/*.sh)
setup:
	git config core.hooksPath .githooks
format:
	clang-format -i $(CSRC)
lint:
	clang-format --dry-run -Werror $(CSRC)
	pyflakes demos/*.py
	for f in $(SH); do bash -n $$f || exit 1; done
typecheck:
	for f in tests/afalg_test.c tools/bbcrypt.c tools/board_aes.c demos/6_hash.c; do \
	  $(CC) -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror -fsyntax-only -I. $$f || exit 1; done
	python3 -m py_compile demos/*.py

host:
	$(MAKE) -C host KDIR=$(KDIR)
tests: tests/afalg_test tools/bbcrypt
tests/%: tests/%.c tests/afalg_extra.h
	$(CC) -O2 -Wall -static -o $@ $< -lpthread
tools/bbcrypt: tools/bbcrypt.c
	$(CC) -O2 -Wall -static -o $@ $< -lpthread
board: build/sysroot/usr/lib/crt1.o
	cd board && SYSROOT=$(abspath build/sysroot) ./build.sh
build/sysroot/usr/lib/crt1.o:
	scripts/fetch-sysroot.sh
install-board: board
	board/install.sh
deploy:
	scripts/deploy-host.sh $(HOST)
clean:
	$(MAKE) -C host KDIR=$(KDIR) clean
	rm -f tests/afalg_test tools/bbcrypt tools/board_aes board/bbcryptod demos/6_hash
	rm -rf demos/__pycache__
.PHONY: all build setup format lint typecheck host tests board install-board deploy clean
