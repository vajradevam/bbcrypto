#!/bin/sh
# Cross-build bbcryptod for the board (armv7 musl). SYSROOT = an Alpine armv7 root with musl-dev+linux-headers.
SYSROOT=${SYSROOT:-$(cd "$(dirname "$0")/.." && pwd)/build/sysroot}
R=$SYSROOT/usr/lib
cd "$(dirname "$0")"
exec clang --target=armv7-alpine-linux-musleabihf --sysroot=$SYSROOT -fuse-ld=lld -nostdlib -O2 -Wall -Wextra -Wno-unused-parameter \
  -o bbcryptod bbcryptod.c $R/crt1.o $R/crti.o $SYSROOT/lib/ld-musl-armhf.so.1 $R/crtn.o -Wl,--dynamic-linker=/lib/ld-musl-armhf.so.1
