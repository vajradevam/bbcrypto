#!/bin/sh
# Downloads the Alpine armv7 musl headers/libs needed to cross-build bbcryptod with clang.
# Result: build/sysroot (override with SYSROOT_DIR). Alpine release: ALPINE (default v3.24).
set -e
cd "$(dirname "$0")/.."
ALPINE=${ALPINE:-v3.24}
OUT=${SYSROOT_DIR:-$PWD/build/sysroot}
[ -f "$OUT/usr/lib/crt1.o" ] && { echo "sysroot already in $OUT"; exit 0; }
mkdir -p "$OUT" build/dl && cd build/dl
B=https://dl-cdn.alpinelinux.org/alpine/$ALPINE/main/armv7
curl -sfL "$B/APKINDEX.tar.gz" -o idx.tgz
tar xzf idx.tgz APKINDEX
for p in linux-headers musl musl-dev; do
  v=$(awk -v p="$p" '$0=="P:"p {getline; sub("V:",""); print; exit}' APKINDEX)
  curl -sfLO "$B/$p-$v.apk"
  tar xzf "$p-$v.apk" -C "$OUT" 2>/dev/null
done
echo "sysroot ready in $OUT"
