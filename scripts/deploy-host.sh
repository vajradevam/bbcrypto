#!/bin/bash
# Install the bbcrypto driver on another Linux machine over ssh and test it against the board.
#   scripts/deploy-host.sh [user@]host     build against that machine's running kernel, install, load, test
#   scripts/deploy-host.sh --build-only    compile here against this machine's headers; installs/loads NOTHING
# Env: SUDO_PASS (if the user needs a sudo password), SSH_OPTS (extra ssh options), SKIP_TEST=1, UNPLUG=1 (also run the deauthorize/reauthorize test).
# The board must already run bbcryptod (make install-board) and be plugged into that machine.
set -e
cd "$(dirname "$0")/.."
TARGET=$1; [ -n "$TARGET" ] || { sed -n 2,5p "$0"; exit 1; }

# remote side: build in a scratch copy, then (unless BUILD_ONLY) install, load, test
payload() { cat <<REMOTE
BUILD_ONLY='$BUILD_ONLY'; SKIP_TEST='$SKIP_TEST'; UNPLUG='$UNPLUG'; SUDO_PASS=$(printf %q "$SUDO_PASS"); SRC=\${SRC:-\$HOME/bbcrypto}
REMOTE
cat <<'REMOTE'
set -e
S() { if [ "$(id -u)" = 0 ]; then "$@"; elif [ -n "$SUDO_PASS" ]; then echo "$SUDO_PASS" | sudo -S -p '' "$@"; else sudo "$@"; fi; }
k=$(uname -r); cd "$SRC"
if [ ! -d /lib/modules/$k/build ]; then
  [ -z "$BUILD_ONLY" ] || { echo "no headers for $k"; exit 1; }
  echo ">>> installing kernel headers for $k"
  if command -v apt-get >/dev/null; then S apt-get install -y build-essential linux-headers-$k
  elif command -v dnf >/dev/null;   then S dnf install -y gcc make kernel-devel-$k
  elif command -v pacman >/dev/null; then S pacman -S --needed --noconfirm base-devel linux-headers
  else echo "install kernel headers for $k by hand"; exit 1; fi
fi
echo ">>> building for $k"
make -C host >/dev/null
cc -O2 -Wall -static -o tests/afalg_test tests/afalg_test.c -lpthread 2>/dev/null ||
  cc -O2 -Wall -o tests/afalg_test tests/afalg_test.c -lpthread
cc -O2 -Wall -static -o tools/bbcrypt tools/bbcrypt.c 2>/dev/null || cc -O2 -Wall -o tools/bbcrypt tools/bbcrypt.c
[ -z "$BUILD_ONLY" ] || { echo ">>> build OK ($(modinfo host/bbcrypto.ko | sed -n 's/^vermagic: *//p'))"; exit 0; }
S install -D -m 644 host/bbcrypto.ko /lib/modules/$k/extra/bbcrypto.ko
S depmod -a                       # writes the USB alias: plugging the board now autoloads the driver
for m in algif_hash algif_skcipher algif_aead; do S modprobe --ignore-install $m 2>/dev/null || true; done   # Ubuntu disables algif_aead via an install/bin/false rule
! grep -q '^bbcrypto ' /proc/modules || S rmmod bbcrypto
S modprobe bbcrypto || { echo "load failed (Secure Boot rejects unsigned modules?)"; dmesg | tail -5; exit 1; }
for i in $(seq 15); do ls /sys/bus/usb/drivers/bbcrypto/*/stats >/dev/null 2>&1 && break; sleep 1; done
ls /sys/bus/usb/drivers/bbcrypto/*/stats >/dev/null 2>&1 || { echo "driver loaded but the board is not bound:"; lsusb | grep 1d6b || echo "  board not on USB"; exit 1; }
echo ">>> board bound"; cat /sys/bus/usb/drivers/bbcrypto/*/stats | head -3
S install -m 755 tools/bbcrypt /usr/local/bin/bbcrypt
[ -n "$SKIP_TEST" ] || { echo ">>> running test suite"; S tests/afalg_test; echo ">>> TEST-EXIT=$?"; }
[ -z "$UNPLUG" ] || { echo ">>> unplug test"; S tests/afalg_test unplug; echo ">>> UNPLUG-EXIT=$?"; }
REMOTE
}

if [ "$TARGET" = --build-only ]; then
  export SRC=$(mktemp -d); BUILD_ONLY=1
  tar czf - host/bbcrypto.c host/Makefile proto.h tests tools | tar xzf - -C "$SRC"
  payload | bash; rm -rf "$SRC"; exit
fi
O="-o ControlMaster=auto -o ControlPath=/tmp/bbc-%C -o ControlPersist=60 $SSH_OPTS"
# the target gets a mirror of this repo in ~/bbcrypto (sources only; its build/ holds the kernel from deploy-kernel.sh and is kept).
# The previous copy of each directory is kept in ~/bbcrypto/.prev, so edits made on the target are not lost by one deploy.
tar czf - --exclude=./build --exclude=./report --exclude=./.git --exclude='*.o' --exclude='*.ko' --exclude='*.mod*' \
  --exclude=Module.symvers --exclude=modules.order --exclude=board/bbcryptod --exclude=tests/afalg_test \
  --exclude=tools/bbcrypt --exclude=tools/board_aes --exclude=demos/6_hash . |
  ssh $O "$TARGET" 'mkdir -p bbcrypto && cd bbcrypto && rm -rf .prev && mkdir .prev && for d in host board tests tools demos scripts; do [ -e $d ] && mv $d .prev/; done; tar xzf -'
payload | ssh $O "$TARGET" 'bash -s'
