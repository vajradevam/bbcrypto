#!/bin/bash
# Install the bbcrypto driver on another Linux machine over ssh and test it against the board.
#   scripts/deploy-host.sh [user@]host     build against that machine's running kernel, install, load, test
#   scripts/deploy-host.sh --build-only    compile here against this machine's headers; installs/loads NOTHING
# Env: SUDO_PASS (if the user needs a sudo password), SSH_OPTS (extra ssh options), SKIP_TEST=1, UNPLUG=1 (also run the deauthorize/reauthorize test).
# The board must already run bbcryptod (make install-board) and be plugged into that machine.
set -e
cd "$(dirname "$0")/.."
TARGET=$1; [ -n "$TARGET" ] || { sed -n 2,5p "$0"; exit 1; }
