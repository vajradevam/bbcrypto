#!/bin/sh
# Installs bbcryptod and the OpenRC services on the BeagleBone and restarts the service safely.
#   BOARD=192.168.7.2  BOARD_PASS=beagle  board/install.sh
# Originals are kept on the board: /root/usbgadget.orig (once), /root/bbcryptod.prev (each run).
# The restart runs detached on the board (stop unbinds the USB gadget first); the link drops for ~20 s.
set -e
cd "$(dirname "$0")"
BOARD=${BOARD:-192.168.7.2}
PASS=${BOARD_PASS:-beagle}
[ -x bbcryptod ] || { echo "build bbcryptod first (make board)"; exit 1; }
A=$(mktemp); printf '#!/bin/sh\necho "%s"\n' "$PASS" > "$A"; chmod 700 "$A"; trap 'rm -f "$A"' EXIT
export SSH_ASKPASS=$A SSH_ASKPASS_REQUIRE=force
O="-o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
scp $O bbcryptod bbcrypto.openrc usbgadget.openrc root@$BOARD:/root/
ssh -n $O root@$BOARD '
  [ -f /root/usbgadget.orig ] || cp /etc/init.d/usbgadget /root/usbgadget.orig
  [ -f /usr/local/bin/bbcryptod ] && cp /usr/local/bin/bbcryptod /root/bbcryptod.prev
  mv /root/bbcryptod /root/bbcryptod.staged
  cp /root/usbgadget.openrc /etc/init.d/usbgadget; chmod +x /etc/init.d/usbgadget
  cp /root/bbcrypto.openrc /etc/init.d/bbcrypto;   chmod +x /etc/init.d/bbcrypto
  rc-update add bbcrypto default >/dev/null 2>&1 || true'
ssh -n -f $O root@$BOARD 'sh -c "mv /root/bbcryptod.staged /usr/local/bin/bbcryptod; rc-service bbcrypto restart" >/root/restart.log 2>&1' >/dev/null 2>&1
echo "installed; the board restarts bbcrypto now (reconnect in ~20 s: ssh root@$BOARD cat /root/restart.log)"
