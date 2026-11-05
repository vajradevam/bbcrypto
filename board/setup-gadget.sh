#!/bin/sh
# Runs ON THE BOARD. Adds the bbcrypto FunctionFS interface to the existing ACM+ECM gadget
# and starts bbcryptod. The USB link drops for ~2 s while the gadget is rebound, so run it
# detached:   nohup sh /usr/local/bin/setup-gadget.sh >/var/log/bbcrypto-setup.log 2>&1 &
# Also the ONLY safe way to restart the daemon: it unbinds the UDC before killing bbcryptod.
# (Killing the daemon while the gadget is bound has hung this board's kernel twice.)
# Always rebinds the UDC at the end so ssh/serial come back even on failure.
G=/sys/kernel/config/usb_gadget/g1
F=$G/functions/ffs.bbc
MNT=/dev/ffs-bbc
UDC=$(ls /sys/class/udc | head -n1)

restore() { echo "$UDC" > $G/UDC 2>/dev/null; }

echo "" > $G/UDC
sleep 1
kill -9 $(pgrep bbcryptod) 2>/dev/null
mountpoint -q $MNT && umount $MNT
rm -f $G/configs/c.1/ffs.bbc
[ -d $F ] || mkdir $F || { restore; exit 1; }
ln -s $F $G/configs/c.1/ffs.bbc || { restore; exit 1; }
mkdir -p $MNT
mount -t functionfs bbc $MNT || { rm $G/configs/c.1/ffs.bbc; restore; exit 1; }
/usr/local/bin/bbcryptod $MNT >>/var/log/bbcryptod.log 2>&1 &
sleep 1
if ! echo "$UDC" > $G/UDC; then
    echo "bind failed, falling back to ACM+ECM only"
    kill -9 $(pgrep bbcryptod); umount $MNT; rm $G/configs/c.1/ffs.bbc
    restore
    exit 1
fi
echo "bbcrypto interface up"
