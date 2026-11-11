#!/bin/bash
# Share the laptop's internet with the board over the USB cable (runtime only; resets on reboot/firewall reload).
# Run as root:  sudo ./bbb-internet.sh        undo:  sudo ./bbb-internet.sh off
# Then on the board: apk add <package>   (board already has gateway 192.168.7.1 and DNS 1.1.1.1)
OUT=$(ip route show default | awk '{print $5; exit}')
IN=$(for n in /sys/class/net/*; do u=$(readlink -f "$n/device/.." 2>/dev/null); [ "$(cat $u/idVendor 2>/dev/null):$(cat $u/idProduct 2>/dev/null)" = "1d6b:0104" ] && basename "$n"; done | head -1)
[ -n "$IN" ] && [ -n "$OUT" ] || { echo "interfaces not found (board: '$IN', uplink: '$OUT')" >&2; exit 1; }
Z=$(firewall-cmd --get-zone-of-interface="$OUT")
if [ "$1" = off ]; then
  firewall-cmd --zone="$Z" --remove-masquerade; iptables -D FORWARD -i "$IN" -o "$OUT" -j ACCEPT; iptables -D FORWARD -i "$OUT" -o "$IN" -m state --state RELATED,ESTABLISHED -j ACCEPT; exit 0
fi
sysctl -q net.ipv4.ip_forward=1
firewall-cmd --zone="$Z" --add-masquerade
iptables -I FORWARD 1 -i "$IN" -o "$OUT" -j ACCEPT
iptables -I FORWARD 2 -i "$OUT" -o "$IN" -m state --state RELATED,ESTABLISHED -j ACCEPT
echo "sharing $OUT -> $IN"
