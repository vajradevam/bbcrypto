#!/bin/bash
# After the board runs the Alpine/6.18 system, it shows up as a USB Ethernet (ECM) + serial gadget.
# This gives the laptop side of the link an address (NetworkManager sometimes drops it) and trusts it
# in firewalld. Run as root:  sudo ./bbb-net-up.sh      then:  ssh root@192.168.7.2   (password: beagle)
IF=$(for n in /sys/class/net/*; do u=$(readlink -f "$n/device/.." 2>/dev/null); [ "$(cat $u/idVendor 2>/dev/null):$(cat $u/idProduct 2>/dev/null)" = "1d6b:0104" ] && basename "$n"; done | head -1)
[ -n "$IF" ] || { echo "board network interface not found" >&2; exit 1; }
ip addr show dev "$IF" | grep -q 192.168.7.1/ || ip addr add 192.168.7.1/30 dev "$IF"
firewall-cmd --zone=trusted --change-interface="$IF" >/dev/null 2>&1
ping -c2 -W2 192.168.7.2 && echo "up on $IF: ssh root@192.168.7.2"
