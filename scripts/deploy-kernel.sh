#!/bin/bash
# Build a kernel with bbcrypto on another Arch (UEFI/UKI) or Ubuntu (GRUB) machine and install it as an EXTRA boot entry.
#   scripts/deploy-kernel.sh [user@]host build     download+configure+compile kernel and module (no root, slow)
#   scripts/deploy-kernel.sh [user@]host install   modules, initramfs+UKI in /boot/EFI/Linux, EFI entry, BootNext
# The existing boot order and kernels are untouched: the new kernel boots ONCE (BootNext); a reboot returns
# to the old default. The kernel tree lives in ~/bbcrypto/build/kernel on the target. Env: SUDO_PASS, KVER (default 6.18.60), SSH_OPTS. Then: scripts/deploy-host.sh <host>
# shortcut: Arch+UKI and Ubuntu/Debian+GRUB (GRUB_DEFAULT an explicit entry) only; other distros need their own install step.
set -e -o pipefail
cd "$(dirname "$0")/.."
TARGET=$1; MODE=$2; [ -n "$MODE" ] || { sed -n 2,7p "$0"; exit 1; }
KVER=${KVER:-6.18.60}; REL=$KVER-bbcrypto
O="-o ControlMaster=auto -o ControlPath=/tmp/bbc-%C -o ControlPersist=60 $SSH_OPTS"
{ printf 'KVER=%s; REL=%s; SUDO_PASS=%q; MODE=%s\n' "$KVER" "$REL" "$SUDO_PASS" "$MODE"; cat <<'REMOTE'
set -e -o pipefail
S() { if [ "$(id -u)" = 0 ]; then "$@"; elif [ -n "$SUDO_PASS" ]; then echo "$SUDO_PASS" | sudo -S -p '' "$@"; else sudo "$@"; fi; }
W=$HOME/bbcrypto/build/kernel; mkdir -p $W; cd $W
if [ $MODE = build ]; then
  [ -f linux-$KVER.tar.xz ] || curl -fLO https://cdn.kernel.org/pub/linux/kernel/v${KVER%%.*}.x/linux-$KVER.tar.xz
  [ -d linux-$KVER ] || tar xf linux-$KVER.tar.xz
  cd linux-$KVER
  # start from this machine's own distro kernel config so every driver it needs is there
  base=$(ls -d /usr/lib/modules/*/build/.config /boot/config-*-generic 2>/dev/null | grep -v pidmon | tail -1)
  if [ -n "$base" ]; then cp "$base" .config; else zcat /proc/config.gz > .config; fi
  scripts/config --set-str LOCALVERSION -bbcrypto -d LOCALVERSION_AUTO -m CRYPTO_USER_API_AEAD \
     -d MODULE_SIG -d MODULE_SIG_FORCE --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS "" \
     -e DEBUG_INFO_NONE -d BUILTIN_MODULE_RANGES -d DEBUG_INFO_BTF -d DEBUG_INFO_DWARF5 -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
  make olddefconfig >/dev/null
  make -j$(nproc) bzImage modules 2>&1 | tail -3
  [ "$(make -s kernelrelease)" = "$REL" ]
  echo ">>> kernel $REL built"
else
  cd linux-$KVER
  S make -s modules_install                       # /lib/modules/$REL incl. build -> this tree
  S depmod $REL                                    # the module itself is built+installed by deploy-host.sh after the reboot
  if [ -f /etc/debian_version ]; then             # Ubuntu/Debian: installkernel makes initrd + grub entry
    S make -s install 2>&1 | tail -3
    S grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux $REL"   # one-shot; GRUB_DEFAULT untouched
    S grub-editenv list
    echo ">>> installed; 'sudo reboot' boots it once, the next boot is back to normal"; exit 0
  fi
  S install -m 644 arch/x86/boot/bzImage /boot/vmlinuz-linux-bbcrypto
  S sh -c "cat > /etc/mkinitcpio.d/linux-bbcrypto.preset" <<P
ALL_kver="/boot/vmlinuz-linux-bbcrypto"
PRESETS=('default')
default_uki="/boot/EFI/Linux/arch-linux-bbcrypto.efi"
P
  S mkinitcpio -p linux-bbcrypto -k $REL 2>&1 | tail -3 || true
  S ls -la /boot/EFI/Linux/arch-linux-bbcrypto.efi
  order=$(S efibootmgr | sed -n 's/^BootOrder: //p')
  if ! S efibootmgr | grep -q 'Arch Linux bbcrypto'; then
    src=$(findmnt -no SOURCE /boot); disk=/dev/$(lsblk -no PKNAME $src); part=$(cat /sys/class/block/${src##*/}/partition)
    S efibootmgr -c -d $disk -p $part -L "Arch Linux bbcrypto" -l '\EFI\Linux\arch-linux-bbcrypto.efi' >/dev/null
  fi
  S efibootmgr -o $order >/dev/null                # -c put it first: restore the original order
  num=$(S efibootmgr | sed -n 's/^Boot\([0-9A-F]*\)\*\? Arch Linux bbcrypto.*/\1/p' | head -1)
  S efibootmgr -n $num >/dev/null                   # one-shot
  S efibootmgr | head -3
  echo ">>> installed; 'sudo systemctl reboot' boots it once (entry $num), the next boot is back to normal"
fi
REMOTE
} | ssh $O "$TARGET" 'bash -s'
