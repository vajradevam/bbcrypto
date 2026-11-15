#!/bin/sh
# Runs every demo in order. Needs the module loaded and the board attached (make deploy HOST=... does both).
cd "$(dirname "$0")"
for d in 1_hash 2_aes 3_gcm 4_priority 5_parallel 7_verify_files 8_encrypt_file 9_signed_token; do echo; echo "=================== $d ==================="; python3 $d.py || echo "(failed)"; done
echo; echo "=================== 6_hash (C) ==================="
cc -O2 -Wall -o 6_hash 6_hash.c && head -c 300000 /dev/urandom > /tmp/demo.bin && ./6_hash /tmp/demo.bin && sha256sum /tmp/demo.bin
echo; echo "Not run here (slow / interactive):  python3 10_benchmark.py    sudo python3 11_resilience.py 16 --simulate"
