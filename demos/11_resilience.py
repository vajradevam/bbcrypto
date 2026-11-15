#!/usr/bin/env python3
"""Demo 11: what happens when the board disappears in the middle of work?
   11_resilience.py [seconds]   keeps hashing; UNPLUG the board (or run as root with --simulate) and watch:
   requests fail fast with an error (no hang, no kernel crash), and work resumes when the board is back."""
import errno, hashlib, os, sys, time
import bbc

secs = int([a for a in sys.argv[1:] if a.isdigit()][0]) if any(a.isdigit() for a in sys.argv[1:]) else 20
dev = next((os.path.dirname(f) for f in __import__("glob").glob("/sys/bus/usb/devices/*/idProduct")
            if open(f).read().strip() == "0104" and open(os.path.dirname(f) + "/idVendor").read().strip() == "1d6b"), None)
data = os.urandom(20000); want = hashlib.sha256(data).digest()
ok = bad = 0; state = None; t0 = time.time(); events = []

def auth(v):
    open(dev + "/authorized", "w").write(str(v))

simulated = "--simulate" in sys.argv and os.geteuid() == 0 and dev
if "--simulate" in sys.argv and not simulated: print("(--simulate needs root; just unplug the cable instead)")
print(f"hashing for {secs}s; " + ("simulating unplug at 5s, replug at 10s" if simulated else "unplug and replug the board now"))
while time.time() - t0 < secs:
    el = time.time() - t0
    if simulated and 5 < el < 5.2 and dev: auth(0)
    if simulated and 10 < el < 10.2: auth(1)
    try:
        good = bbc.hash_("sha256-bbcrypto", data) == want
        ok += good; new = "working" if good else "WRONG ANSWER"
    except OSError as e:
        bad += 1; new = f"failing ({errno.errorcode.get(e.errno, e.errno)})"
    if new != state: events.append((el, new)); print(f"  t={el:5.1f}s  {new}"); state = new
    time.sleep(0.02)
print(f"done: {ok} good results, {bad} errors, wrong answers never returned: {'WRONG' not in str(events)}")
