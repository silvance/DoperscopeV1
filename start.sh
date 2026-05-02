#!/bin/bash

# 1. Wait for the OS and USB bus to fully settle
sleep 10

# 2. Kill any wpa_supplicant that's holding wlan1 specifically. The
#    previous version did `killall wpa_supplicant`, which also killed
#    the supplicant managing wlan0 (the Pi's onboard Wi-Fi) and broke
#    its network connection. Scope strictly to wlan1.
/usr/bin/pkill -f "wpa_supplicant.*wlan1" 2>/dev/null || true

# 3. Clear any soft-blocks
/usr/sbin/rfkill unblock all

# 4. Force monitor mode and PRIME THE CHANNEL
/usr/sbin/ip link set wlan1 down
/usr/sbin/iw dev wlan1 set type monitor
/usr/sbin/ip link set wlan1 up
/usr/sbin/iw dev wlan1 set channel 6

# 5. Kill any orphaned main.py from a previous session that's still
#    holding the Game HAT GPIO pins. lgpio cleanup at the top of main.py
#    can only release pins claimed by the same process — orphan claims
#    have to be killed at the OS level. The brief sleep gives the kernel
#    time to release the GPIO claim before the new process tries to grab.
/usr/bin/pkill -f "python3 -u main.py" 2>/dev/null || true
sleep 1

# 6. Launch with unbuffered output (-u) so we can see errors
cd "$(dirname "$(readlink -f "$0")")"
/usr/bin/python3 -u main.py
