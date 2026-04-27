#!/bin/bash

# 1. Wait for the OS and USB bus to fully settle
sleep 10

# 2. Kill the built-in Wi-Fi manager so it stops hijacking wlan1
/usr/bin/killall wpa_supplicant 2>/dev/null || true

# 3. Clear any soft-blocks
/usr/sbin/rfkill unblock all

# 4. Force monitor mode and PRIME THE CHANNEL
/usr/sbin/ip link set wlan1 down
/usr/sbin/iw dev wlan1 set type monitor
/usr/sbin/ip link set wlan1 up
/usr/sbin/iw dev wlan1 set channel 6

# 5. Launch with unbuffered output (-u) so we can see errors
cd "$(dirname "$(readlink -f "$0")")"
/usr/bin/python3 -u main.py
