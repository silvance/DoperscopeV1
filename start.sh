#!/bin/bash

# Wi-Fi monitor adapter. Override at deploy time:
#   DOPESCOPE_WIFI_IFACE=wlan2 sudo bash start.sh
WIFI_IFACE="${DOPESCOPE_WIFI_IFACE:-wlan1}"
export DOPESCOPE_WIFI_IFACE="$WIFI_IFACE"

# 1. Wait for the OS and USB bus to fully settle
sleep 10

# 1b. Warn (don't block) if NetworkManager is managing the scan
#     interface. NM aggressively reclaims interfaces it considers its
#     own, which silently drops them out of monitor mode mid-sweep.
#     The fix is to mark $WIFI_IFACE unmanaged in NM's config; we
#     don't apply that automatically since it persists across reboots
#     and the operator may want to keep their config under their own
#     control.
if command -v nmcli >/dev/null 2>&1; then
    if nmcli -t -f DEVICE,STATE device 2>/dev/null \
        | grep -E "^${WIFI_IFACE}:(connected|connecting|disconnected)" >/dev/null; then
        echo "WARNING: NetworkManager is managing $WIFI_IFACE."
        echo "  It will reclaim the interface mid-scan and drop monitor mode."
        echo "  To fix permanently, append to /etc/NetworkManager/NetworkManager.conf:"
        echo "    [keyfile]"
        echo "    unmanaged-devices=interface-name:$WIFI_IFACE"
        echo "  Then: sudo systemctl restart NetworkManager"
        echo "  Continuing — sweeps may be unreliable until that's set."
    fi
fi

# 2. Kill any wpa_supplicant that's holding $WIFI_IFACE specifically.
#    The previous version did `killall wpa_supplicant`, which also
#    killed the supplicant managing wlan0 (the Pi's onboard Wi-Fi)
#    and broke its network connection. The regex requires the iface
#    appear as an `-i wlanX` argument so we don't accidentally match
#    unrelated processes whose cmdline happens to contain both
#    "wpa_supplicant" and "wlan1" as substrings.
/usr/bin/pkill -f "wpa_supplicant.*-i[[:space:]]*${WIFI_IFACE}\b" 2>/dev/null || true

# 3. Clear any soft-blocks
/usr/sbin/rfkill unblock all

# 4. Force monitor mode and PRIME THE CHANNEL
/usr/sbin/ip link set "$WIFI_IFACE" down
/usr/sbin/iw dev "$WIFI_IFACE" set type monitor
/usr/sbin/ip link set "$WIFI_IFACE" up
/usr/sbin/iw dev "$WIFI_IFACE" set channel 6

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
