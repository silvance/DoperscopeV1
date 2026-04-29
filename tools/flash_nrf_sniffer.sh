#!/bin/bash
# Flash the Raytac MDBT50Q-CX (nRF52840 dongle) with the nRF Sniffer for
# 802.15.4 firmware so the Zigbee tab can capture frames. Run this once
# per dongle, after which the firmware persists.
#
# Prerequisites you must satisfy yourself:
#   - The dongle is plugged into the Pi via USB and shows up as
#     /dev/ttyACM0 (the script will detect it).
#   - The nRF Sniffer firmware archive is at tools/firmware/nrf_sniffer.zip.
#     Download it from Nordic's nRF Sniffer for 802.15.4 product page on
#     a connected host and copy it onto the Pi (SD card, USB, scp).
#   - python3-nrfutil is installed:
#       pip install nrfutil          # connected host
#       # or include it in your air-gapped wheelhouse
#
# Usage:
#   sudo bash tools/flash_nrf_sniffer.sh [/path/to/firmware.zip] [/dev/ttyACMN]

set -euo pipefail

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

case "${1:-}" in
    -h|--help) usage ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
FIRMWARE="${1:-$SCRIPT_DIR/firmware/nrf_sniffer.zip}"

if [ ! -f "$FIRMWARE" ]; then
    echo "ERROR: firmware archive not found at: $FIRMWARE" >&2
    echo "Drop the nRF Sniffer for 802.15.4 ZIP there, or pass the path as arg 1." >&2
    exit 1
fi

if ! command -v nrfutil >/dev/null 2>&1; then
    echo "ERROR: nrfutil not on PATH. Install with: pip install nrfutil" >&2
    exit 1
fi

# Pick the dongle's serial port. Override by passing a path as arg 2.
PORT="${2:-}"
if [ -z "$PORT" ]; then
    for candidate in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyACM2; do
        if [ -e "$candidate" ]; then
            PORT="$candidate"
            break
        fi
    done
fi
if [ -z "$PORT" ] || [ ! -e "$PORT" ]; then
    echo "ERROR: no /dev/ttyACM* found. Plug the dongle in and try again." >&2
    echo "If it's enumerating elsewhere, pass the port as arg 2." >&2
    exit 1
fi

echo "Firmware : $FIRMWARE"
echo "Port     : $PORT"
echo
echo "Flashing - do NOT unplug. This takes ~30 seconds."
nrfutil dfu usb-serial -pkg "$FIRMWARE" -p "$PORT"

echo
echo "Done. Unplug and re-plug the dongle, then check the Zigbee tab."
echo "Status should switch from NEEDS FLASH to READY."
