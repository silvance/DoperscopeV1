#!/bin/bash
# Flash the Raytac MDBT50Q-CX (nRF52840 dongle) with the nRF Sniffer for
# 802.15.4 firmware so the Zigbee tab can capture frames. Run once per
# dongle; the firmware persists across reboots.
#
# Accepts either of:
#   - A pre-packaged DFU .zip (with manifest.json) — flashed directly.
#   - A raw .hex file (e.g. nrf802154_sniffer_nrf52840dongle.hex from
#     Nordic's GitHub) — automatically wrapped into a DFU package via
#     `nrfutil pkg generate` before flashing.
#
# Prerequisites:
#   - The dongle is plugged in. The script auto-detects /dev/ttyACM[0-2].
#     If it doesn't appear, double-press the dongle's reset button to
#     enter DFU bootloader mode (LD2 LED blinks red).
#   - Firmware sits at tools/firmware/nrf_sniffer.{zip,hex}, or pass
#     a path as arg 1.
#   - nrfutil is installed (pip install nrfutil --break-system-packages).
#
# Usage:
#   sudo bash tools/flash_nrf_sniffer.sh [/path/to/firmware.{zip,hex}] [/dev/ttyACMN]

set -euo pipefail

usage() {
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

case "${1:-}" in
    -h|--help) usage ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# Default search: prefer .zip if present, else fall back to .hex.
FIRMWARE="${1:-}"
if [ -z "$FIRMWARE" ]; then
    for candidate in "$SCRIPT_DIR/firmware/nrf_sniffer.zip" \
                     "$SCRIPT_DIR/firmware/nrf_sniffer.hex" \
                     "$SCRIPT_DIR/firmware/nrf802154_sniffer_nrf52840dongle.hex"; do
        if [ -f "$candidate" ]; then
            FIRMWARE="$candidate"
            break
        fi
    done
fi

if [ -z "$FIRMWARE" ] || [ ! -f "$FIRMWARE" ]; then
    echo "ERROR: firmware not found." >&2
    echo "Drop a .zip (DFU package) or .hex (raw firmware) at:" >&2
    echo "  tools/firmware/nrf_sniffer.zip   or" >&2
    echo "  tools/firmware/nrf_sniffer.hex" >&2
    echo "...or pass the path as arg 1." >&2
    exit 1
fi

# nrfutil is commonly installed per-user via `pip install --user`, which
# lands in $HOME/.local/bin. Under sudo, $HOME flips to /root and that
# path falls off PATH, so the binary appears to be missing. Look in the
# calling user's home (via SUDO_USER) before giving up.
if ! command -v nrfutil >/dev/null 2>&1; then
    if [ -n "${SUDO_USER:-}" ]; then
        USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        if [ -x "$USER_HOME/.local/bin/nrfutil" ]; then
            export PATH="$USER_HOME/.local/bin:$PATH"
        fi
    fi
fi
if ! command -v nrfutil >/dev/null 2>&1; then
    echo "ERROR: nrfutil not on PATH." >&2
    echo "  - System-wide install:  sudo pip install nrfutil --break-system-packages" >&2
    echo "  - User-level install:   pip install nrfutil --break-system-packages" >&2
    echo "    (then re-run this script — SUDO_USER lookup will find it)" >&2
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
    echo "ERROR: no /dev/ttyACM* found. Plug the dongle in (double-press" >&2
    echo "reset to enter DFU mode) and try again. Pass the port as arg 2" >&2
    echo "if it's enumerating elsewhere." >&2
    exit 1
fi

# If we were handed a raw .hex, wrap it into a DFU package first. The
# --sd-req 0xB6 sentinel matches the nRF52840 dongle's stock Nordic
# Open Bootloader (PCA10059); it tells the bootloader "this app does
# not require a SoftDevice." If your dongle has a different bootloader
# (e.g. Adafruit's, sentinel 0xCAFE) and the flash errors with an
# sd-req mismatch, override SD_REQ in the env, e.g.:
#   sudo SD_REQ=0xCAFE bash tools/flash_nrf_sniffer.sh
SD_REQ="${SD_REQ:-0xB6}"
PKG="$FIRMWARE"
case "${FIRMWARE,,}" in
    *.hex)
        PKG="$(mktemp --suffix=.zip)"
        trap 'rm -f "$PKG"' EXIT
        echo "HEX detected — wrapping into DFU package..."
        echo "  hex     : $FIRMWARE"
        echo "  out     : $PKG"
        echo "  sd-req  : $SD_REQ"
        nrfutil pkg generate \
            --hw-version 52 \
            --sd-req "$SD_REQ" \
            --application "$FIRMWARE" \
            --application-version 1 \
            "$PKG"
        echo
        ;;
    *.zip)
        ;;
    *)
        echo "ERROR: firmware must be .zip or .hex (got: $FIRMWARE)" >&2
        exit 1
        ;;
esac

echo "Firmware : $FIRMWARE"
echo "Package  : $PKG"
echo "Port     : $PORT"
echo
echo "Flashing — do NOT unplug. This takes ~30 seconds."
nrfutil dfu usb-serial -pkg "$PKG" -p "$PORT"

echo
echo "Done. Unplug and re-plug the dongle, then check the Zigbee tab."
echo "Status should switch from BLE SNIFFER FW / NEEDS FLASH to READY."
