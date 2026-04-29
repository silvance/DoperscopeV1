"""ZigbeeScanner - skeleton for nRF52840 dongle integration.

This is a stub. It implements the same surface as WiFiScanner / BLEScanner
(`start()`, `stop()`, `get_devices()`) so the UI can already include a
Zigbee tab, but it does not yet talk to the dongle.

Wiring it up later:
  1. Flash the Raytac MDBT50Q-CX (nRF52840) with Nordic's nRF Sniffer
     for 802.15.4 firmware. The dongle's open bootloader accepts
     `nrfutil dfu usb-serial -pkg sniffer.zip -p /dev/ttyACM0`.
     `tools/flash_nrf_sniffer.sh` wraps that command.
  2. Install the nRF Sniffer plugin into Wireshark / tshark - it
     registers an extcap interface called `nrfsniffer`.
  3. Replace `_run_loop` below with a `tshark -i nrfsniffer -T json`
     subprocess that streams 802.15.4 + Zigbee NWK frames; parse
     short address / IEEE address / PAN ID and feed `self.devices`.
"""

import re
import subprocess
import threading
import time

# USB VID:PID patterns we recognise. Notes:
#  - 1915:c00a = Nordic nRF Sniffer for 802.15.4 (most common build);
#    when we see this the dongle is ready to scan and we can launch
#    `tshark -i nrfsniffer` against it.
#  - 1915:* (anything else with the Nordic VID) = open bootloader or
#    some other Nordic firmware; assume the operator still needs to
#    flash the sniffer firmware before it'll capture.
#  - 239a:* = Adafruit / open-bootloader enumeration that some
#    MDBT50Q-CX units ship with; same conclusion as above.
_LSUSB_LINE = re.compile(r"^Bus \S+ Device \S+: ID (\w{4}):(\w{4})", re.IGNORECASE)
_SNIFFER_VID_PID = ("1915", "c00a")
_BOOTLOADER_VIDS = ("1915", "239a")


class ZigbeeScanner:
    def __init__(self):
        self.devices = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._status_cached = None
        self._status_checked_at = 0.0

    def status(self):
        """Return one of:
          - "absent"     : no nRF52840 dongle on USB at all
          - "bootloader" : dongle present but firmware is the open bootloader
                           (or anything other than the sniffer); needs flashing
          - "sniffer"    : Nordic nRF Sniffer firmware running, ready to capture
        Cached for 5s so the render loop can call this every frame.
        """
        now = time.time()
        if self._status_cached is not None and now - self._status_checked_at < 5.0:
            return self._status_cached
        try:
            r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=1.0)
            lines = r.stdout.splitlines()
        except Exception:
            self._status_cached = "absent"
            self._status_checked_at = now
            return self._status_cached

        seen_sniffer    = False
        seen_bootloader = False
        for line in lines:
            m = _LSUSB_LINE.match(line)
            if not m:
                continue
            vid, pid = m.group(1).lower(), m.group(2).lower()
            if (vid, pid) == _SNIFFER_VID_PID:
                seen_sniffer = True
                break
            if vid in _BOOTLOADER_VIDS:
                seen_bootloader = True

        if seen_sniffer:
            status = "sniffer"
        elif seen_bootloader:
            status = "bootloader"
        else:
            status = "absent"

        self._status_cached = status
        self._status_checked_at = now
        return status

    def is_available(self):
        """True if a candidate nRF52840 dongle is plugged in (any state)."""
        return self.status() != "absent"

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _run_loop(self):
        # Stub. Replace with a tshark subprocess that streams nrfsniffer JSON.
        while self._running:
            time.sleep(1.0)

    def get_devices(self, sort_by="rssi"):
        with self._lock:
            devs = list(self.devices.values())
        now = time.time()
        devs = [d for d in devs if now - d.get("last_seen", 0) < 60]
        if sort_by == "rssi":
            devs.sort(key=lambda d: d.get("rssi", -100), reverse=True)
        elif sort_by == "name":
            devs.sort(key=lambda d: (d.get("name") or "").lower())
        return devs
