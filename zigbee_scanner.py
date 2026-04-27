"""ZigbeeScanner - skeleton for nRF52840 dongle integration.

This is a stub. It implements the same surface as WiFiScanner / BLEScanner
(`start()`, `stop()`, `get_devices()`) so the UI can already include a
Zigbee tab, but it does not yet talk to the dongle.

Wiring it up later:
  1. Flash the Raytac MDBT50Q-CX (nRF52840) with Nordic's nRF Sniffer
     for 802.15.4 firmware. The dongle's open bootloader accepts
     `nrfutil dfu usb-serial -pkg sniffer.zip -p /dev/ttyACM0`.
  2. Install the nRF Sniffer plugin into Wireshark / tshark - it
     registers an extcap interface called `nrfsniffer`.
  3. Replace `_run_loop` below with a `tshark -i nrfsniffer -T json`
     subprocess that streams 802.15.4 + Zigbee NWK frames; parse
     short address / IEEE address / PAN ID and feed `self.devices`.
"""

import subprocess
import threading
import time

# Nordic Semi (1915) covers the dongle once it's running the sniffer
# firmware; Adafruit (239a) covers the same hardware while it's still
# in open bootloader mode pre-flash.
_NRF_USB_VIDS = ("1915:", "239a:")


class ZigbeeScanner:
    def __init__(self):
        self.devices = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._available_cached = None
        self._available_checked_at = 0.0

    def is_available(self):
        """True if a candidate nRF52840 dongle is plugged into USB.
        Cached for 5s so a render loop can call this without spamming lsusb."""
        now = time.time()
        if self._available_cached is not None and now - self._available_checked_at < 5.0:
            return self._available_cached
        try:
            r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=1.0)
            present = any(vid in r.stdout for vid in _NRF_USB_VIDS)
        except Exception:
            present = False
        self._available_cached = present
        self._available_checked_at = now
        return present

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
