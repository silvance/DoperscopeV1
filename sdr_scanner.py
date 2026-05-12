"""SDRScanner — RTL-SDR v4 driven cellular cell discovery + decode for
rogue base station detection at conventions, training sites, etc.

Status detection mirrors ZigbeeScanner: lsusb scan for the Realtek
RTL2832U chipset, cached for 5s so the render loop can call it cheaply.
The actual cell capture path (srsRAN_4G cell_search for LTE, gr-gsm's
grgsm_scanner for 2G) is the stage-2 follow-up and lives in _run_loop
as a stub for now.

Wiring it up later (stage 2 — cell capture):
  1. Install srsRAN_4G + gr-gsm + RTL-SDR udev rules via
     tools/setup_sdr.sh.
  2. Replace _run_loop below with a subprocess cycle that:
       - srsRAN: scan US LTE bands (2/4/5/12/13/17/25/26/41/66/71),
         decode SIB1 to extract MCC, MNC, EARFCN, TAC, cell ID, PCI.
       - grgsm_scanner: enumerate visible 2G cells in 850 / 1900 MHz
         bands, capturing ARFCN, LAC, cell ID, MCC, MNC, power.
  3. Populate self.cells keyed by (mcc, mnc, cell_id, tech).

Wiring it up later (stage 3 — rogue detection):
  4. Load an OpenCellID US snapshot at startup as the legitimacy baseline.
  5. Score each detected cell against the snapshot + heuristics
     (encryption disabled / A5/0, sudden 2G appearance under LTE coverage,
     isolated tower with no neighbor list, cell-ID seen only briefly with
     high power) — produce a risk_score 0–100.
  6. Fire cell alerts via persistence._maybe_alert so the existing red
     banner + Log tab pipeline carries them.

The class deliberately exposes the same surface as the other scanners
(start/stop/get_cells/status/error_count/last_packet_ts) so the UI can
treat them uniformly.
"""

import re
import subprocess
import threading
import time

# All RTL2832U-based dongles enumerate with Realtek VID 0bda. The v4
# variant uses the same VID:PIDs as earlier generations (it's
# distinguished only by tuner chip); for the "is a usable SDR plugged in"
# question, the VID:PID set below is sufficient.
_LSUSB_LINE = re.compile(r"^Bus \S+ Device \S+: ID (\w{4}):(\w{4})", re.IGNORECASE)
_RTLSDR_VID_PIDS = {
    ("0bda", "2832"),  # Realtek RTL2832U — common
    ("0bda", "2838"),  # Realtek RTL2832U DVB-T — most current RTL-SDR variants
    ("1d50", "604b"),  # OpenMoko-allocated variant (rare but legitimate)
}


class SDRScanner:
    def __init__(self):
        # Keyed by (mcc, mnc, cell_id, tech). tech is "LTE" or "GSM".
        self.cells = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._status_cached = None
        self._status_checked_at = 0.0
        # Same health surface as WiFiScanner / BLEScanner / ZigbeeScanner
        # so the topbar warning logic treats them uniformly.
        self.error_count    = 0
        self.last_packet_ts = 0.0

    def status(self):
        """Return one of:
          - "absent"   : no RTL-SDR on USB
          - "present"  : RTL-SDR detected, capture stubbed (stage 1)
          - "scanning" : capture loop is actively decoding cells (stage 2+)
        Cached for 5s so the render loop can call it cheaply.
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

        present = False
        for line in lines:
            m = _LSUSB_LINE.match(line)
            if not m:
                continue
            if (m.group(1).lower(), m.group(2).lower()) in _RTLSDR_VID_PIDS:
                present = True
                break

        self._status_cached = "present" if present else "absent"
        self._status_checked_at = now
        return self._status_cached

    def is_available(self):
        """True if an RTL-SDR is plugged in and the capture loop should
        eventually be able to use it. Stage-1 capture is stubbed, so this
        only tells the UI whether to render the 'Cell' tab as actionable
        or as 'plug a dongle in'."""
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
        # Stub. Stage 2 replaces this with a band-cycle that drives
        # srsRAN's cell_search + gr-gsm's grgsm_scanner via subprocess,
        # parses their output, and feeds self.cells.
        while self._running:
            time.sleep(1.0)

    def get_cells(self, sort_by="rssi"):
        with self._lock:
            cells = list(self.cells.values())
        now = time.time()
        # Cells age out after 60s of not being re-observed. Cellular
        # observations are slower than Wi-Fi so the window is longer.
        cells = [c for c in cells if now - c.get("last_seen", 0) < 60]
        if sort_by == "risk":
            cells.sort(key=lambda c: c.get("risk", 0), reverse=True)
        else:
            cells.sort(key=lambda c: c.get("rssi", -120), reverse=True)
        return cells
