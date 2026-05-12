"""SDRScanner — RTL-SDR v4 driven cellular cell discovery + decode for
rogue base station detection at conventions, training sites, etc.

Stage 1 (PR #6): status detection via lsusb.
Stage 2 (this module): drive grgsm_scanner + a configurable LTE cell-search
binary in a band-cycle subprocess loop and populate self.cells.
Stage 3 (future): OpenCellID baseline + IMSI catcher heuristics +
cell_alerts.

Capture model:
  - One background thread cycles a band table (US GSM 850/1900 + US LTE
    bands 2/4/5/12/13/17/25/26/41/66/71). Each pass spawns the relevant
    binary as a subprocess, reads its stdout line-by-line for a bounded
    duration, parses each line, and upserts into self.cells.
  - Only one subprocess holds the RTL-SDR at a time (the dongle is
    single-claim), so the cycle is strictly sequential.
  - Binaries that aren't on PATH are skipped — operators who only have
    gr-gsm installed still get 2G enumeration; the LTE half lights up
    once srsRAN's cell_search is dropped on PATH (setup_sdr.sh does this).

Heuristics + alerting (stage 3) belong in persistence._snapshot — that
layer already owns the alert queue and red banner pipeline. This module
deliberately stays a pure observation source.

The class still exposes the same surface as the other scanners
(start/stop/get_cells/status/is_available/error_count/last_packet_ts).
"""

import os
import re
import shutil
import subprocess
import threading
import time

from cell_analyzer import score_cell

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

# US-relevant bands. Order matters: PCS1900 is the most common stingray
# masquerade target so we hit it first in each cycle.
US_GSM_BANDS = ("PCS1900", "GSM850")
US_LTE_BANDS = (2, 4, 5, 12, 13, 17, 25, 26, 41, 66, 71)

# Per-band scan duration. grgsm_scanner finishes its sweep on its own in
# a few seconds; the LTE binary needs a wall-clock cap because it can
# loop forever if no cell decodes. 8s is enough for a single band sweep
# on a Pi 4 with an RTL-SDR.
_SCAN_DURATION_S = float(os.environ.get("DOPESCOPE_SDR_SCAN_DURATION_S", "8"))
_GAIN_DB         = int(os.environ.get("DOPESCOPE_SDR_GAIN", "40"))
_BIN_GRGSM       = os.environ.get("DOPESCOPE_SDR_BIN_GRGSM", "grgsm_scanner")
_BIN_LTE         = os.environ.get("DOPESCOPE_SDR_BIN_LTE",   "cell_search")

# A scanned cell is considered fresh and renderable for this long after
# its last observation. 60s tolerates the full band-cycle latency
# (~2 minutes) being slower than this, on purpose — cells that go quiet
# for >60s should drop off the live list so the operator's display
# reflects current RF reality, not a stale union of everything ever seen.
_CELL_TTL_S = 60.0

# grgsm_scanner emits one line per cell it found, in roughly this shape:
#   ARFCN:  237, Freq: 940.4M, CID: 1234, LAC: 5678, MCC: 310, MNC: 260, Pwr: -45
# Spacing varies across gr-gsm versions; this regex is permissive about
# whitespace and field order is anchored loosely with .*? between fields.
_RE_GRGSM = re.compile(
    r"ARFCN[:=]?\s*(?P<arfcn>\d+).*?"
    r"CID[:=]?\s*(?P<cid>\d+).*?"
    r"LAC[:=]?\s*(?P<lac>\d+).*?"
    r"MCC[:=]?\s*(?P<mcc>\d+).*?"
    r"MNC[:=]?\s*(?P<mnc>\d+).*?"
    r"Pwr[:=]?\s*(?P<pwr>-?\d+)",
    re.IGNORECASE,
)

# srsRAN_4G's cell_search example prints a "Found Cell" header line and
# then a SIB1-decoded line shortly after. We accept either shape on a
# single line OR as accumulated state across two lines (see parse_lte
# below). Examples we tolerate:
#   Cell found: EARFCN=2400 PCI=123 RSRP=-78.5
#   SIB1: MCC=310 MNC=260 TAC=0x0001 CI=0x00abc123
_RE_LTE_FOUND = re.compile(
    r"EARFCN[=:]\s*(?P<earfcn>\d+).*?"
    r"PCI[=:]\s*(?P<pci>\d+).*?"
    r"RSRP[=:]\s*(?P<rsrp>-?\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_RE_LTE_SIB1 = re.compile(
    r"MCC[=:]\s*(?P<mcc>\d+).*?"
    r"MNC[=:]\s*(?P<mnc>\d+).*?"
    r"TAC[=:]\s*(?:0x)?(?P<tac>[0-9a-fA-F]+).*?"
    r"(?:CI|CELL[\s_-]?ID)[=:]\s*(?:0x)?(?P<cid>[0-9a-fA-F]+)",
    re.IGNORECASE,
)


def parse_grgsm_line(line):
    """Pull a 2G cell out of one grgsm_scanner stdout line. Returns
    a dict matching self.cells row shape, or None if the line is noise.

    Extracted as a module-level function so tests can exercise it
    without a real RTL-SDR or subprocess."""
    m = _RE_GRGSM.search(line)
    if not m:
        return None
    return {
        "tech":    "GSM",
        "mcc":     int(m.group("mcc")),
        "mnc":     int(m.group("mnc")),
        "cell_id": int(m.group("cid")),
        "lac":     int(m.group("lac")),
        "arfcn":   int(m.group("arfcn")),
        "rssi":    int(m.group("pwr")),
    }


def parse_lte_text(text):
    """Pull an LTE cell out of an accumulated chunk of cell_search output.

    cell_search emits the EARFCN/PCI line and the SIB1 line separately
    on most builds, so the capture loop accumulates a few lines worth of
    output per cell-found event and hands the whole block to this
    function. Returns a row dict or None if either half is missing."""
    cell = {"tech": "LTE"}
    m1 = _RE_LTE_FOUND.search(text)
    if m1:
        cell["earfcn"] = int(m1.group("earfcn"))
        cell["pci"]    = int(m1.group("pci"))
        # RSRP comes through as a float (e.g. -78.5). Truncate to int —
        # we store rssi as integer dBm everywhere else.
        cell["rssi"]   = int(float(m1.group("rsrp")))
    m2 = _RE_LTE_SIB1.search(text)
    if m2:
        cell["mcc"]     = int(m2.group("mcc"))
        cell["mnc"]     = int(m2.group("mnc"))
        cell["tac"]     = int(m2.group("tac"), 16)
        cell["cell_id"] = int(m2.group("cid"), 16)
    # Need both halves: a found-cell line without SIB1 decode tells us
    # there's RF energy but not what cell it is; not useful for rogue
    # discrimination. Bin it.
    if "cell_id" not in cell or "mcc" not in cell:
        return None
    return cell


class SDRScanner:
    def __init__(self):
        # Keyed by (mcc, mnc, cell_id, tech). tech is "LTE" or "GSM".
        self.cells = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._status_cached = None
        self._status_checked_at = 0.0
        # Set True once the capture loop has successfully parsed a cell
        # from a subprocess. Drives "scanning" vs "present" in status().
        self._capturing = False
        # Per-binary availability — populated once at loop start so we
        # don't shell out shutil.which() on every band cycle.
        self._has_grgsm = False
        self._has_lte   = False
        # OpenCellID baseline for rogue-cell scoring. None means no
        # baseline available; score_cell() handles that gracefully by
        # skipping the baseline-dependent heuristics. main.py loads
        # this at startup and hands it to us via set_baseline().
        self._baseline = None
        # Same health surface as WiFiScanner / BLEScanner / ZigbeeScanner
        # so the topbar warning logic treats them uniformly.
        self.error_count    = 0
        self.last_packet_ts = 0.0

    def status(self):
        """Return one of:
          - "absent"   : no RTL-SDR on USB
          - "present"  : RTL-SDR detected, capture loop idle / no binaries
          - "scanning" : capture loop has decoded at least one cell
        Cached for 5s so the render loop can call it cheaply.
        """
        now = time.time()
        if self._status_cached is not None and now - self._status_checked_at < 5.0:
            base = self._status_cached
        else:
            base = self._dongle_present_now()
            self._status_cached = base
            self._status_checked_at = now
        if base == "absent":
            return "absent"
        return "scanning" if self._capturing else "present"

    def _dongle_present_now(self):
        try:
            r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=1.0)
            lines = r.stdout.splitlines()
        except Exception:
            return "absent"
        for line in lines:
            m = _LSUSB_LINE.match(line)
            if not m:
                continue
            if (m.group(1).lower(), m.group(2).lower()) in _RTLSDR_VID_PIDS:
                return "present"
        return "absent"

    def is_available(self):
        """True if an RTL-SDR is plugged in. The Cell tab uses this to
        decide whether to render NO SDR vs. live capture state."""
        return self.status() != "absent"

    def set_baseline(self, baseline):
        """Install an OpenCellID baseline (set of (mcc, mnc, cell_id, tech)
        tuples) for the heuristic scorer. Pass None to disable
        baseline-aware scoring. Re-scores any cells already observed
        so the UI doesn't have to wait for the next capture cycle to
        reflect the new baseline."""
        self._baseline = baseline
        with self._lock:
            all_cells = list(self.cells.values())
            for cell in all_cells:
                risk, reasons = score_cell(cell, baseline, all_cells)
                cell["risk"]    = risk
                cell["reasons"] = reasons

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        # Don't join — _run_capture_subprocess can take up to
        # _SCAN_DURATION_S to return after _running flips. The thread is
        # daemon=True so it dies with the process anyway, and main.py's
        # shutdown sequence doesn't need to block on us.

    def _run_loop(self):
        # Probe for capture binaries once. shutil.which is cheap but
        # logging "binary missing" every cycle would be operator-hostile.
        self._has_grgsm = shutil.which(_BIN_GRGSM) is not None
        self._has_lte   = shutil.which(_BIN_LTE)   is not None
        if not (self._has_grgsm or self._has_lte):
            print(f"[sdr] no capture binaries on PATH ({_BIN_GRGSM}, {_BIN_LTE}). "
                  "Run tools/setup_sdr.sh to install gr-gsm + srsRAN_4G.")
            while self._running:
                time.sleep(2.0)
            return

        if self._has_grgsm:
            print(f"[sdr] using {_BIN_GRGSM} for GSM enumeration")
        if self._has_lte:
            print(f"[sdr] using {_BIN_LTE} for LTE cell search")

        while self._running:
            if self._has_grgsm:
                for band in US_GSM_BANDS:
                    if not self._running:
                        break
                    self._scan_gsm(band)
            if self._has_lte:
                for band in US_LTE_BANDS:
                    if not self._running:
                        break
                    self._scan_lte(band)
            # Brief pacing so a fast-failing binary doesn't pin the CPU.
            for _ in range(4):
                if not self._running:
                    break
                time.sleep(0.25)

    def _scan_gsm(self, band):
        """Run grgsm_scanner against one GSM band; parse cells off stdout."""
        cmd = [_BIN_GRGSM, "-b", band, "-g", str(_GAIN_DB)]
        try:
            self._run_capture_subprocess(cmd, _SCAN_DURATION_S, parse_grgsm_line)
        except FileNotFoundError:
            # Binary disappeared between probe and now (apt remove,
            # PATH change). Stop trying for the rest of the session.
            self._has_grgsm = False
            self.error_count += 1
        except Exception as e:
            self.error_count += 1
            print(f"[sdr] gsm scan ({band}) failed: {e}")

    def _scan_lte(self, band):
        """Run the configured LTE cell-search binary against one band.

        cell_search emits two-line cell records (EARFCN/PCI line plus a
        separate SIB1 line). We batch lines into a rolling block-of-6
        window and re-run the LTE parser on each new line so a complete
        cell pops out regardless of which line of the pair arrives first."""
        cmd = [_BIN_LTE, "-b", str(band)]
        buf = []

        def parse_with_block_window(line):
            buf.append(line)
            if len(buf) > 6:
                buf.pop(0)
            cell = parse_lte_text("\n".join(buf))
            if cell is not None:
                # Clear the buffer so the same lines don't re-emit on the
                # next call — once we've extracted a cell, those lines
                # are spent.
                buf.clear()
            return cell

        try:
            self._run_capture_subprocess(cmd, _SCAN_DURATION_S, parse_with_block_window)
        except FileNotFoundError:
            self._has_lte = False
            self.error_count += 1
        except Exception as e:
            self.error_count += 1
            print(f"[sdr] lte scan (band {band}) failed: {e}")

    def _run_capture_subprocess(self, cmd, duration_s, parse_line):
        """Spawn `cmd`, stream stdout line-by-line into `parse_line`,
        record any returned cell, and terminate the process after
        `duration_s`. Used by both _scan_gsm and _scan_lte so the
        timeout + cleanup logic lives in one place."""
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,  # line-buffered so we see cells as they decode
        )
        deadline = time.time() + duration_s
        try:
            while self._running and time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    # Process exited or pipe closed before deadline —
                    # normal grgsm_scanner finish.
                    break
                try:
                    cell = parse_line(line)
                except Exception:
                    cell = None
                if cell is not None:
                    self._record(cell)
                    self._capturing = True
                    self.last_packet_ts = time.time()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        pass

    def _record(self, cell):
        """Upsert a parsed cell observation into self.cells under the
        lock. Brand new cells get first_seen + hits=1; re-observed cells
        bump last_seen, hits, and rssi_max."""
        now = time.time()
        # Cells without a complete identity tuple are useless for
        # rogue discrimination — drop them at the door.
        key = (cell.get("mcc"), cell.get("mnc"), cell.get("cell_id"), cell.get("tech"))
        if None in key:
            return
        with self._lock:
            existing = self.cells.get(key)
            rssi = cell.get("rssi", -120)
            if existing is None:
                cell["first_seen"] = now
                cell["last_seen"]  = now
                cell["hits"]       = 1
                cell["rssi_max"]   = rssi
                self.cells[key] = cell
                target = cell
            else:
                existing["last_seen"] = now
                existing["hits"]      = existing.get("hits", 0) + 1
                existing["rssi"]      = rssi
                existing["rssi_max"]  = max(existing.get("rssi_max", rssi), rssi)
                # Refresh band-side fields too in case a later observation
                # decoded more metadata than the first.
                for f in ("earfcn", "arfcn", "tac", "lac", "pci"):
                    if f in cell and cell[f] is not None:
                        existing[f] = cell[f]
                target = existing
            # Score the cell every time we touch it. The heuristics
            # depend on hits + rssi_max + the live set of co-observed
            # cells, so a re-observation can move risk up or down.
            risk, reasons = score_cell(
                target, self._baseline, self.cells.values()
            )
            target["risk"]    = risk
            target["reasons"] = reasons

    def get_cells(self, sort_by="rssi"):
        with self._lock:
            cells = list(self.cells.values())
        now = time.time()
        # Cells age out after _CELL_TTL_S of not being re-observed.
        cells = [c for c in cells if now - c.get("last_seen", 0) < _CELL_TTL_S]
        if sort_by == "risk":
            cells.sort(key=lambda c: c.get("risk", 0), reverse=True)
        else:
            cells.sort(key=lambda c: c.get("rssi", -120), reverse=True)
        return cells
