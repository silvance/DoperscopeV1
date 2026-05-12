"""Rogue base station detection heuristics + OpenCellID baseline.

Stage 3 of the rogue base station pipeline. Given a cell observation
from sdr_scanner, score_cell() returns (risk, reasons) where:

  - risk is an integer 0-100. Heuristic accumulator, clamped at 100.
  - reasons is a list of short stable strings (used both for the UI
    display and the cell_alerts.reasons JSON column).

Heuristics implemented here are deliberately conservative — designed
to fire on textbook stingray patterns, not on every legitimate cell.
The operator can dial the alert threshold via DOPESCOPE_CELL_ALERT_RISK.

Baseline:
  - load_opencellid_baseline() reads an OpenCellID CSV snapshot into
    a set of (mcc, mnc, cell_id, tech) tuples. Memory-bounded by
    filtering on US MCCs by default; without the filter the full
    OCID global CSV would blow past a Pi 4's 4GB.
  - The operator drops the CSV at ~/.doperscope/opencellid/ocid_us.csv
    (snapshot URL: https://opencellid.org/downloads.php — requires
    free registration for an API key). Filter to MCC=310/311/312 etc
    before saving to keep the file small.

If no baseline is available, heuristics that depend on it (H1, H5) are
skipped — the MCC/MNC plausibility checks (H2, H3) and the 2G-in-LTE
downgrade check (H4) still fire so the tool is useful out of the box.
"""

import csv
import os


# US MCC codes (per ITU). Anything outside this set on US soil is a
# strong rogue signal — a stingray operator who didn't customize the
# default Yate / OpenBTS config will broadcast 001 or a foreign MCC.
US_MCCS = frozenset({310, 311, 312, 313, 314, 315, 316})

# Known US MNC values per MCC. Not exhaustive — small MVNOs and
# regional carriers come and go — but covers the big four (AT&T,
# Verizon, T-Mobile, Sprint) plus most well-known MVNOs. An MNC NOT in
# this table doesn't automatically mean rogue, but it's worth a partial
# risk bump combined with other signals.
KNOWN_US_MNC_BY_MCC = {
    310: frozenset({
        7, 12, 17, 70, 80, 90, 100, 110, 120, 150, 160, 170, 200, 210,
        220, 230, 240, 250, 260, 270, 280, 290, 300, 310, 320, 330, 340,
        350, 380, 390, 400, 410, 420, 430, 440, 450, 460, 470, 480, 490,
        500, 510, 520, 530, 540, 560, 570, 580, 590, 600, 620, 630, 640,
        650, 660, 670, 680, 690, 730, 740, 760, 770, 780, 790, 800, 830,
        840, 850, 870, 880, 890, 900, 910, 940, 950, 960, 970, 980, 990,
        1000,
    }),
    311: frozenset({
        12, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
        150, 160, 170, 180, 190, 210, 220, 230, 240, 260, 270, 280,
        310, 330, 340, 360, 370, 380, 390, 410, 440, 450, 470, 480,
        490, 530, 540, 570, 580, 590, 660, 670, 680, 740, 870, 880,
    }),
    312: frozenset({30, 70, 170, 220, 250, 350, 360, 530, 670, 770}),
    313: frozenset({100}),
}

# Cells with this many or fewer observations are "brief" — relevant for
# the textbook-stingray heuristic (strong + brief + unknown).
_BRIEF_HITS = 5
# Stronger than -60 dBm on cellular is unusual unless the cell is
# physically close. Combined with "brief + unknown" it's the signature
# of a portable rogue tower right next to the target.
_STRONG_RSSI = -60


def load_opencellid_baseline(path, mcc_filter=US_MCCS):
    """Load an OpenCellID CSV snapshot into a set of
    (mcc, mnc, cell_id, tech) tuples. Returns None if the file is
    missing or the load fails — caller treats None as "no baseline".

    OCID CSV columns (no header):
      radio, mcc, net, area, cell, unit, lon, lat, range,
      samples, changeable, created, updated, averageSignal

    mcc_filter limits which cells are kept in memory. Default is the US
    MCC set; pass `None` to disable filtering (operator beware: the
    full global CSV is ~10M cells and won't fit in a Pi 4's RAM)."""
    if not path or not os.path.exists(path):
        return None
    baseline = set()
    kept = 0
    seen = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            first = next(reader, None)
            if first is not None and _row_is_data(first):
                _add_row(baseline, first, mcc_filter)
                if first:
                    seen += 1
            for row in reader:
                seen += 1
                if _add_row(baseline, row, mcc_filter):
                    kept += 1
    except Exception as e:
        print(f"[cell_analyzer] baseline load failed ({path}): {e}")
        return None
    print(f"[cell_analyzer] OCID baseline loaded: {kept}/{seen} cells kept "
          f"({path})")
    return baseline


def _row_is_data(row):
    """OCID files don't have headers but defensive callers might add
    one. If row[1] doesn't parse as an int, treat the row as a header
    and skip it."""
    if len(row) < 5:
        return False
    try:
        int(row[1])
        return True
    except ValueError:
        return False


def _add_row(baseline, row, mcc_filter):
    """Returns True if the row was kept, False if skipped."""
    try:
        radio = row[0].strip().upper()
        mcc   = int(row[1])
        mnc   = int(row[2])
        cell  = int(row[4])
    except (IndexError, ValueError):
        return False
    if mcc_filter is not None and mcc not in mcc_filter:
        return False
    # OCID's "radio" field uses "LTE", "GSM", "UMTS", "CDMA", "NR".
    # We only score LTE + GSM right now; collapse UMTS into GSM since
    # the sdr_scanner stack doesn't decode 3G separately and a 3G entry
    # in the baseline at least confirms a legitimate cell ID.
    if radio == "LTE":
        tech = "LTE"
    elif radio in ("GSM", "UMTS"):
        tech = "GSM"
    else:
        return False
    baseline.add((mcc, mnc, cell, tech))
    return True


def score_cell(cell, baseline, all_cells=()):
    """Score one cell. Returns (risk, reasons).

    cell: dict from SDRScanner.cells — must have mcc/mnc/cell_id/tech.
    baseline: set from load_opencellid_baseline or None.
    all_cells: iterable of all currently-visible cells (including this
        one). Used for the 2G-in-LTE-coverage heuristic.
    """
    reasons = []
    risk = 0

    mcc  = cell.get("mcc")
    mnc  = cell.get("mnc")
    cid  = cell.get("cell_id")
    tech = cell.get("tech")
    rssi = cell.get("rssi", -120)

    # H1: not in OpenCellID. Strong signal on its own — a legitimate US
    # cell will be in the snapshot unless the operator filtered it out
    # or the snapshot is stale. We still cap this at 50 so a stale
    # snapshot doesn't blanket-alert the operator.
    in_baseline = False
    if baseline is not None and None not in (mcc, mnc, cid, tech):
        in_baseline = (mcc, mnc, cid, tech) in baseline
        if not in_baseline:
            risk += 50
            reasons.append("not_in_opencellid")

    # H2: MCC not in US table. A stingray running default OpenBTS
    # broadcasts MCC=001 (test PLMN); a misconfigured one might use
    # a foreign MCC. Either is a hard tell on US soil.
    if mcc is not None and mcc not in US_MCCS:
        risk += 40
        reasons.append(f"non_us_mcc:{mcc}")

    # H3: MNC not in the known set for this MCC. Soft signal — small
    # MVNOs and regional carriers can have legitimate MNCs we don't
    # know about — but combined with H1/H4 it adds up fast.
    known = KNOWN_US_MNC_BY_MCC.get(mcc)
    if known is not None and mnc is not None and mnc not in known:
        risk += 15
        reasons.append(f"unknown_us_mnc:{mcc}-{mnc}")

    # H4: 2G cell visible while an LTE cell is also visible. Modern US
    # carriers run LTE/5G with 2G as fallback only — and most have
    # already sunset 2G entirely (AT&T 2017, Verizon 2022, T-Mobile
    # 2024). A new 2G cell appearing in LTE coverage is the canonical
    # forced-downgrade attack signature.
    if tech == "GSM":
        lte_visible = any(c.get("tech") == "LTE" for c in all_cells)
        if lte_visible:
            risk += 25
            reasons.append("2g_in_lte_coverage")

    # H5: strong signal + few observations + not in baseline = textbook
    # portable rogue tower. Stingrays are designed to be physically
    # close to targets (high RSSI) and to disappear when the operator
    # leaves (few cumulative hits).
    if (rssi > _STRONG_RSSI
            and cell.get("hits", 0) <= _BRIEF_HITS
            and baseline is not None
            and not in_baseline):
        risk += 30
        reasons.append("strong_brief_unknown")

    return min(risk, 100), reasons
