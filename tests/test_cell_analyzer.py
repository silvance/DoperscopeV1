"""Tests for cell_analyzer — heuristic scorer + OpenCellID baseline loader."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cell_analyzer import (
    load_opencellid_baseline,
    score_cell,
    US_MCCS,
)


def _verizon_lte():
    # MCC 311 / MNC 480 = Verizon LTE. Real cell ID with a plausible PCI.
    return {
        "tech": "LTE", "mcc": 311, "mnc": 480, "cell_id": 100200300,
        "earfcn": 5230, "pci": 200, "rssi": -85, "hits": 12,
    }


def _att_gsm():
    # MCC 310 / MNC 410 = AT&T (legacy GSM band).
    return {
        "tech": "GSM", "mcc": 310, "mnc": 410, "cell_id": 4242,
        "lac": 100, "arfcn": 237, "rssi": -75, "hits": 8,
    }


class HeuristicTests(unittest.TestCase):
    def test_known_carrier_no_baseline_scores_low(self):
        # No baseline + a well-known US MCC/MNC + GSM-only environment
        # should not light up the alert threshold.
        risk, reasons = score_cell(_att_gsm(), baseline=None, all_cells=[_att_gsm()])
        self.assertEqual(risk, 0)
        self.assertEqual(reasons, [])

    def test_unknown_mcc_fires_non_us(self):
        # MCC 001 is the test PLMN used by OpenBTS / Yate by default —
        # this is the dead-giveaway rogue signature.
        cell = _verizon_lte()
        cell["mcc"] = 1
        risk, reasons = score_cell(cell, baseline=None, all_cells=[cell])
        self.assertIn("non_us_mcc:1", reasons)
        self.assertGreaterEqual(risk, 40)

    def test_unknown_mnc_for_known_mcc(self):
        cell = _verizon_lte()
        cell["mnc"] = 999  # not a known US MNC
        _, reasons = score_cell(cell, baseline=None, all_cells=[cell])
        self.assertTrue(any(r.startswith("unknown_us_mnc:") for r in reasons))

    def test_2g_in_lte_coverage_fires_downgrade(self):
        # GSM cell visible while an LTE cell is also visible = classic
        # forced-downgrade signature.
        gsm = _att_gsm()
        lte = _verizon_lte()
        _, reasons = score_cell(gsm, baseline=None, all_cells=[gsm, lte])
        self.assertIn("2g_in_lte_coverage", reasons)

    def test_2g_alone_does_not_fire_downgrade(self):
        # Rural areas where only 2G coverage exists should NOT trip the
        # downgrade heuristic.
        gsm = _att_gsm()
        _, reasons = score_cell(gsm, baseline=None, all_cells=[gsm])
        self.assertNotIn("2g_in_lte_coverage", reasons)

    def test_baseline_hit_suppresses_unknown(self):
        cell = _verizon_lte()
        baseline = {(311, 480, 100200300, "LTE")}
        risk, reasons = score_cell(cell, baseline=baseline, all_cells=[cell])
        self.assertEqual(risk, 0)
        self.assertNotIn("not_in_opencellid", reasons)

    def test_baseline_miss_fires_unknown(self):
        cell = _verizon_lte()
        baseline = set()  # empty baseline = nothing matches
        risk, reasons = score_cell(cell, baseline=baseline, all_cells=[cell])
        self.assertIn("not_in_opencellid", reasons)
        self.assertGreaterEqual(risk, 50)

    def test_textbook_stingray_combination_crosses_threshold(self):
        # Strong signal (-50 dBm) + few hits + not in baseline + 2G in
        # LTE area + unknown MNC = all five heuristics fire.
        rogue = {
            "tech": "GSM", "mcc": 310, "mnc": 999, "cell_id": 9001,
            "rssi": -45, "hits": 2,
        }
        lte = _verizon_lte()
        risk, reasons = score_cell(rogue, baseline=set(), all_cells=[rogue, lte])
        # Should max out near 100. Definitely above the default 70.
        self.assertGreaterEqual(risk, 70)
        self.assertIn("not_in_opencellid", reasons)
        self.assertIn("strong_brief_unknown", reasons)
        self.assertIn("2g_in_lte_coverage", reasons)

    def test_risk_clamps_at_100(self):
        # Stack every heuristic, ensure the cap holds.
        rogue = {
            "tech": "GSM", "mcc": 1, "mnc": 999, "cell_id": 1,
            "rssi": -20, "hits": 1,
        }
        lte = _verizon_lte()
        risk, _ = score_cell(rogue, baseline=set(), all_cells=[rogue, lte])
        self.assertLessEqual(risk, 100)


class BaselineLoaderTests(unittest.TestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(load_opencellid_baseline("/nonexistent/path.csv"))
        self.assertIsNone(load_opencellid_baseline(""))
        self.assertIsNone(load_opencellid_baseline(None))

    def test_loads_lte_and_gsm_rows(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            # OCID format: radio,mcc,net,area,cell,unit,lon,lat,range,samples,...
            f.write("LTE,311,480,1,100200300,0,-122.4,37.7,1000,500,1,0,0,-85\n")
            f.write("GSM,310,410,100,4242,0,-122.4,37.7,1000,500,1,0,0,-75\n")
            f.write("UMTS,310,260,200,9999,0,-122.4,37.7,1000,500,1,0,0,-90\n")
            path = f.name
        try:
            baseline = load_opencellid_baseline(path)
            self.assertIn((311, 480, 100200300, "LTE"), baseline)
            self.assertIn((310, 410, 4242, "GSM"), baseline)
            # UMTS collapses to GSM in our tech taxonomy.
            self.assertIn((310, 260, 9999, "GSM"), baseline)
        finally:
            os.unlink(path)

    def test_filters_non_us_mcc_by_default(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write("LTE,311,480,1,100,0,0,0,0,0,0,0,0,0\n")          # US
            f.write("LTE,234,15,1,200,0,0,0,0,0,0,0,0,0\n")           # UK
            f.write("LTE,1,1,1,300,0,0,0,0,0,0,0,0,0\n")              # test PLMN
            path = f.name
        try:
            baseline = load_opencellid_baseline(path)
            self.assertIn((311, 480, 100, "LTE"), baseline)
            self.assertNotIn((234, 15, 200, "LTE"), baseline)
            self.assertNotIn((1, 1, 300, "LTE"), baseline)
        finally:
            os.unlink(path)

    def test_mcc_filter_override(self):
        # Operator can pass a custom filter (e.g. to operate outside the US).
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write("LTE,234,15,1,200,0,0,0,0,0,0,0,0,0\n")
            path = f.name
        try:
            baseline = load_opencellid_baseline(path, mcc_filter={234})
            self.assertIn((234, 15, 200, "LTE"), baseline)
        finally:
            os.unlink(path)

    def test_malformed_rows_skipped(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write("LTE,311,480,1,100,0\n")                # valid
            f.write("LTE,not_a_number,foo,bar,baz\n")      # malformed
            f.write("\n")                                   # empty
            f.write("LTE\n")                                # truncated
            path = f.name
        try:
            baseline = load_opencellid_baseline(path)
            self.assertEqual(baseline, {(311, 480, 100, "LTE")})
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
