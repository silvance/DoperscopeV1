"""Persistence layer tests — schema migration, retention, sweep
lifecycle, alert dedup, CSV export. No hardware deps required."""

import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import unittest

# Make the repo importable when running tests/ directly via unittest.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class _FakeScanner:
    """Minimal scanner stub matching the surface persistence calls into."""
    def __init__(self):
        self.error_count = 0
        self.last_packet_ts = 0.0
        self._devices = []
        self._probes = []

    def get_devices(self):
        return list(self._devices)

    def get_probes(self, phones_only=False):
        return list(self._probes)


class _FakeSDR:
    """Minimal SDR scanner stub for stage-3 cell-alert tests."""
    def __init__(self):
        self.error_count = 0
        self.last_packet_ts = 0.0
        self._cells = []

    def get_cells(self):
        return list(self._cells)


def _make_persistence(env=None):
    """Spin up a Persistence pointed at a fresh tempdir, return
    (Persistence instance, tempdir, db_path). Caller must clean up."""
    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "doperscope.db")
    os.environ["DOPESCOPE_DATA_DIR"] = tmpdir
    os.environ["DOPESCOPE_DB_PATH"] = db_path
    os.environ["DOPESCOPE_EXPORT_DIR"] = os.path.join(tmpdir, "exports")
    if env:
        os.environ.update(env)
    # Force re-import so module-level constants pick up the env.
    for m in list(sys.modules):
        if m.startswith("persistence"):
            del sys.modules[m]
    from persistence import Persistence
    p = Persistence(_FakeScanner(), _FakeScanner(), _FakeSDR(), db_path=db_path)
    return p, tmpdir, db_path


class PersistenceSchemaTests(unittest.TestCase):
    def test_db_and_dir_have_private_perms(self):
        p, tmpdir, db_path = _make_persistence()
        try:
            p.start()
            time.sleep(0.5)
            p.stop()
            self.assertTrue(os.path.isfile(db_path))
            self.assertEqual(stat.S_IMODE(os.stat(db_path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(tmpdir).st_mode), 0o700)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_wal_journal_mode_persists_in_header(self):
        p, tmpdir, db_path = _make_persistence()
        try:
            p.start()
            time.sleep(0.5)
            p.stop()
            conn = sqlite3.connect(db_path)
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            self.assertEqual(mode, "wal")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PersistenceRetentionTests(unittest.TestCase):
    def _seed(self, db_path, schema, ages_days):
        """Insert a wifi_aps row per (label, age_days) tuple."""
        conn = sqlite3.connect(db_path)
        conn.executescript(schema)
        for label, age in ages_days:
            ts = time.time() - age * 86400
            conn.execute(
                "INSERT INTO wifi_aps (bssid, ssid, channel, band, vendor, "
                "hidden, is_phone, rssi_last, rssi_max, first_seen, last_seen, hits) "
                "VALUES (?, ?, 6, '2.4G', 'X', 0, 0, -60, -55, ?, ?, 1)",
                (f"aa:bb:cc:00:00:{ord(label[0])%100:02x}", label, ts, ts),
            )
        conn.commit()
        conn.close()

    def test_default_30_day_retention_prunes_old_keeps_new(self):
        from persistence import SCHEMA  # ok to import early; constants don't depend on env yet
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "30"})
        try:
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            self._seed(db_path, SCHEMA, [("old", 60), ("recent", 1)])
            p.start()
            time.sleep(0.5)
            p.stop()

            conn = sqlite3.connect(db_path)
            ssids = sorted(r[0] for r in conn.execute("SELECT ssid FROM wifi_aps"))
            conn.close()
            self.assertEqual(ssids, ["recent"], f"expected only 'recent' to survive, got {ssids}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_retention_zero_disables_pruning(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            self._seed(db_path, SCHEMA, [("forensic_old", 365)])
            p.start()
            time.sleep(0.5)
            p.stop()

            conn = sqlite3.connect(db_path)
            ssids = [r[0] for r in conn.execute("SELECT ssid FROM wifi_aps")]
            conn.close()
            self.assertEqual(ssids, ["forensic_old"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PersistenceSweepTests(unittest.TestCase):
    def test_sweep_lifecycle_with_observations(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            # Seed a probe + AP that the snapshot loop will capture.
            now = time.time()
            p._wifi._devices = [{
                "bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Joe's iPhone", "channel": 6,
                "band": "2.4G", "vendor": "Apple", "hidden": False, "is_phone": True,
                "rssi": -55, "last_seen": now,
            }]
            p._wifi._probes = [{
                "fingerprint": "ie:fp1", "mac": "a1:b2:c3:d4:e5:f6",
                "macs": ["a1:b2:c3:d4:e5:f6"], "ssid": "CompanyWiFi",
                "ssids_seen": ["CompanyWiFi"], "os": "iPhone",
                "dev_type": "iPhone (iOS 14+)", "wifi_gen": "WiFi 6",
                "vendor": "Unknown", "is_phone": True, "is_watchlisted": True,
                "matched_ssids": ["CompanyWiFi"],
                "rssi": -60, "first_seen": now, "last_seen": now, "hits": 3,
            }]
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA)
            conn.commit()

            sid = p.start_sweep(label="unit-test")
            self.assertIsNotNone(sid)
            self.assertTrue(p.is_sweep_active())
            p._snapshot(conn)
            p._snapshot(conn)  # repeat — observations should dedup, hits should grow
            p.end_sweep()

            sweep = p.get_sweep(sid)
            self.assertIsNotNone(sweep)
            self.assertEqual(sweep["devices_seen"], 2)   # 1 ap + 1 probe
            self.assertEqual(sweep["phones_seen"], 2)    # both flagged is_phone
            self.assertEqual(sweep["watch_hits"], 1)     # only the probe hits watchlist

            obs = p.get_sweep_observations(sid)
            self.assertEqual(len(obs), 2)
            # Watchlist hit should be sorted first.
            self.assertTrue(obs[0]["is_watch"])
            conn.close()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_csv_export_lands_in_export_dir_with_private_perms(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA)
            conn.commit()
            sid = p.start_sweep(label="export-test")
            p._snapshot(conn)
            p.end_sweep()

            csv_path = p.export_sweep_csv(sid)
            self.assertIsNotNone(csv_path)
            self.assertTrue(csv_path.startswith(os.environ["DOPESCOPE_EXPORT_DIR"]))
            self.assertTrue(os.path.isfile(csv_path))
            self.assertEqual(stat.S_IMODE(os.stat(csv_path).st_mode), 0o600)
            self.assertIsNone(p.export_sweep_csv(99999), "missing sweep id should return None")
            conn.close()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_csv_export_writes_truncation_warning_when_capped(self):
        """A sweep with more observations than EXPORT_MAX_ROWS should
        produce a CSV whose header carries a "# WARNING: truncated"
        marker so downstream readers don't silently miss the tail."""
        from persistence import SCHEMA
        # Cap at 5 so the test stays fast while still exercising the
        # overflow path.
        p, tmpdir, db_path = _make_persistence({
            "DOPESCOPE_RETENTION_DAYS": "0",
            "DOPESCOPE_EXPORT_MAX_ROWS": "5",
        })
        try:
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA)
            conn.commit()
            sid = p.start_sweep()
            now = time.time()
            cur = conn.cursor()
            for i in range(20):
                cur.execute(
                    "INSERT INTO sweep_observations (sweep_id, kind, key, label, "
                    "os, dev_type, is_phone, is_watch, rssi_max, rssi_last, "
                    "first_seen, last_seen, hits) "
                    "VALUES (?, 'wifi_probe', ?, ?, '', '', 0, 0, -60, -60, ?, ?, 1)",
                    (sid, f"fp{i}", f"label{i}", now, now),
                )
            conn.commit()
            p.end_sweep()
            csv_path = p.export_sweep_csv(sid)
            self.assertIsNotNone(csv_path)
            with open(csv_path) as f:
                text = f.read()
            self.assertIn("# WARNING: truncated", text)
            data_rows = [l for l in text.splitlines() if l.startswith("wifi_probe,")]
            self.assertEqual(len(data_rows), 5,
                f"expected exactly 5 data rows, got {len(data_rows)}")
            conn.close()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PersistenceBLEAlertTests(unittest.TestCase):
    """The MEDIUM-batch added a BLE alert path so phone-class BLE devices
    (iPhone / AirPods / Apple Watch / etc.) escalate to the same red
    banner Wi-Fi probes do. Confirm a phone-class device fires an alert
    and a non-phone-class one stays quiet."""

    def test_phone_class_ble_device_fires_alert(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            now = time.time()
            p._ble._devices = [
                # phone-class — should alert
                {"name": "Joe's iPhone", "mac": "11:22:33:44:55:66",
                 "macs": ["11:22:33:44:55:66"], "rssi": -55, "vendor": "Apple",
                 "type": "iPhone", "fingerprint": "mfr:4c:01..::svc:",
                 "last_seen": now},
                # generic BLE — should NOT alert
                {"name": "Light Bulb", "mac": "aa:bb:cc:dd:ee:ff",
                 "macs": ["aa:bb:cc:dd:ee:ff"], "rssi": -70, "vendor": "Unknown",
                 "type": "BLE Device", "fingerprint": "mfr:ff:beef::svc:",
                 "last_seen": now},
            ]
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA); conn.commit()
            p._snapshot(conn)
            conn.close()

            alerts = p.get_recent_alerts()
            ble_alerts = [a for a in alerts if a["kind"] == "ble"]
            self.assertEqual(len(ble_alerts), 1, "expected exactly 1 BLE alert (the iPhone)")
            self.assertEqual(ble_alerts[0]["dev_type"], "iPhone")
            self.assertEqual(ble_alerts[0]["mac"], "11:22:33:44:55:66")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PersistenceCellAlertTests(unittest.TestCase):
    """Stage 3 added cell-alert routing — high-risk cells from the SDR
    scanner should write a cell_alerts row, dedupe per session, and show
    up in the unified Log tab feed."""

    def test_high_risk_cell_fires_alert_once(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            now = time.time()
            rogue = {
                "tech": "GSM", "mcc": 1, "mnc": 999, "cell_id": 42,
                "rssi": -45, "rssi_max": -45, "hits": 1,
                "risk": 95, "reasons": ["non_us_mcc:1", "strong_brief_unknown"],
                "first_seen": now, "last_seen": now,
            }
            p._sdr._cells = [rogue]
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA); conn.commit()
            # First snapshot → alert fires.
            p._snapshot(conn)
            # Second snapshot with the same cell → dedup, no new alert.
            p._snapshot(conn)
            conn.close()

            alerts = p.get_recent_alerts()
            cell_alerts = [a for a in alerts if a["kind"] == "cell"]
            self.assertEqual(len(cell_alerts), 1,
                             "expected exactly 1 cell alert (deduped on second snapshot)")
            self.assertIn("cell:GSM-1-999-42", cell_alerts[0]["fingerprint"])
            # reasons land in the ssid field for Log-tab rendering
            self.assertIn("non_us_mcc:1", cell_alerts[0]["ssid"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_low_risk_cell_stays_quiet(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            now = time.time()
            # Verizon LTE, no flags raised by the heuristics.
            benign = {
                "tech": "LTE", "mcc": 311, "mnc": 480, "cell_id": 100200300,
                "rssi": -85, "rssi_max": -85, "hits": 12,
                "risk": 0, "reasons": [],
                "first_seen": now, "last_seen": now,
            }
            p._sdr._cells = [benign]
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA); conn.commit()
            p._snapshot(conn)
            conn.close()

            cell_alerts = [a for a in p.get_recent_alerts() if a["kind"] == "cell"]
            self.assertEqual(cell_alerts, [], "low-risk cell should not alert")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PersistenceFaultIsolationTests(unittest.TestCase):
    """The MEDIUM-batch wrapped each device upsert in its own try/except so
    one malformed row doesn't roll back the whole snapshot. Confirm a
    deliberately-broken probe doesn't take down a sibling AP."""

    def test_one_bad_probe_doesnt_lose_the_good_ap(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence({"DOPESCOPE_RETENTION_DAYS": "0"})
        try:
            now = time.time()
            p._wifi._devices = [{
                "bssid": "aa:bb:cc:dd:ee:ff", "ssid": "GoodAP", "channel": 6,
                "band": "2.4G", "vendor": "X", "hidden": False, "is_phone": False,
                "rssi": -55, "last_seen": now,
            }]
            # Probe missing required keys (no rssi, no last_seen) — will
            # raise inside the upsert and should be skipped silently.
            p._wifi._probes = [{
                "fingerprint": "ie:bad",
                # missing mac, missing rssi, missing last_seen
            }]
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA); conn.commit()
            p._snapshot(conn)

            aps = conn.execute("SELECT ssid FROM wifi_aps").fetchall()
            probes = conn.execute("SELECT fingerprint FROM wifi_probes").fetchall()
            conn.close()
            self.assertEqual(aps, [("GoodAP",)], "good AP should still be persisted")
            self.assertEqual(probes, [], "bad probe should have been skipped")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PersistenceCacheTests(unittest.TestCase):
    def test_repeat_read_hits_cache(self):
        p, tmpdir, db_path = _make_persistence()
        try:
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            from persistence import SCHEMA
            conn.executescript(SCHEMA); conn.commit(); conn.close()

            t0 = time.time(); p.get_recent_alerts(); t1 = time.time()
            t2 = time.time(); p.get_recent_alerts(); t3 = time.time()
            uncached = t1 - t0
            cached   = t3 - t2
            # Cached should be at least 5x faster. The opening sqlite
            # connection dwarfs the dict lookup.
            self.assertLess(cached * 5, uncached,
                            f"cache not effective: uncached={uncached*1000:.2f}ms cached={cached*1000:.2f}ms")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_start_sweep_invalidates_cache(self):
        from persistence import SCHEMA
        p, tmpdir, db_path = _make_persistence()
        try:
            os.makedirs(tmpdir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(SCHEMA); conn.commit(); conn.close()

            self.assertEqual(p.list_sweeps(), [])
            p.start_sweep(label="cache-flush")
            sweeps = p.list_sweeps()
            self.assertEqual(len(sweeps), 1)
            self.assertTrue(sweeps[0]["active"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
