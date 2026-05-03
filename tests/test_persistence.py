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
    p = Persistence(_FakeScanner(), _FakeScanner(), db_path=db_path)
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
