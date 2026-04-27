"""SQLite-backed persistence + new-phone alerting for Doperscope.

Snapshots the live scanners on a background thread and upserts the latest
state into `doperscope.db` so a SCIF sweep can be reviewed offline.

Also detects the appearance of a phone fingerprint that has never been
seen before in this session and exposes it via `pop_new_phone_alerts()`
for the UI to flash + chime on.
"""

import json
import os
import queue
import sqlite3
import threading
import time

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "doperscope.db")
SNAPSHOT_INTERVAL_S = 5.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS wifi_aps (
    bssid       TEXT PRIMARY KEY,
    ssid        TEXT,
    channel     INTEGER,
    band        TEXT,
    vendor      TEXT,
    hidden      INTEGER,
    is_phone    INTEGER,
    rssi_last   INTEGER,
    rssi_max    INTEGER,
    first_seen  REAL,
    last_seen   REAL,
    hits        INTEGER
);
CREATE INDEX IF NOT EXISTS ix_wifi_aps_last_seen ON wifi_aps(last_seen);
CREATE INDEX IF NOT EXISTS ix_wifi_aps_phone     ON wifi_aps(is_phone);

CREATE TABLE IF NOT EXISTS wifi_probes (
    fingerprint TEXT PRIMARY KEY,
    mac_last    TEXT,
    macs        TEXT,
    ssids_seen  TEXT,
    os          TEXT,
    dev_type    TEXT,
    wifi_gen    TEXT,
    vendor      TEXT,
    is_phone    INTEGER,
    rssi_last   INTEGER,
    rssi_max    INTEGER,
    first_seen  REAL,
    last_seen   REAL,
    hits        INTEGER
);
CREATE INDEX IF NOT EXISTS ix_wifi_probes_last_seen ON wifi_probes(last_seen);
CREATE INDEX IF NOT EXISTS ix_wifi_probes_phone     ON wifi_probes(is_phone);

CREATE TABLE IF NOT EXISTS ble_devices (
    mac         TEXT PRIMARY KEY,
    name        TEXT,
    vendor      TEXT,
    dev_type    TEXT,
    fingerprint TEXT,
    rssi_last   INTEGER,
    rssi_max    INTEGER,
    first_seen  REAL,
    last_seen   REAL
);
CREATE INDEX IF NOT EXISTS ix_ble_last_seen ON ble_devices(last_seen);

-- One row every time a phone fingerprint shows up that the session hasn't
-- seen before. This is the SCIF "smoking gun" log.
CREATE TABLE IF NOT EXISTS phone_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    kind         TEXT NOT NULL,    -- 'wifi_probe' | 'wifi_ap' | 'ble'
    fingerprint  TEXT,
    mac          TEXT,
    ssid         TEXT,
    os           TEXT,
    dev_type     TEXT,
    rssi         INTEGER,
    detail       TEXT              -- JSON for forensic replay
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON phone_alerts(ts);
"""


class Persistence:
    def __init__(self, wifi_scanner, ble_scanner, db_path=DEFAULT_DB_PATH):
        self._wifi = wifi_scanner
        self._ble  = ble_scanner
        self._db_path = db_path
        self._running = False
        self._thread  = None

        self._seen_phone_fps = set()    # in-session dedup for alerts
        self._alert_queue    = queue.Queue()

    def start(self):
        # Open the DB on the background thread to keep sqlite3's
        # check_same_thread happy.
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def pop_new_phone_alerts(self):
        """Return all pending alerts and clear the queue. UI calls this each frame."""
        alerts = []
        try:
            while True:
                alerts.append(self._alert_queue.get_nowait())
        except queue.Empty:
            pass
        return alerts

    def _loop(self):
        conn = sqlite3.connect(self._db_path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
            while self._running:
                try:
                    self._snapshot(conn)
                except Exception as e:
                    # Never let a logging error kill the scanner UI.
                    print(f"[persistence] snapshot error: {e}")
                time.sleep(SNAPSHOT_INTERVAL_S)
        finally:
            conn.close()

    def _snapshot(self, conn):
        now = time.time()
        cur = conn.cursor()

        for ap in self._wifi.get_devices():
            cur.execute(
                """
                INSERT INTO wifi_aps (bssid, ssid, channel, band, vendor, hidden, is_phone,
                                      rssi_last, rssi_max, first_seen, last_seen, hits)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid      = excluded.ssid,
                    channel   = excluded.channel,
                    band      = excluded.band,
                    vendor    = excluded.vendor,
                    hidden    = excluded.hidden,
                    is_phone  = excluded.is_phone,
                    rssi_last = excluded.rssi_last,
                    rssi_max  = MAX(rssi_max, excluded.rssi_last),
                    last_seen = excluded.last_seen,
                    hits      = hits + 1
                """,
                (
                    ap["bssid"], ap.get("ssid"), ap.get("channel"), ap.get("band"),
                    ap.get("vendor"), int(ap.get("hidden", False)),
                    int(ap.get("is_phone", False)),
                    ap["rssi"], ap["rssi"], now, ap["last_seen"],
                ),
            )
            if ap.get("is_phone"):
                self._maybe_alert(conn, "wifi_ap", ap.get("bssid"), ap.get("bssid"),
                                  ap.get("ssid"), "Hotspot", "WiFi AP",
                                  ap["rssi"], ap)

        for pr in self._wifi.get_probes():
            cur.execute(
                """
                INSERT INTO wifi_probes (fingerprint, mac_last, macs, ssids_seen,
                                         os, dev_type, wifi_gen, vendor, is_phone,
                                         rssi_last, rssi_max, first_seen, last_seen, hits)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    mac_last   = excluded.mac_last,
                    macs       = excluded.macs,
                    ssids_seen = excluded.ssids_seen,
                    rssi_last  = excluded.rssi_last,
                    rssi_max   = MAX(rssi_max, excluded.rssi_last),
                    last_seen  = excluded.last_seen,
                    hits       = excluded.hits
                """,
                (
                    pr["fingerprint"], pr["mac"],
                    json.dumps(pr.get("macs", [])),
                    json.dumps(pr.get("ssids_seen", [])),
                    pr.get("os"), pr.get("dev_type"), pr.get("wifi_gen"),
                    pr.get("vendor"), int(pr.get("is_phone", False)),
                    pr["rssi"], pr["rssi"],
                    pr.get("first_seen", now), pr["last_seen"], pr.get("hits", 1),
                ),
            )
            if pr.get("is_phone"):
                self._maybe_alert(conn, "wifi_probe", pr["fingerprint"], pr["mac"],
                                  pr.get("ssid"), pr.get("os"), pr.get("dev_type"),
                                  pr["rssi"], pr)

        for dev in self._ble.get_devices():
            cur.execute(
                """
                INSERT INTO ble_devices (mac, name, vendor, dev_type, fingerprint,
                                         rssi_last, rssi_max, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    name        = excluded.name,
                    vendor      = excluded.vendor,
                    dev_type    = excluded.dev_type,
                    fingerprint = excluded.fingerprint,
                    rssi_last   = excluded.rssi_last,
                    rssi_max    = MAX(rssi_max, excluded.rssi_last),
                    last_seen   = excluded.last_seen
                """,
                (
                    dev["mac"], dev.get("name"), dev.get("vendor"),
                    dev.get("type"), dev.get("fingerprint"),
                    dev["rssi"], dev["rssi"], now, dev["last_seen"],
                ),
            )

        conn.commit()

    def _maybe_alert(self, conn, kind, fp, mac, ssid, os_, dev_type, rssi, raw):
        if not fp or fp in self._seen_phone_fps:
            return
        self._seen_phone_fps.add(fp)
        alert = {
            "ts": time.time(),
            "kind": kind,
            "fingerprint": fp,
            "mac": mac,
            "ssid": ssid,
            "os": os_,
            "dev_type": dev_type,
            "rssi": rssi,
        }
        self._alert_queue.put(alert)

        # Persist the alert on the same connection as the snapshot upserts so
        # we don't fight ourselves for the SQLite write lock.
        safe = {k: (sorted(v) if isinstance(v, set) else v) for k, v in raw.items()}
        conn.execute(
            """INSERT INTO phone_alerts (ts, kind, fingerprint, mac, ssid, os,
                                         dev_type, rssi, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["ts"], kind, fp, mac, ssid, os_, dev_type, rssi,
             json.dumps(safe, default=str)),
        )
