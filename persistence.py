"""SQLite-backed persistence + new-phone alerting for Doperscope.

Snapshots the live scanners on a background thread and upserts the latest
state into `doperscope.db` so a SCIF sweep can be reviewed offline.

Also detects the appearance of a phone fingerprint that has never been
seen before in this session and exposes it via `pop_new_phone_alerts()`
for the UI to flash + chime on.
"""

import csv
import json
import os
import queue
import sqlite3
import threading
import time

# DB lives in the operator's home directory by default — the previous
# default put it next to source code, which is a SCIF-hostile place
# for sensitive sweep data. Override with DOPESCOPE_DB_PATH.
DEFAULT_DATA_DIR = os.environ.get(
    "DOPESCOPE_DATA_DIR",
    os.path.expanduser("~/.doperscope"),
)
DEFAULT_DB_PATH = os.environ.get(
    "DOPESCOPE_DB_PATH",
    os.path.join(DEFAULT_DATA_DIR, "doperscope.db"),
)
DEFAULT_EXPORT_DIR = os.environ.get(
    "DOPESCOPE_EXPORT_DIR",
    os.path.join(DEFAULT_DATA_DIR, "exports"),
)
SNAPSHOT_INTERVAL_S = 5.0

# Drop rows older than this on every startup. 0 disables retention
# (keep forever — useful for forensic deployments). Default 30 days
# is plenty for SCIF post-sweep review without growing a 1GB DB on
# the SD card over a year of operation.
RETENTION_DAYS = float(os.environ.get("DOPESCOPE_RETENTION_DAYS", "30"))

# Default busy timeout for every sqlite3 connection in this module.
# Without this, two concurrent writers (snapshot thread + UI thread
# calling start_sweep / end_sweep / export) can race and the loser
# raises "database is locked" instantly. 5s is well above the longest
# transaction we run, so locks resolve invisibly under contention.
SQLITE_BUSY_TIMEOUT_MS = 5000


def _connect(db_path):
    """sqlite3.connect with our standard busy_timeout applied. Use this
    everywhere instead of bare sqlite3.connect so writers never silently
    drop transactions on lock contention."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    except Exception:
        pass
    return conn


def _ensure_private_dir(path):
    """mkdir -p with mode 0700 — sweep data and watchlists are sensitive."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _ensure_private_file(path):
    """chmod the file 0600 if it exists. No-op on fresh creates; called
    after sqlite3.connect so the file definitely exists."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

# An in-memory BLE entry with this fingerprint string is "trivial" — no
# manufacturer data and no services (the new BLE fingerprint format
# omits name on purpose since users rename devices). The scanner keeps
# these per-MAC; persistence does the same to keep them from collapsing.
_TRIVIAL_BLE_FP = "mfr:::svc:"

def _ble_storage_key(fingerprint, mac):
    if not fingerprint or fingerprint == _TRIVIAL_BLE_FP:
        return f"mac:{mac}"
    return fingerprint

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
    -- key = fingerprint when one carries real signal; mac:<addr> for
    -- adverts with no name/mfr/services (matches the in-memory scanner).
    key         TEXT PRIMARY KEY,
    fingerprint TEXT,
    mac_last    TEXT,
    macs        TEXT,           -- JSON list of all observed MACs
    name        TEXT,
    vendor      TEXT,
    dev_type    TEXT,
    rssi_last   INTEGER,
    rssi_max    INTEGER,
    first_seen  REAL,
    last_seen   REAL,
    hits        INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ble_last_seen ON ble_devices(last_seen);

-- One row every time a phone fingerprint shows up that the session hasn't
-- seen before. This is the SCIF "smoking gun" log.
CREATE TABLE IF NOT EXISTS phone_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    kind         TEXT NOT NULL,    -- 'wifi_probe' | 'wifi_ap' | 'ble' | 'watchlist'
    fingerprint  TEXT,
    mac          TEXT,
    ssid         TEXT,
    os           TEXT,
    dev_type     TEXT,
    rssi         INTEGER,
    detail       TEXT              -- JSON for forensic replay
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON phone_alerts(ts);

-- A "sweep" is an operator-bounded capture window. While a sweep is
-- active the snapshot loop logs every observation into
-- sweep_observations so the operator can review just the devices
-- present during the walk-through, separated from background noise.
CREATE TABLE IF NOT EXISTS sweeps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts     REAL NOT NULL,
    end_ts       REAL,
    label        TEXT,
    devices_seen INTEGER DEFAULT 0,
    phones_seen  INTEGER DEFAULT 0,
    watch_hits   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_sweeps_start ON sweeps(start_ts DESC);

CREATE TABLE IF NOT EXISTS sweep_observations (
    sweep_id   INTEGER NOT NULL,
    kind       TEXT NOT NULL,    -- 'wifi_ap' | 'wifi_probe' | 'ble'
    key        TEXT NOT NULL,    -- bssid for AP, fingerprint otherwise
    label      TEXT,             -- ssid / name / dev_type for human display
    os         TEXT,
    dev_type   TEXT,
    is_phone   INTEGER,
    is_watch   INTEGER,
    rssi_max   INTEGER,
    rssi_last  INTEGER,
    first_seen REAL,
    last_seen  REAL,
    hits       INTEGER DEFAULT 1,
    PRIMARY KEY (sweep_id, kind, key)
);
CREATE INDEX IF NOT EXISTS ix_sweep_obs_sweep ON sweep_observations(sweep_id);
"""


class Persistence:
    def __init__(self, wifi_scanner, ble_scanner, db_path=DEFAULT_DB_PATH):
        self._wifi = wifi_scanner
        self._ble  = ble_scanner
        self._db_path = db_path
        self._running = False
        self._thread  = None

        # In-session dedup for alerts. Separate sets so a fingerprint can
        # alert once as a phone AND once as a watchlist hit.
        self._seen_phone_fps     = set()
        self._seen_watchlist_fps = set()
        self._alert_queue    = queue.Queue()

        # Active sweep state. Protected by _sweep_lock so the UI thread
        # can toggle without racing the snapshot thread.
        self._sweep_lock        = threading.Lock()
        self._active_sweep      = None     # int sweep_id or None
        self._active_sweep_ts   = 0.0      # start_ts for the active sweep

        # Tiny TTL cache for read-heavy UI queries (Log tab calls these
        # every render frame at ~20fps; without caching we'd open and
        # close ~20 sqlite connections per second per query).
        self._read_cache       = {}      # name -> (expires_at, value)
        self._read_cache_lock  = threading.Lock()
        self._read_cache_ttl_s = 1.0

    def start(self):
        # Open the DB on the background thread to keep sqlite3's
        # check_same_thread happy.
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        # Finalize any sweep that was still active so it gets a real
        # end_ts / aggregate counts instead of looking crashed.
        if self.is_sweep_active():
            self.end_sweep()
        self._running = False
        # Wait for the snapshot thread to wake from its sleep and exit
        # cleanly so the last in-flight transaction commits and the conn
        # closes; otherwise the daemon thread can be killed mid-sleep on
        # process exit and lose up to SNAPSHOT_INTERVAL_S of upserts.
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=SNAPSHOT_INTERVAL_S + 1.0)

    def pop_new_phone_alerts(self):
        """Return all pending alerts and clear the queue. UI calls this each frame."""
        alerts = []
        try:
            while True:
                alerts.append(self._alert_queue.get_nowait())
        except queue.Empty:
            pass
        return alerts

    def is_sweep_active(self):
        with self._sweep_lock:
            return self._active_sweep is not None

    def active_sweep_id(self):
        with self._sweep_lock:
            return self._active_sweep

    def active_sweep_started_at(self):
        with self._sweep_lock:
            return self._active_sweep_ts

    def start_sweep(self, label=None):
        """Open a new sweep. Returns the sweep id. Idempotent — if a
        sweep is already active the existing id is returned."""
        with self._sweep_lock:
            if self._active_sweep is not None:
                return self._active_sweep
        start_ts = time.time()
        try:
            conn = _connect(self._db_path)
            try:
                cur = conn.execute(
                    "INSERT INTO sweeps (start_ts, label) VALUES (?, ?)",
                    (start_ts, label),
                )
                conn.commit()
                sid = cur.lastrowid
            finally:
                conn.close()
        except Exception as e:
            print(f"[persistence] start_sweep error: {e}")
            return None
        with self._sweep_lock:
            self._active_sweep    = sid
            self._active_sweep_ts = start_ts
        self.invalidate_read_cache()
        return sid

    def end_sweep(self):
        """Close the active sweep and roll up its aggregate counts.
        No-op if no sweep is active."""
        with self._sweep_lock:
            sid = self._active_sweep
            self._active_sweep    = None
            self._active_sweep_ts = 0.0
        self.invalidate_read_cache()
        if sid is None:
            return
        try:
            conn = _connect(self._db_path)
            try:
                row = conn.execute(
                    """SELECT COUNT(*),
                              SUM(CASE WHEN is_phone THEN 1 ELSE 0 END),
                              SUM(CASE WHEN is_watch THEN 1 ELSE 0 END)
                         FROM sweep_observations WHERE sweep_id = ?""",
                    (sid,),
                ).fetchone()
                devices, phones, watch = row[0] or 0, row[1] or 0, row[2] or 0
                conn.execute(
                    """UPDATE sweeps SET end_ts = ?, devices_seen = ?,
                                          phones_seen = ?, watch_hits = ?
                       WHERE id = ?""",
                    (time.time(), devices, phones, watch, sid),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            print(f"[persistence] end_sweep error: {e}")

    def _cache_get(self, key):
        with self._read_cache_lock:
            entry = self._read_cache.get(key)
            if entry and entry[0] > time.time():
                return entry[1]
        return None

    def _cache_put(self, key, value):
        with self._read_cache_lock:
            self._read_cache[key] = (time.time() + self._read_cache_ttl_s, value)

    def invalidate_read_cache(self):
        """Drop all cached read results — call after start/end_sweep so the
        UI sees the new state immediately instead of waiting up to 1s."""
        with self._read_cache_lock:
            self._read_cache.clear()

    def list_sweeps(self, limit=50):
        cache_key = ("list_sweeps", limit)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            conn = _connect(self._db_path)
            try:
                rows = conn.execute(
                    """SELECT id, start_ts, end_ts, label, devices_seen,
                              phones_seen, watch_hits
                         FROM sweeps
                         ORDER BY start_ts DESC
                         LIMIT ?""",
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return []
        active = self.active_sweep_id()
        result = [
            {
                "id": r[0], "start_ts": r[1], "end_ts": r[2], "label": r[3],
                "devices_seen": r[4] or 0, "phones_seen": r[5] or 0,
                "watch_hits": r[6] or 0,
                "active": (r[0] == active),
            }
            for r in rows
        ]
        self._cache_put(cache_key, result)
        return result

    def get_sweep_observations(self, sweep_id, limit=500):
        """Return every distinct device captured during a sweep, sorted
        watchlist-first, then phones, then by max RSSI seen during the
        capture window."""
        try:
            conn = _connect(self._db_path)
            try:
                rows = conn.execute(
                    """SELECT kind, key, label, os, dev_type, is_phone, is_watch,
                              rssi_max, rssi_last, first_seen, last_seen, hits
                         FROM sweep_observations
                         WHERE sweep_id = ?
                         ORDER BY is_watch DESC, is_phone DESC, rssi_max DESC
                         LIMIT ?""",
                    (sweep_id, limit),
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return []
        return [
            {
                "kind": r[0], "key": r[1], "label": r[2],
                "os": r[3], "dev_type": r[4],
                "is_phone": bool(r[5]), "is_watch": bool(r[6]),
                "rssi_max": r[7], "rssi_last": r[8],
                "first_seen": r[9], "last_seen": r[10],
                "hits": r[11] or 0,
            }
            for r in rows
        ]

    def export_sweep_csv(self, sweep_id, dest_dir=None):
        """Dump a sweep + every observation to a CSV under ~/.doperscope/exports
        (or DOPESCOPE_EXPORT_DIR) so the operator can pull the SD card and read
        it without sqlite3 on the receiving box. Returns the absolute path
        written, or None on failure (missing sweep, IO error)."""
        sweep = self.get_sweep(sweep_id)
        if not sweep:
            return None
        observations = self.get_sweep_observations(sweep_id, limit=10_000)
        if dest_dir is None:
            dest_dir = DEFAULT_EXPORT_DIR
        try:
            _ensure_private_dir(dest_dir)
        except Exception:
            return None
        # Use the sweep's start time in the filename so multiple exports
        # of different sweeps don't collide and the operator can sort.
        ts_part = time.strftime("%Y%m%d-%H%M%S", time.localtime(sweep["start_ts"]))
        path = os.path.join(dest_dir, f"sweep_{sweep_id:04d}_{ts_part}.csv")
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                # Header rows describe the sweep itself, then observations.
                w.writerow(["# sweep_id", sweep["id"]])
                w.writerow(["# start_ts", sweep["start_ts"]])
                w.writerow(["# end_ts", sweep["end_ts"]])
                w.writerow(["# label", sweep.get("label") or ""])
                w.writerow(["# devices_seen", sweep["devices_seen"]])
                w.writerow(["# phones_seen", sweep["phones_seen"]])
                w.writerow(["# watch_hits", sweep["watch_hits"]])
                w.writerow([])
                w.writerow([
                    "kind", "key", "label", "os", "dev_type",
                    "is_phone", "is_watch", "rssi_max", "rssi_last",
                    "first_seen", "last_seen", "hits",
                ])
                for o in observations:
                    w.writerow([
                        o["kind"], o["key"], o.get("label") or "",
                        o.get("os") or "", o.get("dev_type") or "",
                        int(o["is_phone"]), int(o["is_watch"]),
                        o["rssi_max"], o["rssi_last"],
                        o["first_seen"], o["last_seen"], o["hits"],
                    ])
        except Exception as e:
            print(f"[persistence] export_sweep_csv error: {e}")
            return None
        _ensure_private_file(path)
        return path

    def get_sweep(self, sweep_id):
        """Fetch a single sweep header row by id."""
        try:
            conn = _connect(self._db_path)
            try:
                r = conn.execute(
                    """SELECT id, start_ts, end_ts, label, devices_seen,
                              phones_seen, watch_hits
                         FROM sweeps WHERE id = ?""",
                    (sweep_id,),
                ).fetchone()
            finally:
                conn.close()
        except Exception:
            return None
        if not r:
            return None
        return {
            "id": r[0], "start_ts": r[1], "end_ts": r[2], "label": r[3],
            "devices_seen": r[4] or 0, "phones_seen": r[5] or 0,
            "watch_hits": r[6] or 0,
            "active": (r[0] == self.active_sweep_id()),
        }

    def get_recent_alerts(self, limit=50):
        """Read the most recent alerts from disk for the Log tab. Opens a
        fresh read-only connection so it's safe to call from the UI thread.
        Result is cached for ~1s to avoid per-frame sqlite churn."""
        cache_key = ("get_recent_alerts", limit)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            conn = _connect(self._db_path)
            try:
                rows = conn.execute(
                    """SELECT ts, kind, fingerprint, mac, ssid, os, dev_type, rssi
                       FROM phone_alerts
                       ORDER BY ts DESC
                       LIMIT ?""",
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return []
        result = [
            {
                "ts": r[0], "kind": r[1], "fingerprint": r[2], "mac": r[3],
                "ssid": r[4], "os": r[5], "dev_type": r[6], "rssi": r[7],
            }
            for r in rows
        ]
        self._cache_put(cache_key, result)
        return result

    def _migrate(self, conn):
        """Drop ble_devices if it has the old MAC-keyed shape. Old rows were
        accumulating one per MAC rotation, so they aren't worth preserving."""
        try:
            cols = conn.execute("PRAGMA table_info(ble_devices)").fetchall()
        except Exception:
            return
        if not cols:
            return
        names = {c[1] for c in cols}
        if "macs" not in names or "key" not in names:
            conn.execute("DROP TABLE ble_devices")
            conn.commit()

    def _retention_sweep(self, conn):
        """Drop rows older than RETENTION_DAYS so the SD card doesn't fill
        over months of operation. Skipped entirely when retention is 0
        (forensic mode — keep everything)."""
        if RETENTION_DAYS <= 0:
            return
        cutoff = time.time() - RETENTION_DAYS * 86400
        # Order matters: prune children before parents so the sweeps row
        # itself can be dropped only after its observations are gone.
        plans = [
            ("DELETE FROM phone_alerts        WHERE ts        < ?", "phone_alerts"),
            ("DELETE FROM wifi_aps            WHERE last_seen < ?", "wifi_aps"),
            ("DELETE FROM wifi_probes         WHERE last_seen < ?", "wifi_probes"),
            ("DELETE FROM ble_devices         WHERE last_seen < ?", "ble_devices"),
            ("DELETE FROM sweep_observations  WHERE last_seen < ?", "sweep_observations"),
            ("DELETE FROM sweeps              WHERE start_ts  < ?", "sweeps"),
        ]
        total = 0
        for sql, tbl in plans:
            try:
                cur = conn.execute(sql, (cutoff,))
                if cur.rowcount and cur.rowcount > 0:
                    total += cur.rowcount
            except Exception as e:
                print(f"[persistence] retention skip {tbl}: {e}")
        conn.commit()
        if total:
            print(f"[persistence] retention: pruned {total} rows older than {RETENTION_DAYS} days")

    def _loop(self):
        # Ensure the data dir exists with private perms BEFORE sqlite3
        # creates the DB file there. Otherwise the DB lands with whatever
        # umask the parent process has.
        _ensure_private_dir(os.path.dirname(os.path.abspath(self._db_path)))
        conn = _connect(self._db_path)
        _ensure_private_file(self._db_path)
        # WAL + synchronous=NORMAL drastically cuts SD-card write
        # amplification: instead of a full-DB fsync per snapshot we get
        # one append + a periodic checkpoint. Capture data is recoverable
        # if power drops mid-write — losing a few seconds of beacons isn't
        # worth grinding the SD card to dust over a year of operation.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception as e:
            print(f"[persistence] WAL setup failed (continuing in default mode): {e}")
        try:
            self._migrate(conn)
            conn.executescript(SCHEMA)
            conn.commit()
            self._retention_sweep(conn)
            print(f"[persistence] db: {self._db_path}")
            while self._running:
                try:
                    self._snapshot(conn)
                except Exception as e:
                    # Never let a logging error kill the scanner UI.
                    print(f"[persistence] snapshot error: {e}")
                time.sleep(SNAPSHOT_INTERVAL_S)
        finally:
            conn.close()

    # BLE device types that we treat as "phone-class" — any of these on
    # an unauthorized BLE radio in a SCIF should alert. iBeacon is
    # excluded (advertised by lots of non-phone things). Match the
    # strings classify_device() in ble_scanner.py emits.
    _BLE_PHONE_TYPES = {
        "iPhone", "Apple Watch", "MacBook", "AirPods", "AirDrop", "AirTag",
        "Apple Device", "Android Device", "Samsung Device",
        "Microsoft Device", "Google Device",
    }

    def _ble_is_phone(self, dev):
        return dev.get("type") in self._BLE_PHONE_TYPES

    def _snapshot(self, conn):
        now = time.time()
        cur = conn.cursor()
        # Read once per snapshot so we don't acquire the sweep lock per-row.
        sweep_id = self.active_sweep_id()
        # Per-device try/except below so one bad row (malformed dict,
        # surprise None where we expected an int) doesn't roll back the
        # whole snapshot. We commit at the end regardless of partial
        # failures so successful upserts persist.
        skipped = 0

        for ap in self._wifi.get_devices():
            try:
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
                                      ap["rssi"], ap,
                                      seen_set=self._seen_phone_fps)
                if sweep_id is not None:
                    self._record_observation(
                        cur, sweep_id, "wifi_ap", ap["bssid"],
                        label=ap.get("ssid"), os_=None, dev_type=None,
                        is_phone=ap.get("is_phone"), is_watch=False,
                        rssi=ap["rssi"], last_seen=ap["last_seen"],
                    )
            except Exception as e:
                skipped += 1
                print(f"[persistence] skipping ap row ({ap.get('bssid')}): {e}")

        for pr in self._wifi.get_probes():
            try:
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
                                      pr["rssi"], pr,
                                      seen_set=self._seen_phone_fps)
                if pr.get("is_watchlisted"):
                    # Surface the matched watchlist SSID, not the most recent
                    # ssid value, since that's the actual operational signal.
                    matched = pr.get("matched_ssids") or []
                    hit_ssid = matched[0] if matched else pr.get("ssid")
                    self._maybe_alert(conn, "watchlist", pr["fingerprint"], pr["mac"],
                                      hit_ssid, pr.get("os"), pr.get("dev_type"),
                                      pr["rssi"], pr,
                                      seen_set=self._seen_watchlist_fps)
                if sweep_id is not None:
                    self._record_observation(
                        cur, sweep_id, "wifi_probe", pr["fingerprint"],
                        label=pr.get("ssid"), os_=pr.get("os"),
                        dev_type=pr.get("dev_type"),
                        is_phone=pr.get("is_phone"),
                        is_watch=pr.get("is_watchlisted"),
                        rssi=pr["rssi"], last_seen=pr["last_seen"],
                    )
            except Exception as e:
                skipped += 1
                print(f"[persistence] skipping probe row ({pr.get('fingerprint')}): {e}")

        for dev in self._ble.get_devices():
            try:
                ble_key   = _ble_storage_key(dev.get("fingerprint"), dev["mac"])
                is_phone  = self._ble_is_phone(dev)
                cur.execute(
                    """
                    INSERT INTO ble_devices (key, fingerprint, mac_last, macs, name,
                                             vendor, dev_type, rssi_last, rssi_max,
                                             first_seen, last_seen, hits)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(key) DO UPDATE SET
                        fingerprint = excluded.fingerprint,
                        mac_last    = excluded.mac_last,
                        macs        = excluded.macs,
                        name        = excluded.name,
                        vendor      = excluded.vendor,
                        dev_type    = excluded.dev_type,
                        rssi_last   = excluded.rssi_last,
                        rssi_max    = MAX(rssi_max, excluded.rssi_last),
                        last_seen   = excluded.last_seen,
                        hits        = hits + 1
                    """,
                    (
                        ble_key, dev.get("fingerprint"), dev["mac"],
                        json.dumps(dev.get("macs", [dev["mac"]])),
                        dev.get("name"), dev.get("vendor"), dev.get("type"),
                        dev["rssi"], dev["rssi"], now, dev["last_seen"],
                    ),
                )
                # BLE alert path: phone-class types (iPhone, AirPods, Apple
                # Watch, etc.) fire the same red banner the Wi-Fi side
                # does, deduped per BLE storage key. Without this, BLE
                # sees the device but never escalates it as a phone.
                if is_phone:
                    self._maybe_alert(conn, "ble", ble_key, dev["mac"],
                                      dev.get("name"), None, dev.get("type"),
                                      dev["rssi"], dev,
                                      seen_set=self._seen_phone_fps)
                if sweep_id is not None:
                    # Re-use the same key for sweep observations so a rotating
                    # AirPods only takes one row per sweep.
                    self._record_observation(
                        cur, sweep_id, "ble", ble_key,
                        label=dev.get("name"), os_=None,
                        dev_type=dev.get("type"),
                        is_phone=is_phone, is_watch=False,
                        rssi=dev["rssi"], last_seen=dev["last_seen"],
                    )
            except Exception as e:
                skipped += 1
                print(f"[persistence] skipping ble row ({dev.get('mac')}): {e}")

        conn.commit()
        if skipped:
            print(f"[persistence] snapshot kept partial result, skipped {skipped} bad rows")

    def _record_observation(self, cur, sweep_id, kind, key, label, os_,
                            dev_type, is_phone, is_watch, rssi, last_seen):
        """Upsert a single (sweep, kind, key) observation. Updates rssi_max
        / rssi_last / last_seen / hits on each call so a row tells the
        complete story of how that device was seen during the sweep."""
        cur.execute(
            """INSERT INTO sweep_observations
               (sweep_id, kind, key, label, os, dev_type, is_phone, is_watch,
                rssi_max, rssi_last, first_seen, last_seen, hits)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(sweep_id, kind, key) DO UPDATE SET
                   label      = COALESCE(excluded.label, label),
                   os         = COALESCE(excluded.os, os),
                   dev_type   = COALESCE(excluded.dev_type, dev_type),
                   is_phone   = MAX(is_phone, excluded.is_phone),
                   is_watch   = MAX(is_watch, excluded.is_watch),
                   rssi_max   = MAX(rssi_max, excluded.rssi_last),
                   rssi_last  = excluded.rssi_last,
                   last_seen  = excluded.last_seen,
                   hits       = hits + 1
            """,
            (
                sweep_id, kind, key, label, os_, dev_type,
                int(bool(is_phone)), int(bool(is_watch)),
                rssi, rssi, last_seen, last_seen,
            ),
        )

    def _maybe_alert(self, conn, kind, fp, mac, ssid, os_, dev_type, rssi, raw, seen_set):
        if not fp or fp in seen_set:
            return
        seen_set.add(fp)
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
