import os
import signal
import sys
import time
import collections
import queue
import pygame

os.environ["SDL_VIDEODRIVER"] = "offscreen"

# Release any GPIO pins claimed by previous run
try:
    import lgpio
    h = lgpio.gpiochip_open(0)
    for pin in [4, 5, 6, 12, 13, 16, 18, 19, 20, 21, 26]:
        try:
            lgpio.gpio_free(h, pin)
        except:
            pass
    lgpio.gpiochip_close(h)
except:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from input_handler import InputHandler
from wifi_scanner import WiFiScanner
from ble_scanner import BLEScanner
from zigbee_scanner import ZigbeeScanner
from sdr_scanner import SDRScanner
from cell_analyzer import load_opencellid_baseline
from persistence import Persistence, _TRIVIAL_BLE_FP

# ── Colors ───────────────────────────────────────────────
BG         = (10,  10,  30)
BG_ROW     = (15,  15,  40)
BG_SEL     = (25,  25,  70)
BG_HEADER  = (20,  20,  55)
BG_FOOTER  = (20,  20,  55)
TAB_ACTIVE = (0,   180, 220)
TAB_INACT  = (40,  40,  70)
WHITE      = (255, 255, 255)
GREY       = (120, 120, 120)
GREEN      = (0,   255, 120)
YELLOW     = (255, 255,   0)
ORANGE     = (255, 165,   0)
RED        = (255,  60,  60)
CYAN       = (0,   220, 255)
LOCKED_COL = (255, 200,   0)

WIFI_FILTERS = ["ALL", "2.4G", "5G"]
SORTS        = ["rssi", "ssid", "channel"]
TABS         = ["WiFi", "BLE", "Phones", "Cell", "Zigbee", "Log"]
# Tab-index constants. Use these everywhere instead of literal ints so
# inserting / reordering tabs only touches the TABS list above.
TAB_WIFI, TAB_BLE, TAB_PHONES, TAB_CELL, TAB_ZIGBEE, TAB_LOG = range(len(TABS))

# DF mode history length
DF_HISTORY = 60

# How long the red phone-alert banner stays visible after a new detection.
ALERT_FLASH_S = 4.0


def rssi_color(rssi):
    if rssi >= -50: return GREEN
    if rssi >= -65: return YELLOW
    if rssi >= -75: return ORANGE
    return RED


def rssi_bar_width(rssi, max_width=300):
    clamped = max(-100, min(-20, rssi))
    return int((clamped + 100) / 80 * max_width)


def draw_signal_bars(surface, x, y, rssi, height=20):
    bar_w = 6
    gap   = 2
    color = rssi_color(rssi)
    if rssi >= -50:   filled = 5
    elif rssi >= -60: filled = 4
    elif rssi >= -70: filled = 3
    elif rssi >= -80: filled = 2
    else:             filled = 1
    for i in range(5):
        bar_h = int(height * (i + 1) / 5)
        bx = x + i * (bar_w + gap)
        by = y + (height - bar_h)
        c = color if i < filled else (50, 50, 50)
        pygame.draw.rect(surface, c, (bx, by, bar_w, bar_h))


class Doperscope:
    def __init__(self):
        pygame.init()
        # Audio is optional — Pis without an audio device (or with the
        # mixer disabled in raspi-config) raise pygame.error on init.
        # Degrade gracefully: no tick sound, no banner audio, but the
        # rest of the UI still runs.
        try:
            pygame.mixer.init()
            self.tick_sound = pygame.mixer.Sound("tick.wav")
        except Exception as e:
            print(f"[doperscope] audio disabled ({e})")
            self.tick_sound = None
        self.last_tick_time = 0
        self.screen = pygame.display.set_mode((640, 480))
        # Framebuffer write target. Missing on dev hosts / CI runners /
        # any non-Pi machine; degrade to None so the rest of the UI can
        # still drive scanners + persistence for testing. _render
        # checks this before writing.
        try:
            self.fb = open("/dev/fb0", "wb")
        except OSError as e:
            print(f"[doperscope] /dev/fb0 unavailable ({e}); rendering off-screen only")
            self.fb = None

        self.font_title  = pygame.font.SysFont(None, 38)
        self.font_main   = pygame.font.SysFont(None, 30)
        self.font_small  = pygame.font.SysFont(None, 24)
        self.font_rssi   = pygame.font.SysFont(None, 28)
        self.font_huge   = pygame.font.SysFont(None, 96)
        self.font_large  = pygame.font.SysFont(None, 56)

        wifi_iface       = os.environ.get("DOPESCOPE_WIFI_IFACE", "wlan1")
        self.wifi_iface  = wifi_iface
        self.scanner     = WiFiScanner(wifi_iface)
        self.ble         = BLEScanner()
        self.zigbee      = ZigbeeScanner()
        self.sdr         = SDRScanner()
        self.inp         = InputHandler()
        self.persistence = Persistence(self.scanner, self.ble, self.sdr)

        # Phone-alert UI state: when a new phone fingerprint shows up the
        # banner stays red for ALERT_FLASH_S so it's visible during a sweep.
        self.alert_until = 0.0
        self.alert_text  = ""

        # Tab + filter state
        self.tab         = 0
        self.wifi_filter = 0
        self.sort_idx    = 0
        self.selected    = 0
        self.scroll      = 0
        self.locked      = None
        # Select on the WiFi tab toggles the probe-request panel via
        # _action_select. (The previous show_hidden field and its
        # H:ON/OFF topbar status were dead code — the toggle was never
        # wired up — and have been removed.)
        self.show_probes = True
        self.view        = "ap_list"  # ap_list | client_list | df_mode

        # BLE DF state
        self.ble_df_target  = None
        self.ble_df_history = collections.deque(maxlen=DF_HISTORY)
        self.ble_df_peak    = -100
        self.ble_df_avg     = -100
        self.ble_df_last    = -100
        self.ble_df_trend   = "STEADY"
        self.ble_df_missing = False

        self._event_queue = queue.Queue()

        # WiFi DF state
        self.df_history  = collections.deque(maxlen=DF_HISTORY)
        self.df_peak     = -100
        self.df_avg      = -100
        self.df_last     = -100
        self.df_trend    = "STEADY"

        # Phone DF state — tracks by IE fingerprint so MAC rotation doesn't
        # break the lock during a sweep.
        self.phone_df_target  = None
        self.phone_df_history = collections.deque(maxlen=DF_HISTORY)
        self.phone_df_peak    = -100
        self.phone_df_avg     = -100
        self.phone_df_last    = -100
        self.phone_df_trend   = "STEADY"
        self.phone_df_missing = False

        # Log tab subview: "alerts" shows phone_alerts, "sweeps" shows
        # the captured-sweep list. X cycles between them on tab 4.
        self.log_view = "sweeps"

        # Sweep-detail drill-down: which sweep id we're currently viewing.
        self.sweep_detail_id = None

        self.ROWS_VISIBLE = 5
        self.ROW_H        = 70

        self.ble_frozen = False
        self.ble_frozen_list = []
        self._bind_buttons()
        # Load the OpenCellID baseline before starting the SDR thread so
        # the very first observation gets scored against it. Path is
        # configurable via DOPESCOPE_OCID_PATH; the default sits next to
        # the DB in ~/.doperscope/opencellid/ocid_us.csv where
        # setup_sdr.sh provisioned the directory.
        ocid_path = os.environ.get(
            "DOPESCOPE_OCID_PATH",
            os.path.expanduser("~/.doperscope/opencellid/ocid_us.csv"),
        )
        self.sdr.set_baseline(load_opencellid_baseline(ocid_path))
        self.scanner.start()
        self.ble.start()
        self.zigbee.start()
        self.sdr.start()
        self.persistence.start()

    # ── Button bindings ──────────────────────────────────

    def _bind_buttons(self):
        self.inp.on("up",     lambda: self._event_queue.put("up"))
        self.inp.on("down",   lambda: self._event_queue.put("down"))
        self.inp.on("left",   lambda: self._event_queue.put("left"))
        self.inp.on("right",  lambda: self._event_queue.put("right"))
        self.inp.on("a",      lambda: self._event_queue.put("a"))
        self.inp.on("b",      lambda: self._event_queue.put("b"))
        self.inp.on("x",      lambda: self._event_queue.put("x"))
        self.inp.on("y",      lambda: self._event_queue.put("y"))
        self.inp.on("select", lambda: self._event_queue.put("select"))
        self.inp.on("start",  lambda: self._event_queue.put("start"))
        self.inp.on("joy",    lambda: self._event_queue.put("joy"))











    def _scroll_up(self):
        self.selected = max(0, self.selected - 1)
        if self.selected < self.scroll:
            self.scroll = self.selected

    def _scroll_down(self):
        if self.view == "sweep_detail" and self.sweep_detail_id is not None:
            items = self.persistence.get_sweep_observations(self.sweep_detail_id)
        elif self.view == "client_list":
            items = self.scanner.get_clients(self.locked["bssid"])
        elif self.tab == TAB_BLE:
            items = self.ble.get_devices()
        elif self.tab == TAB_PHONES:
            items = self.scanner.get_probes(phones_only=True)
        elif self.tab == TAB_CELL:
            items = self.sdr.get_cells()
        elif self.tab == TAB_ZIGBEE:
            items = self.zigbee.get_devices()
        elif self.tab == TAB_LOG:
            if self.log_view == "sweeps":
                items = self.persistence.list_sweeps()
            else:
                items = self.persistence.get_recent_alerts()
        else:
            items = self._get_wifi_devices()
        self.selected = min(max(len(items) - 1, 0), self.selected + 1)
        if self.selected >= self.scroll + self.ROWS_VISIBLE:
            self.scroll = self.selected - self.ROWS_VISIBLE + 1

    def _action_a(self):
        # A: enter client view from AP list
        if self.tab == TAB_WIFI and self.view == "ap_list":
            devs = self._get_wifi_devices()
            if devs and 0 <= self.selected < len(devs):
                self.locked   = devs[self.selected]
                self.scanner.locked_channel = devs[self.selected]["channel"]
                self.view     = "client_list"
                self.selected = 0
                self.scroll   = 0
        elif self.tab == TAB_LOG and self.view == "ap_list" and self.log_view == "sweeps":
            # A on a sweep row drills into the captured observations.
            sweeps = self.persistence.list_sweeps()
            if sweeps and 0 <= self.selected < len(sweeps):
                self.sweep_detail_id = sweeps[self.selected]["id"]
                self.view            = "sweep_detail"
                self.selected        = 0
                self.scroll          = 0

    def _action_b(self):
        if self.view == "ap_list" and self.tab == TAB_WIFI:
            # WiFi DF mode
            devs = self._get_wifi_devices()
            if devs and 0 <= self.selected < len(devs):
                self.locked     = devs[self.selected]
                self.view       = "df_mode"
                self.df_history.clear()
                self.df_peak    = -100
                self.df_avg     = -100
                self.df_last    = -100
                self.df_trend   = "STEADY"
        elif self.view == "ap_list" and self.tab == TAB_BLE:
            # BLE DF mode
            devs = self.ble.get_devices()
            if devs and 0 <= self.selected < len(devs):
                self.ble_df_target  = devs[self.selected]
                self.view           = "ble_df_mode"
                self.ble_df_history.clear()
                self.ble_df_peak    = -100
                self.ble_df_avg     = -100
                self.ble_df_last    = -100
                self.ble_df_trend   = "STEADY"
                self.ble_df_missing = False
        elif self.view == "ap_list" and self.tab == TAB_LOG:
            # Log tab — B toggles the active sweep.
            if self.persistence.is_sweep_active():
                self.persistence.end_sweep()
            else:
                self.persistence.start_sweep()
            return
        elif self.view == "ap_list" and self.tab == TAB_PHONES:
            # Phone DF mode — fingerprint-locked.
            probes = self.scanner.get_probes(phones_only=True)
            if probes and 0 <= self.selected < len(probes):
                self.phone_df_target  = probes[self.selected]
                self.view             = "phone_df_mode"
                self.phone_df_history.clear()
                self.phone_df_peak    = -100
                self.phone_df_avg     = -100
                self.phone_df_last    = -100
                self.phone_df_trend   = "STEADY"
                self.phone_df_missing = False
        elif self.view in ("client_list", "df_mode", "ble_df_mode", "phone_df_mode", "sweep_detail"):
            self.view     = "ap_list"
            self.selected = 0
            self.scroll   = 0
            self.locked   = None
            self.phone_df_target = None
            self.sweep_detail_id = None
            self.scanner.locked_channel = None

    def _action_y(self):
        # Y (shoulder): switch tabs. Suppressed in every sub-view that
        # carries unsaved DF / detail state so a fat-finger Y can't
        # silently drop the operator's lock.
        if self.view in ("client_list", "df_mode", "ble_df_mode",
                         "phone_df_mode", "sweep_detail"):
            return
        self.tab      = (self.tab + 1) % len(TABS)
        self.selected = 0
        self.scroll   = 0
        self.locked   = None
        self.view     = "ap_list"

    def _action_start(self):
        if self.view == "df_mode":
            self.df_peak = self.df_last
            self.df_history.clear()
        elif self.view == "ble_df_mode":
            self.ble_df_peak = self.ble_df_last
            self.ble_df_history.clear()
            self.ble_df_missing = False
        elif self.view == "phone_df_mode":
            self.phone_df_peak = self.phone_df_last
            self.phone_df_history.clear()
            self.phone_df_missing = False
        elif self.view == "sweep_detail":
            self.view            = "ap_list"
            self.sweep_detail_id = None
            self.selected        = 0
            self.scroll          = 0
        else:
            self.locked   = None
            self.view     = "ap_list"
            self.selected = 0
            self.scroll   = 0

    def _action_joy(self):
        if self.view in ("client_list", "df_mode", "ble_df_mode", "phone_df_mode", "sweep_detail"):
            self.view     = "ap_list"
            self.selected = 0
            self.scroll   = 0
            self.locked   = None
            self.ble_df_target   = None
            self.phone_df_target = None
            self.sweep_detail_id = None

    def _cycle_sort(self):
        # X is contextual:
        #  - on the Log tab, swap between sweeps and alerts subviews
        #  - inside a sweep_detail view, export that sweep to CSV
        #  - everywhere else, cycle the sort order
        if self.view == "sweep_detail" and self.sweep_detail_id is not None:
            path = self.persistence.export_sweep_csv(self.sweep_detail_id)
            self.alert_until = time.time() + ALERT_FLASH_S
            if path:
                self.alert_text = f"EXPORTED  {os.path.basename(path)}"
            else:
                self.alert_text = "EXPORT FAILED"
            return
        if self.tab == TAB_LOG:
            self.log_view = "alerts" if self.log_view == "sweeps" else "sweeps"
            self.selected = 0
            self.scroll   = 0
            return
        self.sort_idx = (self.sort_idx + 1) % len(SORTS)

    def _cycle_wifi_filter(self):
        if self.tab == TAB_WIFI and self.view == "ap_list":
            self.wifi_filter = (self.wifi_filter + 1) % len(WIFI_FILTERS)
            self.selected    = 0
            self.scroll      = 0

    def _action_select(self):
        # Select is contextual:
        #  - BLE tab:   freeze / unfreeze the live list
        #  - elsewhere: toggle the probe-request panel on the WiFi tab
        if self.tab == TAB_BLE:
            self.ble_frozen = not self.ble_frozen
            if self.ble_frozen:
                sort_key = "name" if SORTS[self.sort_idx] == "ssid" else "rssi"
                self.ble_frozen_list = self.ble.get_devices(sort_by=sort_key)
            else:
                self.ble_frozen_list = []
            self.selected = 0
            self.scroll   = 0
        else:
            self.show_probes = not self.show_probes
            self.selected    = 0
            self.scroll      = 0

    # ── Data helpers ─────────────────────────────────────

    def _get_wifi_devices(self):
        band = None if WIFI_FILTERS[self.wifi_filter] == "ALL" else WIFI_FILTERS[self.wifi_filter]
        return self.scanner.get_devices(band_filter=band, sort_by=SORTS[self.sort_idx])

    def _update_df(self):
        """Update DF mode stats from live scan data."""
        if not self.locked:
            return
        live_devs = self.scanner.get_devices()
        live = next((d for d in live_devs if d["bssid"] == self.locked["bssid"]), None)
        if not live:
            return

        rssi = live["rssi"]
        self.df_history.append(rssi)
        self.df_last = rssi

        if rssi > self.df_peak:
            self.df_peak = rssi

        if len(self.df_history) >= 3:
            self.df_avg = int(sum(self.df_history) / len(self.df_history))
            recent = list(self.df_history)[-6:]
            older  = list(self.df_history)[-12:-6]
            if older:
                recent_avg = sum(recent) / len(recent)
                older_avg  = sum(older)  / len(older)
                diff = recent_avg - older_avg
                if diff > 2:
                    self.df_trend = "STRONGER ▲"
                elif diff < -2:
                    self.df_trend = "WEAKER ▼"
                else:
                    self.df_trend = "STEADY ●"

    def _update_ble_df(self):
        if not self.ble_df_target:
            return

        target_mac = self.ble_df_target["mac"]
        target_fp  = self.ble_df_target.get("fingerprint", "")
        devs = self.ble.get_devices()

        # 1. Try to find the target by exact MAC first
        live = next((d for d in devs if d["mac"] == target_mac), None)

        # 2. ANTI-RANDOMIZATION: If MAC is missing, try to find by fingerprint.
        #    A trivial fingerprint (no mfr / no services) is too weak to use
        #    as an anti-randomization key, so we skip the fallback for it
        #    and let the target stay marked missing.
        if not live and target_fp and target_fp != _TRIVIAL_BLE_FP:
            candidates = [d for d in devs if d.get("fingerprint") == target_fp]
            if candidates:
                # Grab the most recently seen candidate with this fingerprint
                live = sorted(candidates, key=lambda x: x["last_seen"], reverse=True)[0]

        if not live:
            self.ble_df_missing = True
            return

        # Silently fold the latest MAC alias and rotation set onto our locked
        # target so the DF header's rotation count stays current.
        self.ble_df_target["mac"]  = live["mac"]
        self.ble_df_target["macs"] = live.get("macs", [live["mac"]])
        self.ble_df_missing = False
        rssi = live["rssi"]
        self.ble_df_history.append(rssi)
        self.ble_df_last = rssi

        if rssi > self.ble_df_peak:
            self.ble_df_peak = rssi

        if len(self.ble_df_history) >= 3:
            self.ble_df_avg = int(sum(self.ble_df_history) / len(self.ble_df_history))
            recent = list(self.ble_df_history)[-6:]
            older  = list(self.ble_df_history)[-12:-6]
            if older:
                recent_avg = sum(recent) / len(recent)
                older_avg  = sum(older)  / len(older)
                diff = recent_avg - older_avg
                if diff > 2:
                    self.ble_df_trend = "STRONGER ▲"
                elif diff < -2:
                    self.ble_df_trend = "WEAKER ▼"
                else:
                    self.ble_df_trend = "STEADY ●"

    def _update_phone_df(self):
        """Read live RSSI for the locked probe fingerprint. The fingerprint
        is the primary key — MAC rotation just produces a new alias on the
        same tracked probe, so we keep the lock through randomization."""
        if not self.phone_df_target:
            return

        target_fp = self.phone_df_target.get("fingerprint")
        if not target_fp:
            self.phone_df_missing = True
            return

        # All probes (not phones_only) so a watchlist-only target also tracks.
        probes = self.scanner.get_probes()
        live   = next((p for p in probes if p.get("fingerprint") == target_fp), None)

        if not live:
            self.phone_df_missing = True
            return

        self.phone_df_missing = False
        # Surface the latest MAC alias on the target so the UI shows rotation.
        self.phone_df_target["mac"]  = live["mac"]
        self.phone_df_target["macs"] = live.get("macs", [live["mac"]])

        rssi = live["rssi"]
        self.phone_df_history.append(rssi)
        self.phone_df_last = rssi
        if rssi > self.phone_df_peak:
            self.phone_df_peak = rssi

        if len(self.phone_df_history) >= 3:
            self.phone_df_avg = int(sum(self.phone_df_history) / len(self.phone_df_history))
            recent = list(self.phone_df_history)[-6:]
            older  = list(self.phone_df_history)[-12:-6]
            if older:
                recent_avg = sum(recent) / len(recent)
                older_avg  = sum(older)  / len(older)
                diff = recent_avg - older_avg
                if diff > 2:
                    self.phone_df_trend = "STRONGER ▲"
                elif diff < -2:
                    self.phone_df_trend = "WEAKER ▼"
                else:
                    self.phone_df_trend = "STEADY ●"

    def _play_geiger_tick(self, rssi):
        if not self.tick_sound:
            return

        now = time.time()
        # Map RSSI to tick interval. -90 dBm = 1.0s between ticks,
        # -30 dBm = 0.1s (floored — going faster than 10Hz on a small
        # mixer buffer just clips and sounds worse than the slower rate).
        clamped_rssi = max(-90, min(-30, rssi))
        normalized = (clamped_rssi + 90) / 60          # 0.0 to 1.0
        interval = max(0.1, 1.0 - (normalized * 0.9))  # 1.0s down to 0.1s

        if now - self.last_tick_time >= interval:
            try:
                self.tick_sound.play()
            except Exception:
                pass
            self.last_tick_time = now

    def _draw_tabs(self):
        # Auto-shrink tab width as tabs are added so right_text in the
        # topbar still has room. 6 tabs at 60px is the practical floor
        # before the labels themselves start clipping.
        n     = len(TABS)
        if n >= 6:
            tab_w = 60
        elif n >= 5:
            tab_w = 72
        elif n >= 4:
            tab_w = 90
        else:
            tab_w = 120
        tab_h = 36
        for i, label in enumerate(TABS):
            x      = 10 + i * (tab_w + 8)
            active = (i == self.tab)
            color  = TAB_ACTIVE if active else TAB_INACT
            pygame.draw.rect(self.screen, color, (x, 4, tab_w, tab_h), border_radius=6)
            t = self.font_main.render(label, True, WHITE if active else GREY)
            self.screen.blit(t, (x + tab_w // 2 - t.get_width() // 2, 10))

    def _scanner_health_warning(self):
        """If any scanner has been silent past the threshold or has
        accumulated parse errors, return a one-line warning string and
        a colour. Otherwise return (None, None). Capture-stubbed
        scanners (Zigbee currently) are excluded — they're allowed to
        be 0/0 without triggering a "silent" alarm."""
        SILENT_S       = 30.0
        ERROR_VISIBLE  = 1
        now = time.time()
        warnings = []
        worst_red = False  # any scanner with errors → red, otherwise yellow

        for name, scn, capturing in [
            ("WiFi", self.scanner, True),
            ("BLE",  self.ble,     True),
            # Zigbee not in capture mode yet, so don't alarm on silence.
        ]:
            errs = getattr(scn, "error_count", 0)
            last = getattr(scn, "last_packet_ts", 0.0)
            silent_for = now - last if last > 0 else None
            if errs >= ERROR_VISIBLE:
                warnings.append(f"{name}:{errs}err")
                worst_red = True
            elif capturing and (last == 0.0 or silent_for > SILENT_S):
                if last == 0.0:
                    warnings.append(f"{name}:no pkt")
                else:
                    warnings.append(f"{name}:silent {int(silent_for)}s")
        if not warnings:
            return None, None
        col = RED if worst_red else LOCKED_COL
        return "⚠ " + "  ".join(warnings), col

    def _draw_topbar(self, right_text=""):
        pygame.draw.rect(self.screen, BG_HEADER, (0, 0, 640, 44))
        self._draw_tabs()
        # Compose the right-side status text from up to three pieces:
        #   1. scanner-health warning (operationally critical — silent
        #      scanner shouldn't be hidden behind a normal tab status)
        #   2. active sweep timer
        #   3. the per-tab right_text the caller passed in
        # Pulled into one render so they don't fight for screen space.
        warning, warn_col = self._scanner_health_warning()
        sweep_active = self.persistence.is_sweep_active()
        if sweep_active:
            elapsed = int(time.time() - self.persistence.active_sweep_started_at())
            mm, ss  = divmod(max(0, elapsed), 60)
            sweep_str = f"● SWEEP {mm}:{ss:02d}"
        else:
            sweep_str = ""

        if warning:
            # Health warning takes the prime slot. Push other text below.
            wt = self.font_small.render(warning, True, warn_col)
            self.screen.blit(wt, (640 - wt.get_width() - 10, 6))
            tail = "  ".join(s for s in (sweep_str, right_text) if s)
            if tail:
                tt = self.font_small.render(tail, True, RED if sweep_active else GREY)
                self.screen.blit(tt, (640 - tt.get_width() - 10, 24))
            return

        if sweep_str:
            full = f"{sweep_str}  {right_text}" if right_text else sweep_str
            rt = self.font_small.render(full, True, RED)
            self.screen.blit(rt, (640 - rt.get_width() - 10, 14))
            return
        if right_text:
            rt = self.font_small.render(right_text, True, GREY)
            self.screen.blit(rt, (640 - rt.get_width() - 10, 14))

    def _draw_footer(self, text):
        pygame.draw.rect(self.screen, BG_FOOTER, (0, 440, 640, 40))
        ft = self.font_small.render(text, True, GREY)
        self.screen.blit(ft, (8, 450))

    def _draw_device_row(self, dev, y, is_selected, is_locked=False):
        bg = BG_SEL if is_selected else BG_ROW
        pygame.draw.rect(self.screen, bg, (0, y, 640, self.ROW_H - 2))
        if is_locked:
            pygame.draw.rect(self.screen, LOCKED_COL, (0, y, 5, self.ROW_H - 2))
        elif is_selected:
            pygame.draw.rect(self.screen, CYAN, (0, y, 5, self.ROW_H - 2))
        # Phone hotspots get the same red the phone-row probes use, kept
        # in sync with the module-level RED so the colour grammar is
        # consistent across the UI.
        is_phone = dev.get('is_phone', False)
        if is_phone:
            ssid_col = RED
        else:
            ssid_col = LOCKED_COL if is_locked else (WHITE if is_selected else GREY)
        self.screen.blit(
            self.font_main.render(dev.get("ssid", "<Probe>")[:28], True, ssid_col),
            (12, y + 5)
        )
        
        band = dev.get('band', '2.4G')
        vendor = dev.get('vendor', 'MOBILE')[:18]
        meta = f"{band} ch{dev.get('channel', '??')} {vendor}"
        self.screen.blit(self.font_small.render(meta, True, GREY), (12, y + 34))
        self.screen.blit(
            self.font_rssi.render(f"{dev['rssi']}dBm", True, rssi_color(dev["rssi"])),
            (490, y + 5)
        )
        draw_signal_bars(self.screen, 580, y + 8, dev["rssi"], height=30)
        # Define the label first (Safe for phones)
        bssid_label = dev.get("bssid", "PROBE REQUEST")

        # Now blit it to the screen
        self.screen.blit(
            self.font_small.render(bssid_label, True, (60, 60, 80)),
            (490, y + 38)
        )

    # ── WiFi AP list ─────────────────────────────────────

    def _draw_ap_list(self):
        devs       = self._get_wifi_devices()
        filter_str = WIFI_FILTERS[self.wifi_filter]
        sort_str   = SORTS[self.sort_idx].upper()
        self._draw_topbar(
            right_text=f"{filter_str}  {sort_str}  {len(devs)}APs"
        )

        pygame.draw.rect(self.screen, (18, 18, 48), (0, 44, 640, 22))
        for i, f in enumerate(WIFI_FILTERS):
            active = (i == self.wifi_filter)
            col    = CYAN if active else GREY
            self.screen.blit(self.font_small.render(f, True, col), (280 + i * 70, 48))
        self.screen.blit(
            self.font_small.render("X:Sort  Sel:Probes", True, (60, 60, 80)),
            (8, 48)
        )

        probes = self.scanner.get_probes() if self.show_probes else []
        probe_rows = min(len(probes), 2) if probes else 0
        ap_rows = self.ROWS_VISIBLE if not probes else max(3, self.ROWS_VISIBLE - probe_rows)

        visible = devs[self.scroll: self.scroll + ap_rows]
        for i, dev in enumerate(visible):
            abs_idx   = self.scroll + i
            is_sel    = (abs_idx == self.selected)
            is_locked = bool(self.locked and dev["bssid"] == self.locked["bssid"])
            self._draw_device_row(dev, 68 + i * self.ROW_H, is_sel, is_locked)

        if not devs:
            self.screen.blit(
                self.font_main.render("Scanning...", True, GREY), (250, 180)
            )

        if probes:
            probe_y = 68 + ap_rows * self.ROW_H
            pygame.draw.rect(self.screen, (30, 10, 10), (0, probe_y, 640, 22))
            self.screen.blit(
                self.font_small.render(
                    f"PROBE REQUESTS ({len(probes)})", True, RED
                ), (8, probe_y + 4)
            )
            for i, probe in enumerate(probes[:probe_rows]):
                py = probe_y + 22 + i * 48
                is_phone   = probe.get("is_phone", False)
                row_bg     = (40, 8, 8) if is_phone else (20, 8, 8)
                top_col    = RED if is_phone else ORANGE
                pygame.draw.rect(self.screen, row_bg, (0, py, 640, 46))
                pygame.draw.rect(self.screen, RED, (0, py, 3, 46))
                mac_count  = len(probe.get("macs", [probe["mac"]]))
                rotate_tag = f"  [{mac_count}x MAC]" if mac_count > 1 else ""
                tag        = "[PHONE] " if is_phone else ""
                self.screen.blit(
                    self.font_small.render(
                        f"{tag}{probe.get('os','?')}  {probe.get('dev_type','?')[:22]}  {probe.get('wifi_gen','?')}",
                        True, top_col
                    ), (8, py + 4)
                )
                self.screen.blit(
                    self.font_small.render(
                        f"{probe['mac']}{rotate_tag}  seeking:{probe['ssid'][:18]}",
                        True, GREY
                    ), (8, py + 24)
                )
                self.screen.blit(
                    self.font_rssi.render(
                        f"{probe['rssi']}dBm", True, rssi_color(probe["rssi"])
                    ), (490, py + 10)
                )
                draw_signal_bars(self.screen, 580, py + 12, probe["rssi"], height=24)

        self._draw_footer("↕:Scroll  B:DF  A:Clients  X:Sort  Y:Tab  Sel:Probes")

    # ── Client list ──────────────────────────────────────

    def _draw_client_list(self):
        clients = self.scanner.get_clients(self.locked["bssid"])

        pygame.draw.rect(self.screen, BG_HEADER, (0, 0, 640, 44))
        self.screen.blit(
            self.font_title.render(f"Clients → {self.locked['ssid'][:22]}", True, LOCKED_COL),
            (12, 8)
        )
        pygame.draw.rect(self.screen, (25, 20, 10), (0, 44, 640, 24))
        self.screen.blit(
            self.font_small.render(
                f"{self.locked['bssid']}  ch{self.locked['channel']}  {self.locked['band']}",
                True, GREY
            ), (12, 50)
        )
        self.screen.blit(
            self.font_small.render(
                f"{len(clients)} client{'s' if len(clients) != 1 else ''}",
                True, CYAN
            ), (540, 50)
        )

        ROW_H = 62
        if not clients:
            self.screen.blit(
                self.font_main.render("No clients detected yet...", True, GREY),
                (155, 230)
            )
            self.screen.blit(
                self.font_small.render("Clients appear as devices send traffic", True, (60,60,80)),
                (135, 264)
            )
        else:
            visible = clients[self.scroll: self.scroll + 6]
            for i, client in enumerate(visible):
                y      = 70 + i * ROW_H
                is_sel = (i + self.scroll == self.selected)
                pygame.draw.rect(
                    self.screen, BG_SEL if is_sel else BG_ROW,
                    (0, y, 640, ROW_H - 2)
                )
                if is_sel:
                    pygame.draw.rect(self.screen, CYAN, (0, y, 5, ROW_H - 2))
                self.screen.blit(
                    self.font_main.render(client["mac"], True, WHITE if is_sel else GREY),
                    (12, y + 5)
                )
                self.screen.blit(
                    self.font_small.render(client["vendor"], True, CYAN),
                    (12, y + 34)
                )
                self.screen.blit(
                    self.font_rssi.render(
                        f"{client['rssi']}dBm", True, rssi_color(client["rssi"])
                    ), (490, y + 5)
                )
                draw_signal_bars(self.screen, 580, y + 8, client["rssi"], height=30)

        self._draw_footer("B/Joy/Start:Back  ↕:Scroll")

    # ── DF Mode ──────────────────────────────────────────

    def _draw_df_mode(self):
        self._update_df()
        rssi  = self.df_last
        color = rssi_color(rssi)

        # Header
        pygame.draw.rect(self.screen, BG_HEADER, (0, 0, 640, 44))
        self.screen.blit(
            self.font_title.render(f"DF: {self.locked['ssid'][:26]}", True, LOCKED_COL),
            (12, 8)
        )
        self.screen.blit(
            self.font_small.render(
                f"{self.locked['bssid']}  ch{self.locked['channel']}  {self.locked['band']}",
                True, GREY
            ), (12, 32)
        )

        # Big RSSI number
        rssi_str  = f"{rssi} dBm"
        rssi_surf = self.font_huge.render(rssi_str, True, color)
        self.screen.blit(rssi_surf, (320 - rssi_surf.get_width() // 2, 55))

        # Large signal bar
        bar_x = 20
        bar_y = 155
        bar_h = 40
        bar_max_w = 600
        bar_w = rssi_bar_width(rssi, max_width=bar_max_w)
        pygame.draw.rect(self.screen, (40, 40, 40), (bar_x, bar_y, bar_max_w, bar_h))
        pygame.draw.rect(self.screen, color, (bar_x, bar_y, bar_w, bar_h))

        # Scale markers
        for dbm, label in [(-80, "-80"), (-65, "-65"), (-50, "-50"), (-35, "-35")]:
            mx = bar_x + rssi_bar_width(dbm, max_width=bar_max_w)
            pygame.draw.line(self.screen, GREY, (mx, bar_y), (mx, bar_y + bar_h), 1)
            self.screen.blit(self.font_small.render(label, True, GREY), (mx - 10, bar_y + bar_h + 4))

        # Peak + avg stats
        pygame.draw.rect(self.screen, (18, 18, 48), (0, 210, 640, 44))
        self.screen.blit(
            self.font_main.render(f"PEAK: {self.df_peak} dBm", True, GREEN),
            (20, 218)
        )
        self.screen.blit(
            self.font_main.render(f"AVG: {self.df_avg} dBm", True, YELLOW),
            (220, 218)
        )
        trend_col = GREEN if "STRONGER" in self.df_trend else RED if "WEAKER" in self.df_trend else GREY
        self.screen.blit(
            self.font_main.render(self.df_trend, True, trend_col),
            (430, 218)
        )

        # History graph
        graph_x = 20
        graph_y = 265
        graph_w = 600
        graph_h = 120
        pygame.draw.rect(self.screen, (18, 18, 40), (graph_x, graph_y, graph_w, graph_h))
        pygame.draw.rect(self.screen, (40, 40, 60), (graph_x, graph_y, graph_w, graph_h), 1)

        # Graph label
        self.screen.blit(
            self.font_small.render("Signal History", True, GREY),
            (graph_x + 4, graph_y + 4)
        )

        history = list(self.df_history)
        if len(history) > 1:
            step = graph_w / DF_HISTORY
            points = []
            for i, val in enumerate(history):
                px = int(graph_x + i * step)
                norm = (val + 100) / 80  # -100 to -20 → 0 to 1
                py = int(graph_y + graph_h - norm * graph_h)
                py = max(graph_y + 2, min(graph_y + graph_h - 2, py))
                points.append((px, py))
            if len(points) > 1:
                pygame.draw.lines(self.screen, color, False, points, 2)

        # Horizontal guide lines on graph
        for dbm, label in [(-80, "-80"), (-65, "-65"), (-50, "-50")]:
            norm = (dbm + 100) / 80
            gy   = int(graph_y + graph_h - norm * graph_h)
            pygame.draw.line(self.screen, (40, 40, 60), (graph_x, gy), (graph_x + graph_w, gy), 1)
            self.screen.blit(
                self.font_small.render(label, True, (50, 50, 70)),
                (graph_x + graph_w - 30, gy - 10)
            )

        self._draw_footer("B/Joy:Back  Start:Reset Peak")
        self._play_geiger_tick(rssi)

    def _draw_ble_df_mode(self):
        self._update_ble_df()
        target = self.ble_df_target
        rssi   = self.ble_df_last
        color  = rssi_color(rssi)

        # Is this a suspicious device?
        is_suspicious = (
            target["vendor"] == "Unknown" or
            target["name"] == "[unnamed]" or
            target["type"] == "BLE Device"
        )

        # Header
        pygame.draw.rect(self.screen, BG_HEADER, (0, 0, 640, 44))
        self.screen.blit(
            self.font_title.render(f"BLE DF: {target['name'][:24]}", True, LOCKED_COL),
            (12, 8)
        )

        # MAC + vendor + suspicious flag
        pygame.draw.rect(self.screen, (25, 20, 10), (0, 44, 640, 24))
        ble_mac_count = len(target.get("macs", [target["mac"]]))
        ble_rotate    = f"  [{ble_mac_count}x MAC]" if ble_mac_count > 1 else ""
        self.screen.blit(
            self.font_small.render(
                f"{target['mac']}{ble_rotate}  {target['vendor']}  {target['type']}",
                True, GREY
            ), (12, 50)
        )
        if is_suspicious:
            self.screen.blit(
                self.font_small.render("⚠ UNKNOWN DEVICE", True, RED),
                (490, 50)
            )

        # Missing warning
        if self.ble_df_missing:
            pygame.draw.rect(self.screen, (60, 10, 10), (0, 68, 640, 36))
            self.screen.blit(
                self.font_main.render(
                    "⚠ TARGET LOST — MAC may have randomized", True, RED
                ), (12, 76)
            )
            y_offset = 108
        else:
            y_offset = 68

        # Big RSSI number
        rssi_str  = f"{rssi} dBm"
        rssi_surf = self.font_huge.render(rssi_str, True, color)
        self.screen.blit(rssi_surf, (320 - rssi_surf.get_width() // 2, y_offset))

        # Large signal bar
        bar_x     = 20
        bar_y     = y_offset + 100
        bar_h     = 36
        bar_max_w = 600
        bar_w     = rssi_bar_width(rssi, max_width=bar_max_w)
        pygame.draw.rect(self.screen, (40, 40, 40), (bar_x, bar_y, bar_max_w, bar_h))
        pygame.draw.rect(self.screen, color, (bar_x, bar_y, bar_w, bar_h))

        # Scale markers
        for dbm, label in [(-80, "-80"), (-65, "-65"), (-50, "-50"), (-35, "-35")]:
            mx = bar_x + rssi_bar_width(dbm, max_width=bar_max_w)
            pygame.draw.line(self.screen, GREY, (mx, bar_y), (mx, bar_y + bar_h), 1)
            self.screen.blit(
                self.font_small.render(label, True, GREY),
                (mx - 10, bar_y + bar_h + 4)
            )

        # Peak + avg + trend
        stats_y = bar_y + bar_h + 24
        pygame.draw.rect(self.screen, (18, 18, 48), (0, stats_y, 640, 36))
        self.screen.blit(
            self.font_main.render(f"PEAK: {self.ble_df_peak} dBm", True, GREEN),
            (20, stats_y + 6)
        )
        self.screen.blit(
            self.font_main.render(f"AVG: {self.ble_df_avg} dBm", True, YELLOW),
            (220, stats_y + 6)
        )
        trend_col = GREEN if "STRONGER" in self.ble_df_trend else RED if "WEAKER" in self.ble_df_trend else GREY
        self.screen.blit(
            self.font_main.render(self.ble_df_trend, True, trend_col),
            (430, stats_y + 6)
        )

        # History graph
        graph_x = 20
        graph_y = stats_y + 44
        graph_w = 600
        graph_h = 480 - graph_y - 44
        if graph_h > 20:
            pygame.draw.rect(self.screen, (18, 18, 40), (graph_x, graph_y, graph_w, graph_h))
            pygame.draw.rect(self.screen, (40, 40, 60), (graph_x, graph_y, graph_w, graph_h), 1)
            self.screen.blit(
                self.font_small.render("Signal History", True, GREY),
                (graph_x + 4, graph_y + 4)
            )

            history = list(self.ble_df_history)
            if len(history) > 1:
                step   = graph_w / DF_HISTORY
                points = []
                for i, val in enumerate(history):
                    px   = int(graph_x + i * step)
                    norm = (val + 100) / 80
                    py   = int(graph_y + graph_h - norm * graph_h)
                    py   = max(graph_y + 2, min(graph_y + graph_h - 2, py))
                    points.append((px, py))
                if len(points) > 1:
                    pygame.draw.lines(self.screen, color, False, points, 2)

            for dbm, label in [(-80, "-80"), (-65, "-65"), (-50, "-50")]:
                norm = (dbm + 100) / 80
                gy   = int(graph_y + graph_h - norm * graph_h)
                pygame.draw.line(
                    self.screen, (40, 40, 60),
                    (graph_x, gy), (graph_x + graph_w, gy), 1
                )
                self.screen.blit(
                    self.font_small.render(label, True, (50, 50, 70)),
                    (graph_x + graph_w - 30, gy - 10)
                )

        self._draw_footer("B/Joy:Back  Start:Reset Peak")

    # ── Phone DF Mode ────────────────────────────────────

    def _draw_phone_df_mode(self):
        self._update_phone_df()
        target = self.phone_df_target
        rssi   = self.phone_df_last
        color  = rssi_color(rssi)
        watch  = bool(target.get("is_watchlisted"))

        # Header
        pygame.draw.rect(self.screen, BG_HEADER, (0, 0, 640, 44))
        title_col = LOCKED_COL if watch else RED
        title     = f"PHONE DF: {target.get('os','?')} {target.get('dev_type','?')[:18]}"
        self.screen.blit(self.font_title.render(title[:42], True, title_col), (12, 8))

        # MAC line — show rotation count and seeking SSID.
        pygame.draw.rect(self.screen, (25, 20, 10), (0, 44, 640, 24))
        mac_count = len(target.get("macs", [target.get("mac", "?")]))
        rotate    = f"  [{mac_count}x MAC]" if mac_count > 1 else ""
        seeking   = target.get("ssid", "<broadcast>")
        if watch and target.get("matched_ssids"):
            seeking = target["matched_ssids"][0]
        self.screen.blit(
            self.font_small.render(
                f"{target.get('mac','?')}{rotate}  seeking:{seeking[:24]}",
                True, GREY
            ), (12, 50)
        )
        if watch:
            self.screen.blit(
                self.font_small.render("⚠ WATCHLIST", True, LOCKED_COL),
                (530, 50)
            )

        # Missing warning — phones may stop probing for 30+ seconds.
        if self.phone_df_missing:
            pygame.draw.rect(self.screen, (60, 10, 10), (0, 68, 640, 36))
            self.screen.blit(
                self.font_main.render(
                    "⚠ TARGET QUIET — phone may have stopped probing", True, RED
                ), (12, 76)
            )
            y_offset = 108
        else:
            y_offset = 68

        # Big RSSI
        rssi_str  = f"{rssi} dBm"
        rssi_surf = self.font_huge.render(rssi_str, True, color)
        self.screen.blit(rssi_surf, (320 - rssi_surf.get_width() // 2, y_offset))

        # Bar
        bar_x, bar_h, bar_max_w = 20, 36, 600
        bar_y = y_offset + 100
        bar_w = rssi_bar_width(rssi, max_width=bar_max_w)
        pygame.draw.rect(self.screen, (40, 40, 40), (bar_x, bar_y, bar_max_w, bar_h))
        pygame.draw.rect(self.screen, color, (bar_x, bar_y, bar_w, bar_h))
        for dbm, label in [(-80, "-80"), (-65, "-65"), (-50, "-50"), (-35, "-35")]:
            mx = bar_x + rssi_bar_width(dbm, max_width=bar_max_w)
            pygame.draw.line(self.screen, GREY, (mx, bar_y), (mx, bar_y + bar_h), 1)
            self.screen.blit(
                self.font_small.render(label, True, GREY),
                (mx - 10, bar_y + bar_h + 4)
            )

        # Peak / avg / trend
        stats_y = bar_y + bar_h + 24
        pygame.draw.rect(self.screen, (18, 18, 48), (0, stats_y, 640, 36))
        self.screen.blit(
            self.font_main.render(f"PEAK: {self.phone_df_peak} dBm", True, GREEN),
            (20, stats_y + 6)
        )
        self.screen.blit(
            self.font_main.render(f"AVG: {self.phone_df_avg} dBm", True, YELLOW),
            (220, stats_y + 6)
        )
        trend_col = GREEN if "STRONGER" in self.phone_df_trend else RED if "WEAKER" in self.phone_df_trend else GREY
        self.screen.blit(
            self.font_main.render(self.phone_df_trend, True, trend_col),
            (430, stats_y + 6)
        )

        # History graph
        graph_x, graph_y = 20, stats_y + 44
        graph_w = 600
        graph_h = 480 - graph_y - 44
        if graph_h > 20:
            pygame.draw.rect(self.screen, (18, 18, 40), (graph_x, graph_y, graph_w, graph_h))
            pygame.draw.rect(self.screen, (40, 40, 60), (graph_x, graph_y, graph_w, graph_h), 1)
            self.screen.blit(
                self.font_small.render("Signal History", True, GREY),
                (graph_x + 4, graph_y + 4)
            )
            history = list(self.phone_df_history)
            if len(history) > 1:
                step   = graph_w / DF_HISTORY
                points = []
                for i, val in enumerate(history):
                    px   = int(graph_x + i * step)
                    norm = (val + 100) / 80
                    py   = int(graph_y + graph_h - norm * graph_h)
                    py   = max(graph_y + 2, min(graph_y + graph_h - 2, py))
                    points.append((px, py))
                if len(points) > 1:
                    pygame.draw.lines(self.screen, color, False, points, 2)
            for dbm, label in [(-80, "-80"), (-65, "-65"), (-50, "-50")]:
                norm = (dbm + 100) / 80
                gy   = int(graph_y + graph_h - norm * graph_h)
                pygame.draw.line(
                    self.screen, (40, 40, 60),
                    (graph_x, gy), (graph_x + graph_w, gy), 1
                )
                self.screen.blit(
                    self.font_small.render(label, True, (50, 50, 70)),
                    (graph_x + graph_w - 30, gy - 10)
                )

        self._draw_footer("B/Joy:Back  Start:Reset Peak")
        self._play_geiger_tick(rssi)

    # ── BLE list ─────────────────────────────────────────

    def _draw_ble_list(self):
        sort_key = "name" if SORTS[self.sort_idx] == "ssid" else "rssi"
        if self.ble_frozen:
            devs = self.ble_frozen_list
        else:
            devs = self.ble.get_devices(sort_by=sort_key)

        freeze_str = "❚❚FROZEN" if self.ble_frozen else ""
        self._draw_topbar(
            right_text=f"Sort:{SORTS[self.sort_idx].upper()}  {len(devs)} devices  {freeze_str}"
        )
        pygame.draw.rect(self.screen, (18, 18, 48), (0, 44, 640, 22))
        self.screen.blit(
            self.font_small.render("X:Sort", True, (60, 60, 80)), (8, 48)
        )

        ROW_H   = 70
        VISIBLE = 5

        if not devs:
            self.screen.blit(
                self.font_main.render("Scanning for BLE devices...", True, GREY),
                (155, 250)
            )
        else:
            visible = devs[self.scroll: self.scroll + VISIBLE]
            for i, dev in enumerate(visible):
                y      = 68 + i * ROW_H
                abs_i  = self.scroll + i
                is_sel = (abs_i == self.selected)

                pygame.draw.rect(
                    self.screen, BG_SEL if is_sel else BG_ROW,
                    (0, y, 640, ROW_H - 2)
                )
                if is_sel:
                    pygame.draw.rect(self.screen, CYAN, (0, y, 5, ROW_H - 2))

                self.screen.blit(
                    self.font_main.render(dev["name"][:28], True, WHITE if is_sel else GREY),
                    (12, y + 5)
                )
                self.screen.blit(
                    self.font_small.render(
                        f"{dev['type']}  ·  {dev['vendor']}", True, CYAN
                    ), (12, y + 34)
                )
                mac_count = len(dev.get("macs", [dev["mac"]]))
                rotate    = f"  [{mac_count}x MAC]" if mac_count > 1 else ""
                self.screen.blit(
                    self.font_small.render(
                        f"{dev['mac']}{rotate}",
                        True, (60, 60, 80)
                    ),
                    (12, y + 52)
                )
                self.screen.blit(
                    self.font_rssi.render(
                        f"{dev['rssi']}dBm", True, rssi_color(dev["rssi"])
                    ), (490, y + 5)
                )
                draw_signal_bars(self.screen, 580, y + 8, dev["rssi"], height=30)

        self._draw_footer("↕:Scroll  X:Sort  B:DF  Y:Tab  Sel:Freeze")

    # ── Phones tab ───────────────────────────────────────

    def _draw_phones_list(self):
        probes = self.scanner.get_probes(phones_only=True)
        n_phones    = sum(1 for p in probes if p.get("is_phone"))
        n_watchlist = sum(1 for p in probes if p.get("is_watchlisted"))
        self._draw_topbar(
            right_text=f"{n_phones} PHONES  {n_watchlist} WATCH"
        )

        pygame.draw.rect(self.screen, (40, 8, 8), (0, 44, 640, 22))
        self.screen.blit(
            self.font_small.render(
                "Live phone probes - watchlist first, then by signal", True, ORANGE
            ), (8, 48)
        )

        ROW_H   = 70
        VISIBLE = 5

        if not probes:
            self.screen.blit(
                self.font_main.render("No phone probes detected.", True, GREY),
                (155, 240)
            )
            self.screen.blit(
                self.font_small.render(
                    "Phones probe heavily on 5GHz - verify wlan1 is dual-band.",
                    True, (90, 90, 110)
                ),
                (90, 274)
            )
        else:
            visible = probes[self.scroll: self.scroll + VISIBLE]
            for i, pr in enumerate(visible):
                y      = 68 + i * ROW_H
                abs_i  = self.scroll + i
                is_sel = (abs_i == self.selected)
                watch  = pr.get("is_watchlisted")

                # Watchlist hits get a yellow accent stripe so they're
                # distinguishable from regular phone detections at a glance.
                row_bg = (50, 30, 0) if watch else ((40, 8, 8) if pr.get("is_phone") else BG_ROW)
                if is_sel:
                    row_bg = BG_SEL
                pygame.draw.rect(self.screen, row_bg, (0, y, 640, ROW_H - 2))
                stripe = LOCKED_COL if watch else (RED if pr.get("is_phone") else CYAN)
                pygame.draw.rect(self.screen, stripe, (0, y, 5, ROW_H - 2))

                if watch:
                    tag = "[WATCH] "
                elif pr.get("is_phone"):
                    tag = "[PHONE] "
                else:
                    tag = ""

                top_col = LOCKED_COL if watch else (RED if pr.get("is_phone") else WHITE)
                self.screen.blit(
                    self.font_main.render(
                        f"{tag}{pr.get('os','?')}  {pr.get('dev_type','?')[:24]}",
                        True, top_col
                    ), (12, y + 5)
                )

                mac_count = len(pr.get("macs", [pr["mac"]]))
                rotate    = f"  [{mac_count}x MAC]" if mac_count > 1 else ""
                seeking   = pr.get("ssid", "<broadcast>")
                if watch and pr.get("matched_ssids"):
                    seeking = pr["matched_ssids"][0]
                self.screen.blit(
                    self.font_small.render(
                        f"{pr['mac']}{rotate}", True, GREY
                    ), (12, y + 34)
                )
                self.screen.blit(
                    self.font_small.render(
                        f"seeking: {seeking[:34]}", True, (90, 90, 110)
                    ), (12, y + 52)
                )
                self.screen.blit(
                    self.font_rssi.render(
                        f"{pr['rssi']}dBm", True, rssi_color(pr["rssi"])
                    ), (490, y + 5)
                )
                draw_signal_bars(self.screen, 580, y + 8, pr["rssi"], height=30)

        self._draw_footer("up/dn:Scroll  B:DF  Y:Tab  Edit ssid_watchlist.txt to tune")

    # ── Cell tab ─────────────────────────────────────────

    def _draw_cell_list(self):
        sstatus = self.sdr.status()
        cells   = self.sdr.get_cells() if sstatus != "absent" else []

        if sstatus == "scanning":
            label = "SCANNING"
        elif sstatus == "present":
            label = "NO CAPTURE"
        else:
            label = "NO SDR"
        self._draw_topbar(right_text=f"{label}  {len(cells)}c")

        if sstatus == "absent":
            pygame.draw.rect(self.screen, (40, 8, 8), (0, 44, 640, 22))
            self.screen.blit(
                self.font_small.render("RTL-SDR v4 not detected on USB.", True, ORANGE),
                (8, 48)
            )
            lines = [
                "Plug in the RTL-SDR v4 (Realtek RTL2832U) and re-launch.",
                "",
                "Mission: rogue base station detection in non-SCIF spaces",
                "  - LTE cell discovery via srsRAN cell_search + SIB1 decode",
                "  - 2G cell enum via grgsm_scanner (catches downgrade attacks)",
                "  - OpenCellID US snapshot as the legitimacy baseline (stage 3)",
                "",
                "Once the dongle is in, run tools/setup_sdr.sh to install",
                "srsRAN + gr-gsm + RTL-SDR udev rules.",
            ]
            y = 90
            for line in lines:
                self.screen.blit(self.font_small.render(line, True, GREY), (24, y))
                y += 22
            self._draw_footer("Y:Tab")
            return

        if sstatus == "present":
            # RTL-SDR plugged in but the capture loop never produced a
            # cell — most likely because grgsm_scanner / cell_search
            # aren't on PATH yet.
            pygame.draw.rect(self.screen, (50, 30, 0), (0, 44, 640, 22))
            self.screen.blit(
                self.font_small.render(
                    "RTL-SDR detected. Capture binaries missing or no cells yet — run tools/setup_sdr.sh.",
                    True, LOCKED_COL
                ),
                (8, 48)
            )
        else:
            # scanning
            pygame.draw.rect(self.screen, (0, 30, 10), (0, 44, 640, 22))
            self.screen.blit(
                self.font_small.render(
                    "Cycling US LTE + GSM bands. Risk scoring (stage 3) not yet active.",
                    True, GREEN
                ),
                (8, 48)
            )

        if not cells:
            self.screen.blit(
                self.font_main.render("Awaiting first cell observation...", True, GREY),
                (140, 240)
            )
            self.screen.blit(
                self.font_small.render(
                    "Band cycle takes ~2 minutes per pass.",
                    True, (90, 90, 110)
                ),
                (170, 274)
            )
        else:
            ROW_H   = 70
            VISIBLE = 5
            visible = cells[self.scroll: self.scroll + VISIBLE]
            for i, cell in enumerate(visible):
                y      = 68 + i * ROW_H
                abs_i  = self.scroll + i
                is_sel = (abs_i == self.selected)
                risk   = cell.get("risk", 0)
                # Higher-risk cells get a louder colour grammar — matches
                # the watchlist/phone pattern from the Wi-Fi side.
                stripe = RED if risk >= 70 else (LOCKED_COL if risk >= 30 else CYAN)
                pygame.draw.rect(
                    self.screen, BG_SEL if is_sel else BG_ROW,
                    (0, y, 640, ROW_H - 2)
                )
                pygame.draw.rect(self.screen, stripe, (0, y, 5, ROW_H - 2))
                top_col = RED if risk >= 70 else (WHITE if is_sel else GREY)
                self.screen.blit(
                    self.font_main.render(
                        f"{cell.get('tech','?')} {cell.get('mcc','?')}-{cell.get('mnc','?')}  "
                        f"cell {cell.get('cell_id','?')}",
                        True, top_col
                    ),
                    (12, y + 5)
                )
                self.screen.blit(
                    self.font_small.render(
                        f"PCI:{cell.get('pci','?')}  EARFCN:{cell.get('earfcn','?')}  "
                        f"TAC:{cell.get('tac','?')}  risk:{risk}",
                        True, CYAN
                    ),
                    (12, y + 34)
                )
                self.screen.blit(
                    self.font_rssi.render(
                        f"{cell.get('rssi', -120)}dBm",
                        True, rssi_color(cell.get("rssi", -120))
                    ),
                    (490, y + 5)
                )
                draw_signal_bars(self.screen, 580, y + 8, cell.get("rssi", -120), height=30)

        self._draw_footer("Y:Tab")

    # ── Zigbee tab ───────────────────────────────────────

    def _draw_zigbee_list(self):
        zstatus = self.zigbee.status()
        devs    = self.zigbee.get_devices() if zstatus == "sniffer" else []
        # Don't say "READY" while the capture path is stubbed — operators
        # would assume Zigbee is being captured and miss real intrusions.
        if zstatus == "sniffer":
            label = "FW OK / NO CAPTURE"
        elif zstatus == "ble_sniffer":
            label = "BLE SNIFFER FW"
        elif zstatus == "bootloader":
            label = "NEEDS FLASH"
        else:
            label = "NO DONGLE"
        self._draw_topbar(right_text=f"{label}  {len(devs)}d")

        if zstatus == "absent":
            pygame.draw.rect(self.screen, (40, 8, 8), (0, 44, 640, 22))
            self.screen.blit(
                self.font_small.render("nRF52840 dongle not detected on USB.", True, ORANGE),
                (8, 48)
            )
            lines = [
                "Plug in the Raytac MDBT50Q-CX (nRF52840) and re-launch.",
                "",
                "When the firmware is flashed:",
                "  - nRF Sniffer for 802.15.4 -> Zigbee/Thread",
                "  - or Sniffle -> BLE 5 long-range capture",
                "",
                "See zigbee_scanner.py for the integration TODO.",
            ]
            y = 90
            for line in lines:
                self.screen.blit(self.font_small.render(line, True, GREY), (24, y))
                y += 26
            self._draw_footer("Y:Tab")
            return

        if zstatus == "bootloader":
            pygame.draw.rect(self.screen, (50, 30, 0), (0, 44, 640, 22))
            self.screen.blit(
                self.font_small.render(
                    "Dongle present but in bootloader - flash nRF Sniffer firmware.",
                    True, LOCKED_COL
                ),
                (8, 48)
            )
            lines = [
                "1. Drop the firmware HEX at:",
                "   tools/firmware/nrf_sniffer.hex",
                "   (raw HEX from NordicSemiconductor/nRF-Sniffer-for-802.15.4)",
                "",
                "2. sudo bash tools/flash_nrf_sniffer.sh",
                "",
                "3. After flash, re-plug the dongle and return to this tab.",
                "",
                "(.zip DFU package also accepted. See --help for details.)",
            ]
            y = 90
            for line in lines:
                self.screen.blit(self.font_small.render(line, True, GREY), (24, y))
                y += 26
            self._draw_footer("Y:Tab")
            return

        if zstatus == "ble_sniffer":
            pygame.draw.rect(self.screen, (50, 30, 0), (0, 44, 640, 22))
            self.screen.blit(
                self.font_small.render(
                    "Dongle has nRF Sniffer for Bluetooth LE - reflash for Zigbee.",
                    True, LOCKED_COL
                ),
                (8, 48)
            )
            lines = [
                "Current firmware sniffs BLE link-layer (Wireshark-only, not used",
                "by Doperscope today). To capture Zigbee/Thread you need to",
                "reflash with nRF Sniffer for 802.15.4:",
                "",
                "1. Drop the firmware HEX at:",
                "   tools/firmware/nrf_sniffer.hex",
                "",
                "2. sudo bash tools/flash_nrf_sniffer.sh",
                "",
                "Reflashing is reversible if you want to swap back later.",
            ]
            y = 90
            for line in lines:
                self.screen.blit(self.font_small.render(line, True, GREY), (24, y))
                y += 22
            self._draw_footer("Y:Tab")
            return

        # zstatus == "sniffer"
        pygame.draw.rect(self.screen, (50, 30, 0), (0, 44, 640, 22))
        self.screen.blit(
            self.font_small.render(
                "Sniffer firmware OK - but Doperscope's tshark integration is NOT yet active.",
                True, LOCKED_COL
            ),
            (8, 48)
        )

        if not devs:
            self.screen.blit(
                self.font_main.render("Awaiting first Zigbee/Thread frame...", True, GREY),
                (115, 240)
            )
            self.screen.blit(
                self.font_small.render(
                    "If this stays empty after flashing: tshark -i nrfsniffer to debug.",
                    True, (90, 90, 110)
                ),
                (60, 274)
            )
        else:
            ROW_H   = 70
            VISIBLE = 5
            visible = devs[self.scroll: self.scroll + VISIBLE]
            for i, dev in enumerate(visible):
                y      = 68 + i * ROW_H
                abs_i  = self.scroll + i
                is_sel = (abs_i == self.selected)
                pygame.draw.rect(
                    self.screen, BG_SEL if is_sel else BG_ROW,
                    (0, y, 640, ROW_H - 2)
                )
                if is_sel:
                    pygame.draw.rect(self.screen, CYAN, (0, y, 5, ROW_H - 2))
                self.screen.blit(
                    self.font_main.render(
                        (dev.get("name") or "<unnamed>")[:28], True,
                        WHITE if is_sel else GREY
                    ), (12, y + 5)
                )
                self.screen.blit(
                    self.font_small.render(
                        f"PAN:{dev.get('pan_id','?')}  ch{dev.get('channel','?')}  "
                        f"{dev.get('addr','?')}",
                        True, CYAN
                    ), (12, y + 34)
                )
                self.screen.blit(
                    self.font_rssi.render(
                        f"{dev.get('rssi', -100)}dBm",
                        True, rssi_color(dev.get("rssi", -100))
                    ), (490, y + 5)
                )
                draw_signal_bars(self.screen, 580, y + 8, dev.get("rssi", -100), height=30)

        self._draw_footer("Y:Tab")

    # ── Alert log tab ────────────────────────────────────

    def _draw_log_list(self):
        if self.log_view == "sweeps":
            self._draw_sweeps_view()
            return
        alerts = self.persistence.get_recent_alerts(limit=200)
        n = len(alerts)
        self._draw_topbar(right_text=f"{n} alerts")

        pygame.draw.rect(self.screen, (40, 8, 8), (0, 44, 640, 22))
        self.screen.blit(
            self.font_small.render(
                "Alerts (most recent first)  — X: switch to Sweeps", True, ORANGE
            ), (8, 48)
        )

        ROW_H   = 50
        VISIBLE = 7

        if not alerts:
            self.screen.blit(
                self.font_main.render("No alerts logged yet.", True, GREY),
                (190, 240)
            )
            self.screen.blit(
                self.font_small.render(
                    "Alerts land here on phone / watchlist / rogue-cell events.",
                    True, (90, 90, 110)
                ),
                (60, 274)
            )
            self._draw_footer("Y:Tab")
            return

        # Clamp selection to the visible window.
        if self.selected >= len(alerts):
            self.selected = len(alerts) - 1
        if self.selected < self.scroll:
            self.scroll = self.selected
        if self.selected >= self.scroll + VISIBLE:
            self.scroll = self.selected - VISIBLE + 1

        visible = alerts[self.scroll: self.scroll + VISIBLE]
        for i, a in enumerate(visible):
            y      = 68 + i * ROW_H
            abs_i  = self.scroll + i
            is_sel = (abs_i == self.selected)
            kind   = a.get("kind") or "?"

            if kind == "watchlist":
                tag, stripe = "[WATCH] ", LOCKED_COL
            elif kind in ("wifi_probe", "wifi_ap"):
                tag, stripe = "[PHONE] ", RED
            elif kind == "ble":
                tag, stripe = "[BLE] ", CYAN
            elif kind == "cell":
                tag, stripe = "[ROGUE CELL] ", RED
            else:
                tag, stripe = "", GREY

            row_bg = BG_SEL if is_sel else BG_ROW
            pygame.draw.rect(self.screen, row_bg, (0, y, 640, ROW_H - 2))
            pygame.draw.rect(self.screen, stripe, (0, y, 5, ROW_H - 2))

            ts_str = time.strftime("%H:%M:%S", time.localtime(a.get("ts", 0)))
            mac    = a.get("mac")  or "?"
            os_    = a.get("os")   or "?"
            ssid   = a.get("ssid") or ""
            rssi   = a.get("rssi", -100)

            # Cell alerts don't have a MAC; the fingerprint is the unique
            # identifier the operator cares about ("cell:LTE-310-260-1234").
            if kind == "cell":
                primary = a.get("fingerprint") or "?"
                header  = f"{ts_str}  {tag}{primary}"
            else:
                header  = f"{ts_str}  {tag}{os_}  {mac}"
            self.screen.blit(
                self.font_small.render(
                    header,
                    True, WHITE if is_sel else GREY
                ),
                (12, y + 4)
            )
            detail = a.get("dev_type") or ""
            if ssid:
                detail = f"{detail}  ssid:{ssid[:22]}"
            self.screen.blit(
                self.font_small.render(detail[:60], True, (90, 90, 110)),
                (12, y + 24)
            )
            self.screen.blit(
                self.font_rssi.render(f"{rssi}dBm", True, rssi_color(rssi)),
                (530, y + 8)
            )

        self._draw_footer("up/dn:Scroll  X:Sweeps  B:Toggle Sweep  Y:Tab")

    # ── Sweeps subview ───────────────────────────────────

    def _draw_sweeps_view(self):
        sweeps = self.persistence.list_sweeps(limit=50)
        active = self.persistence.is_sweep_active()
        self._draw_topbar(right_text=f"{len(sweeps)} sweeps")

        pygame.draw.rect(self.screen, (40, 8, 8), (0, 44, 640, 22))
        hint = ("Sweep ACTIVE — B to STOP  ·  X: switch to Alerts"
                if active else
                "B: START SWEEP  ·  X: switch to Alerts")
        self.screen.blit(
            self.font_small.render(hint, True, ORANGE if active else GREY),
            (8, 48)
        )

        ROW_H   = 50
        VISIBLE = 7

        if not sweeps:
            self.screen.blit(
                self.font_main.render("No sweeps recorded.", True, GREY),
                (200, 240)
            )
            self.screen.blit(
                self.font_small.render(
                    "Press B to begin a sweep. Walk the room. Press B again to end.",
                    True, (90, 90, 110)
                ),
                (50, 274)
            )
            self._draw_footer("B:Start Sweep  X:Alerts  Y:Tab")
            return

        if self.selected >= len(sweeps):
            self.selected = len(sweeps) - 1
        if self.selected < self.scroll:
            self.scroll = self.selected
        if self.selected >= self.scroll + VISIBLE:
            self.scroll = self.selected - VISIBLE + 1

        visible = sweeps[self.scroll: self.scroll + VISIBLE]
        for i, sw in enumerate(visible):
            y      = 68 + i * ROW_H
            abs_i  = self.scroll + i
            is_sel = (abs_i == self.selected)

            row_bg = BG_SEL if is_sel else BG_ROW
            pygame.draw.rect(self.screen, row_bg, (0, y, 640, ROW_H - 2))
            stripe = RED if sw["active"] else (LOCKED_COL if sw["watch_hits"] else CYAN)
            pygame.draw.rect(self.screen, stripe, (0, y, 5, ROW_H - 2))

            start_str = time.strftime("%m-%d %H:%M:%S", time.localtime(sw["start_ts"]))
            if sw["active"]:
                dur = max(0, int(time.time() - sw["start_ts"]))
                dur_str = "ACTIVE"
            elif sw["end_ts"]:
                dur = int(sw["end_ts"] - sw["start_ts"])
                mm, ss = divmod(dur, 60)
                dur_str = f"{mm}:{ss:02d}"
            else:
                # Crashed mid-sweep: no end_ts. Treat duration as unknown.
                dur_str = "—"

            top_col = WHITE if is_sel else (RED if sw["active"] else GREY)
            self.screen.blit(
                self.font_small.render(
                    f"#{sw['id']}  {start_str}  ({dur_str})",
                    True, top_col
                ),
                (12, y + 4)
            )
            phone_col = RED if sw["phones_seen"] else GREY
            watch_col = LOCKED_COL if sw["watch_hits"] else GREY
            self.screen.blit(
                self.font_small.render(
                    f"{sw['devices_seen']} dev  ·  ", True, GREY
                ),
                (12, y + 24)
            )
            self.screen.blit(
                self.font_small.render(
                    f"{sw['phones_seen']} phones",
                    True, phone_col
                ),
                (130, y + 24)
            )
            self.screen.blit(
                self.font_small.render(
                    f"  ·  {sw['watch_hits']} watch",
                    True, watch_col
                ),
                (260, y + 24)
            )

        self._draw_footer("A:Open  up/dn:Scroll  B:Toggle Sweep  X:Alerts  Y:Tab")

    # ── Sweep detail drill-down ──────────────────────────

    def _draw_sweep_detail(self):
        sid = self.sweep_detail_id
        sweep = self.persistence.get_sweep(sid) if sid is not None else None
        if not sweep:
            # Sweep id no longer resolvable (deleted, db error). Bail out.
            self.view = "ap_list"
            self.sweep_detail_id = None
            return

        observations = self.persistence.get_sweep_observations(sid)

        # Header band
        pygame.draw.rect(self.screen, BG_HEADER, (0, 0, 640, 44))
        title = f"SWEEP #{sweep['id']}"
        if sweep["active"]:
            title += " ● LIVE"
        self.screen.blit(self.font_title.render(title, True, LOCKED_COL), (12, 8))

        start_str = time.strftime("%m-%d %H:%M:%S", time.localtime(sweep["start_ts"]))
        if sweep["active"]:
            dur = max(0, int(time.time() - sweep["start_ts"]))
        elif sweep["end_ts"]:
            dur = int(sweep["end_ts"] - sweep["start_ts"])
        else:
            dur = 0
        mm, ss = divmod(dur, 60)
        meta = f"{start_str}  ·  {mm}:{ss:02d}  ·  {len(observations)} dev"
        self.screen.blit(self.font_small.render(meta, True, GREY), (320, 18))

        # Counts band
        pygame.draw.rect(self.screen, (25, 20, 10), (0, 44, 640, 24))
        phone_col = RED if sweep["phones_seen"] else GREY
        watch_col = LOCKED_COL if sweep["watch_hits"] else GREY
        self.screen.blit(self.font_small.render(
            f"{sweep['devices_seen']} devices", True, GREY), (12, 50))
        self.screen.blit(self.font_small.render(
            f"·  {sweep['phones_seen']} phones", True, phone_col), (140, 50))
        self.screen.blit(self.font_small.render(
            f"·  {sweep['watch_hits']} watchlist hits", True, watch_col), (300, 50))

        ROW_H   = 50
        VISIBLE = 7

        if not observations:
            self.screen.blit(
                self.font_main.render("No observations captured.", True, GREY),
                (170, 240)
            )
            self._draw_footer("Joy/Start:Back")
            return

        if self.selected >= len(observations):
            self.selected = len(observations) - 1
        if self.selected < self.scroll:
            self.scroll = self.selected
        if self.selected >= self.scroll + VISIBLE:
            self.scroll = self.selected - VISIBLE + 1

        visible = observations[self.scroll: self.scroll + VISIBLE]
        for i, ob in enumerate(visible):
            y      = 68 + i * ROW_H
            abs_i  = self.scroll + i
            is_sel = (abs_i == self.selected)

            kind = ob["kind"]
            if ob["is_watch"]:
                tag, stripe = "[WATCH] ", LOCKED_COL
                top_col = LOCKED_COL
            elif ob["is_phone"]:
                tag, stripe = "[PHONE] ", RED
                top_col = RED
            elif kind == "ble":
                tag, stripe = "[BLE] ", CYAN
                top_col = WHITE if is_sel else GREY
            elif kind == "wifi_ap":
                tag, stripe = "[AP] ", CYAN
                top_col = WHITE if is_sel else GREY
            else:
                tag, stripe = "[?] ", GREY
                top_col = WHITE if is_sel else GREY

            row_bg = BG_SEL if is_sel else BG_ROW
            pygame.draw.rect(self.screen, row_bg, (0, y, 640, ROW_H - 2))
            pygame.draw.rect(self.screen, stripe, (0, y, 5, ROW_H - 2))

            label = ob.get("label") or ob["key"][:24]
            os_   = ob.get("os")    or ""
            top_str = f"{tag}{os_}  {label[:30]}".strip()
            self.screen.blit(
                self.font_small.render(top_str[:60], True, top_col),
                (12, y + 4)
            )

            dev_type = ob.get("dev_type") or kind
            self.screen.blit(
                self.font_small.render(
                    f"{dev_type[:24]}  ·  {ob['hits']} hits  ·  {ob['key'][:20]}",
                    True, (90, 90, 110)
                ),
                (12, y + 24)
            )
            self.screen.blit(
                self.font_rssi.render(
                    f"{ob['rssi_max']}dBm", True, rssi_color(ob["rssi_max"])
                ),
                (530, y + 8)
            )

        self._draw_footer("up/dn:Scroll  X:Export CSV  Joy/Start:Back")

    # ── Main render loop ─────────────────────────────────

    def _poll_alerts(self):
        for alert in self.persistence.pop_new_phone_alerts():
            self.alert_until = time.time() + ALERT_FLASH_S
            mac = alert.get("mac") or "?"
            os_ = alert.get("os")  or "?"
            kind = alert.get("kind")
            if kind == "watchlist":
                ssid = alert.get("ssid") or "?"
                self.alert_text = f"WATCHLIST HIT  '{ssid}'  {mac}"
            elif kind == "cell":
                # Cell alerts use the dev_type field for "Cell:LTE risk:N"
                # and ssid for the comma-joined reasons. Surface the
                # fingerprint so the operator can cross-ref the Cell tab.
                fp = alert.get("fingerprint") or "?"
                reasons = alert.get("ssid") or ""
                short = reasons.split(",")[0] if reasons else "rogue"
                self.alert_text = f"ROGUE CELL  {fp}  ({short})"
            else:
                self.alert_text = f"PHONE DETECTED  {os_}  {mac}"
            if self.tick_sound:
                try:
                    self.tick_sound.play()
                except Exception:
                    pass

    def _draw_alert_banner(self):
        if time.time() >= self.alert_until:
            return
        # Pulse so it's hard to miss in a sweep. Green for benign status
        # (export succeeded), red for everything else (phone / watchlist /
        # export failure). The text itself already conveys which one.
        pulse = int((time.time() * 4) % 2)
        if self.alert_text.startswith("EXPORTED"):
            col = (40, 200, 80) if pulse else (10, 140, 50)
        else:
            col = (255, 30, 30) if pulse else (200, 0, 0)
        pygame.draw.rect(self.screen, col, (0, 0, 640, 44))
        txt = self.font_main.render(self.alert_text[:60], True, WHITE)
        self.screen.blit(txt, (10, 10))

    def _render(self):
        self.screen.fill(BG)
        self._poll_alerts()
        if self.view == "df_mode" and self.locked:
            self._draw_df_mode()
        elif self.view == "ble_df_mode" and self.ble_df_target:
            self._draw_ble_df_mode()
        elif self.view == "phone_df_mode" and self.phone_df_target:
            self._draw_phone_df_mode()
        elif self.view == "sweep_detail" and self.sweep_detail_id is not None:
            self._draw_sweep_detail()
        elif self.view == "client_list" and self.locked:
            self._draw_client_list()
        elif self.tab == TAB_BLE:
            self._draw_ble_list()
        elif self.tab == TAB_PHONES:
            self._draw_phones_list()
        elif self.tab == TAB_CELL:
            self._draw_cell_list()
        elif self.tab == TAB_ZIGBEE:
            self._draw_zigbee_list()
        elif self.tab == TAB_LOG:
            self._draw_log_list()
        else:
            self._draw_ap_list()
        # Drawn last so it overlays whatever view is active.
        self._draw_alert_banner()
        pygame.display.flip()
        if self.fb is None:
            return
        # tobytes is the modern API; tostring was deprecated in pygame 2.1.3.
        # Fall back to tostring for older pygame on legacy installs.
        try:
            raw = pygame.image.tobytes(self.screen, "BGRA")
        except AttributeError:
            raw = pygame.image.tostring(self.screen, "BGRA")
        self.fb.seek(0)
        self.fb.write(raw)


    def _process_events(self):
        try:
            while True:
                event = self._event_queue.get_nowait()
                if event == "up":       self._scroll_up()
                elif event == "down":   self._scroll_down()
                elif event == "left":   self._cycle_wifi_filter()
                elif event == "right":  self._cycle_wifi_filter()
                elif event == "a":      self._action_a()
                elif event == "b":      self._action_b()
                elif event == "x":      self._cycle_sort()
                elif event == "y":      self._action_y()
                elif event == "select": self._action_select()
                elif event == "start":  self._action_start()
                elif event == "joy":    self._action_joy()
        except queue.Empty:
            pass

    def _install_signal_handlers(self):
        # systemd's `systemctl stop` sends SIGTERM, which Python doesn't
        # auto-translate to KeyboardInterrupt. Without this handler the
        # finally block in run() may not execute, leaving an active
        # sweep orphaned with no end_ts. Both SIGTERM and SIGINT now
        # raise KeyboardInterrupt so the existing shutdown path runs.
        def _raise_interrupt(signum, frame):
            raise KeyboardInterrupt(f"signal {signum}")
        try:
            signal.signal(signal.SIGTERM, _raise_interrupt)
            signal.signal(signal.SIGHUP,  _raise_interrupt)
        except (ValueError, OSError):
            # Non-main-thread or unsupported platform; skip silently.
            pass

    def run(self):
        self._install_signal_handlers()
        try:
            while True:
                self._process_events()
                self._render()
                # Render at 20 FPS for live views (DF graphs, alert
                # banners, sweep timer); throttle to 10 FPS in calmer
                # views where the screen barely changes. Drops idle CPU
                # by half on a Pi 4B without affecting reaction time
                # for the views that need it.
                fast = (
                    self.view in ("df_mode", "ble_df_mode", "phone_df_mode")
                    or time.time() < self.alert_until
                    or self.persistence.is_sweep_active()
                )
                time.sleep(0.05 if fast else 0.1)
        except KeyboardInterrupt:
            pass
        finally:
            if self.fb is not None:
                self.fb.close()
            self.scanner.stop()
            self.ble.stop()
            self.zigbee.stop()
            self.sdr.stop()
            self.persistence.stop()
            self.inp.cleanup()
            pygame.quit()


if __name__ == "__main__":
    app = Doperscope()
    app.run()
