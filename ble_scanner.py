import asyncio
import threading
import time
from bleak import BleakScanner

# BLE Company ID lookup (subset of Bluetooth SIG assigned numbers)
COMPANY_TABLE = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0499: "Ruuvi",
    0x0059: "Nordic Semi",
    0x0157: "Tile",
    0x0171: "Amazon",
    0x0087: "Garmin",
    0x00D2: "Bose",
    0x0010: "Qualcomm",
    0x0000: "Ericsson",
    0x0001: "Nokia",
    0x0002: "Intel",
    0x0003: "IBM",
    0x0004: "Toshiba",
    0x0005: "3Com",
    0x0008: "Motorola",
    0x001D: "Qualcomm",
    0x0046: "Motorola",
    0x0047: "Apple",
    0x004D: "Lego",
    0x006B: "Garmin",
    0x0089: "Plantronics",
    0x008A: "Pioneer",
    0x008B: "Pioneer",
    0x00AC: "Harman",
    0x00D7: "Sony",
    0x00CD: "Beats",
    0x01D9: "Xiaomi",
    0x038F: "Fitbit",
    0x0397: "Fitbit",
    0x0310: "Nymi",
    0x02E5: "Anhui",
}

def get_ble_vendor(manufacturer_data):
    """Extract vendor from BLE manufacturer data."""
    if not manufacturer_data:
        return "Unknown"
    company_id = list(manufacturer_data.keys())[0]
    return COMPANY_TABLE.get(company_id, f"ID:0x{company_id:04X}")

def classify_device(name, manufacturer_data):
    """Try to classify what kind of device this is."""
    if not manufacturer_data:
        return "BLE Device"
    company_id = list(manufacturer_data.keys())[0]
    if company_id == 0x004C:
        data = manufacturer_data[0x004C]
        if len(data) >= 2:
            subtype = data[0]
            if subtype == 0x02:   return "iBeacon"
            if subtype == 0x05:   return "AirDrop"
            if subtype == 0x07:   return "AirPods"
            if subtype == 0x09:   return "AirPods"
            if subtype == 0x0A:   return "iPhone"
            if subtype == 0x0B:   return "Apple Watch"
            if subtype == 0x0C:   return "MacBook"
            if subtype == 0x10:   return "iPhone"
            if subtype == 0x12 and len(data) == 25: return "AirTag"
            if subtype == 0x12:   return "MacBook"
        return "Apple Device"
    if company_id == 0x0006:      return "Microsoft Device"
    if company_id == 0x0075:      return "Samsung Device"
    if company_id == 0x00E0:      return "Google Device"
    if company_id == 0x0171:      return "Amazon Device"
    return "BLE Device"


class BLEScanner:
    def __init__(self):
        # Keyed by fingerprint when one is meaningful, otherwise by MAC.
        # See _store_advert for the rule.
        self.devices = {}
        self._lock    = threading.Lock()
        self._running = False
        self._thread  = None
        self._loop    = None
        # Health counters — same shape as WiFiScanner so the UI can
        # treat them uniformly.
        self.error_count    = 0
        self.last_packet_ts = 0.0

    def _get_fingerprint(self, name, mfr_data, services):
        """Stable signature used to track devices through MAC rotations.
        Composed of manufacturer data + service UUIDs only. The device
        name is intentionally excluded — users rename their AirPods,
        Apple Watch, etc., and a rename shouldn't fork tracking into
        two ghosts. The trivial-fingerprint sentinel
        (no mfr + no services) is still preserved by including the
        empty-string structure so _is_trivial_fp's check still matches."""
        mfr_str = ""
        if mfr_data:
            for k, v in sorted(mfr_data.items()):
                try:
                    # Convert byte arrays to hex strings for safe hashing
                    mfr_str += f"{k}:{v.hex()}|"
                except Exception:
                    pass
        svc_str = ",".join(sorted(services))
        return f"mfr:{mfr_str}::svc:{svc_str}"

    @staticmethod
    def _is_trivial_fp(name, mfr_data, services):
        """A fingerprint is trivial when neither manufacturer data nor
        services are present. We used to also check name, but the
        fingerprint formula no longer includes it (users rename their
        devices), so any name-only differentiation between devices
        would collide on the same fingerprint string. Trivial entries
        are keyed by MAC so they don't collapse together."""
        return not mfr_data and not services

    def _detection_callback(self, device, advertisement_data):
        try:
            rssi   = advertisement_data.rssi if advertisement_data.rssi else -100
            name   = device.name or "[unnamed]"
            mac    = device.address
            mfr    = advertisement_data.manufacturer_data or {}
            vendor = get_ble_vendor(mfr)
            dtype  = classify_device(name, mfr)
            svcs   = list(advertisement_data.service_uuids or [])
            fp     = self._get_fingerprint(name, mfr, svcs)
            now    = time.time()

            # Devices with a real fingerprint collapse across MAC rotation;
            # devices that broadcast nothing identifiable stay per-MAC.
            key = mac if self._is_trivial_fp(name, mfr, svcs) else fp

            with self._lock:
                existing = self.devices.get(key)
                if existing:
                    existing["mac"]        = mac
                    existing["macs"].add(mac)
                    existing["rssi"]       = int((existing["rssi"] + rssi) / 2)
                    existing["last_seen"]  = now
                    existing["hits"]      += 1
                    # Later adverts may carry richer info than the first.
                    if name and name != "[unnamed]":
                        existing["name"] = name
                    if svcs:
                        existing["services"] = svcs
                    if dtype and dtype != "BLE Device":
                        existing["type"] = dtype
                    if vendor and vendor != "Unknown":
                        existing["vendor"] = vendor
                else:
                    self.devices[key] = {
                        "name":        name,
                        "mac":         mac,
                        "macs":        {mac},
                        "rssi":        rssi,
                        "vendor":      vendor,
                        "type":        dtype,
                        "services":    svcs,
                        "fingerprint": fp,
                        "first_seen":  now,
                        "last_seen":   now,
                        "hits":        1,
                    }
            self.last_packet_ts = now

        except Exception:
            self.error_count += 1
            import traceback
            traceback.print_exc()
            
    async def _scan(self):
        # The `async with` block tears the BleakScanner down cleanly when
        # the while loop exits. Setting self._running = False from another
        # thread will land on the next sleep tick (≤0.5s), at which point
        # the scanner context manager runs its __aexit__ and we return.
        async with BleakScanner(self._detection_callback) as scanner:
            while self._running:
                await asyncio.sleep(0.5)

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._scan())
        finally:
            self._loop.close()
            self._loop = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        # Don't loop.stop() — it would yank the rug while _scan's BleakScanner
        # is mid-cleanup ("Event loop stopped before Future completed").
        # Just signal _scan to exit and join the thread; the async-with block
        # tears the scanner down properly on its own.
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def get_devices(self, sort_by="rssi"):
        with self._lock:
            # Snapshot with sets converted to sorted lists so callers don't
            # see internal mutable state.
            devs = [
                {**d, "macs": sorted(d["macs"])}
                for d in self.devices.values()
            ]
        now  = time.time()
        devs = [d for d in devs if now - d["last_seen"] < 30]
        if sort_by == "rssi":
            devs.sort(key=lambda d: d["rssi"], reverse=True)
        elif sort_by == "name":
            devs.sort(key=lambda d: d["name"].lower())
        return devs
