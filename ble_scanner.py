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
        self.devices = {}
        self._lock    = threading.Lock()
        self._running = False
        self._thread  = None
        self._loop    = None

    def _get_fingerprint(self, name, mfr_data, services):
        """Creates a unique signature to track devices through MAC rotations."""
        mfr_str = ""
        if mfr_data:
            for k, v in sorted(mfr_data.items()):
                try:
                    # Convert byte arrays to hex strings for safe hashing
                    mfr_str += f"{k}:{v.hex()}|"
                except Exception:
                    pass
        svc_str = ",".join(sorted(services))
        return f"{name}::{mfr_str}::{svc_str}"

    def _detection_callback(self, device, advertisement_data):
        try:
            rssi   = advertisement_data.rssi if advertisement_data.rssi else -100
            name   = device.name or "[unnamed]"
            mac    = device.address
            mfr    = advertisement_data.manufacturer_data or {}
            vendor = get_ble_vendor(mfr)
            dtype  = classify_device(name, mfr)
            svcs   = list(advertisement_data.service_uuids or [])

            # Generate the anti-randomization fingerprint
            fp = self._get_fingerprint(name, mfr, svcs)

            entry = {
                "name":        name,
                "mac":         mac,
                "rssi":        rssi,
                "vendor":      vendor,
                "type":        dtype,
                "services":    svcs,
                "fingerprint": fp,
                "last_seen":   time.time(),
            }

            with self._lock:
                existing = self.devices.get(mac)
                if existing:
                    entry["rssi"] = int((existing["rssi"] + rssi) / 2)
                self.devices[mac] = entry

        except Exception as e:
            import traceback
            traceback.print_exc()
            
    async def _scan(self):
        async with BleakScanner(self._detection_callback) as scanner:
            while self._running:
                await asyncio.sleep(0.5)

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._scan())

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

    def get_devices(self, sort_by="rssi"):
        with self._lock:
            devs = list(self.devices.values())
        now  = time.time()
        devs = [d for d in devs if now - d["last_seen"] < 30]
        if sort_by == "rssi":
            devs.sort(key=lambda d: d["rssi"], reverse=True)
        elif sort_by == "name":
            devs.sort(key=lambda d: d["name"].lower())
        return devs
