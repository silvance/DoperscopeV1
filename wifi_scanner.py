import threading
import time
import subprocess
import warnings
warnings.filterwarnings("ignore")
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Elt, RadioTap

OUI_TABLE = {
    "00:50:f2": "Microsoft",
    "00:0c:e7": "Apple",
    "ac:bc:32": "Apple",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1a:11": "Google",
    "50:c7:bf": "TP-Link",
    "c8:3a:35": "Tenda",
    "00:23:69": "Cisco",
    "00:18:f8": "Netgear",
    "00:26:b9": "Dell",
    "00:1b:63": "Apple",
    "00:17:f2": "Apple",
    "00:1c:b3": "Apple",
    "00:1d:4f": "Apple",
    "00:1e:c2": "Apple",
    "00:1f:5b": "Apple",
    "00:1f:f3": "Apple",
    "00:21:e9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6c": "Apple",
    "00:23:df": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4b": "Apple",
    "00:25:bc": "Apple",
    "00:26:08": "Apple",
    "00:26:4a": "Apple",
    "00:03:93": "Apple",
    "00:0a:27": "Apple",
    "00:0a:95": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:cb": "Apple",
    "00:17:ab": "Apple",
    "00:18:34": "Apple",
    "00:19:e3": "Apple",
    "18:65:90": "Apple",
    "1c:ab:a7": "Apple",
    "28:cf:e9": "Apple",
    "3c:07:54": "Apple",
    "40:6c:8f": "Apple",
    "44:2a:60": "Apple",
    "48:74:6e": "Apple",
    "4c:8d:79": "Apple",
    "58:55:ca": "Apple",
    "5c:96:9d": "Apple",
    "60:fb:42": "Apple",
    "64:20:0c": "Apple",
    "68:a8:6d": "Apple",
    "6c:40:08": "Apple",
    "70:de:e2": "Apple",
    "74:e2:f5": "Apple",
    "78:ca:39": "Apple",
    "7c:6d:62": "Apple",
    "80:be:05": "Apple",
    "84:38:35": "Apple",
    "88:1f:a1": "Apple",
    "8c:7b:9d": "Apple",
    "90:84:0d": "Apple",
    "90:b0:ed": "Apple",
    "90:c1:c6": "Apple",
    "94:94:26": "Apple",
    "98:fe:94": "Apple",
    "9c:4f:da": "Apple",
    "a4:b1:97": "Apple",
    "a4:d1:8c": "Apple",
    "a8:20:66": "Apple",
    "a8:bb:cf": "Apple",
    "a8:fa:d8": "Apple",
    "ac:29:3a": "Apple",
    "ac:3c:0b": "Apple",
    "ac:7f:3e": "Apple",
    "b0:34:95": "Apple",
    "b0:65:bd": "Apple",
    "b4:f0:ab": "Apple",
    "b8:8d:12": "Apple",
    "bc:3b:af": "Apple",
    "bc:52:b7": "Apple",
    "bc:67:78": "Apple",
    "c0:84:7a": "Apple",
    "c0:ce:cd": "Apple",
    "c8:2a:14": "Apple",
    "c8:b5:b7": "Apple",
    "cc:08:8d": "Apple",
    "d0:23:db": "Apple",
    "d4:9a:20": "Apple",
    "d8:00:4d": "Apple",
    "d8:a2:5e": "Apple",
    "dc:2b:2a": "Apple",
    "e0:ac:cb": "Apple",
    "e4:25:e7": "Apple",
    "e8:04:0b": "Apple",
    "ec:35:86": "Apple",
    "f0:d1:a9": "Apple",
    "f4:1b:a1": "Apple",
    "f8:1e:df": "Apple",
    "fc:25:3f": "Apple",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "00:1a:4b": "Samsung",
    "00:1c:43": "Samsung",
    "00:1d:25": "Samsung",
    "00:1e:7d": "Samsung",
    "00:1f:cc": "Samsung",
    "00:21:19": "Samsung",
    "00:23:39": "Samsung",
    "00:23:99": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:25:38": "Samsung",
    "00:25:66": "Samsung",
    "00:26:37": "Samsung",
    "18:3f:47": "Samsung",
    "20:6e:9c": "Samsung",
    "24:4b:03": "Samsung",
    "28:98:7b": "Samsung",
    "2c:44:01": "Samsung",
    "30:19:66": "Samsung",
    "34:23:ba": "Samsung",
    "38:0a:94": "Samsung",
    "3c:8b:fe": "Samsung",
    "40:0e:85": "Samsung",
    "44:4e:1a": "Samsung",
    "48:44:f7": "Samsung",
    "4c:3c:16": "Samsung",
    "50:01:bb": "Samsung",
    "50:32:75": "Samsung",
    "54:88:0e": "Samsung",
    "58:ef:68": "Samsung",
    "5c:f6:dc": "Samsung",
    "60:6b:bd": "Samsung",
    "60:a1:0a": "Samsung",
    "64:b3:10": "Samsung",
    "68:eb:ae": "Samsung",
    "6c:83:36": "Samsung",
    "70:f9:27": "Samsung",
    "78:1f:db": "Samsung",
    "78:52:1a": "Samsung",
    "7c:0b:c6": "Samsung",
    "80:57:19": "Samsung",
    "84:25:db": "Samsung",
    "84:38:38": "Samsung",
    "88:32:9b": "Samsung",
    "8c:71:f8": "Samsung",
    "90:18:7c": "Samsung",
    "94:35:0a": "Samsung",
    "94:63:d1": "Samsung",
    "98:52:b1": "Samsung",
    "9c:02:98": "Samsung",
    "a0:07:98": "Samsung",
    "a0:0b:ba": "Samsung",
    "a4:eb:d3": "Samsung",
    "a8:06:00": "Samsung",
    "ac:36:13": "Samsung",
    "b0:47:bf": "Samsung",
    "b4:07:f9": "Samsung",
    "b4:79:a7": "Samsung",
    "b8:5e:7b": "Samsung",
    "bc:20:a4": "Samsung",
    "bc:72:b1": "Samsung",
    "c0:bd:d1": "Samsung",
    "c4:42:02": "Samsung",
    "c4:57:6e": "Samsung",
    "c8:19:f7": "Samsung",
    "cc:07:ab": "Samsung",
    "d0:17:6a": "Samsung",
    "d0:22:be": "Samsung",
    "d0:59:e4": "Samsung",
    "d4:87:d8": "Samsung",
    "d8:57:ef": "Samsung",
    "d8:90:e8": "Samsung",
    "dc:71:96": "Samsung",
    "e0:99:71": "Samsung",
    "e4:40:e2": "Samsung",
    "e4:92:fb": "Samsung",
    "e8:50:8b": "Samsung",
    "ec:1f:72": "Samsung",
    "f0:08:f1": "Samsung",
    "f0:25:b7": "Samsung",
    "f4:42:8f": "Samsung",
    "f8:04:2e": "Samsung",
    "fc:a1:3e": "Samsung",
    "00:19:7d": "Belkin",
    "00:1c:df": "Belkin",
    "00:30:bd": "Belkin",
    "00:90:4b": "Gemtek",
    "00:0f:66": "Motorola",
    "00:a0:96": "Kentrox",
    "00:0c:e5": "Linksys",
    "00:12:17": "Linksys",
    "00:13:10": "Linksys",
    "00:14:bf": "Linksys",
    "00:16:b6": "Linksys",
    "00:18:39": "Linksys",
    "00:1b:2f": "Netgear",
    "00:1e:2a": "Netgear",
    "00:1f:33": "Netgear",
    "00:22:3f": "Netgear",
    "00:24:b2": "Netgear",
    "00:26:f2": "Netgear",
    "20:4e:7f": "Netgear",
    "2c:b0:5d": "Netgear",
    "30:46:9a": "Netgear",
    "44:94:fc": "Netgear",
    "4c:60:de": "Netgear",
    "60:45:cb": "Netgear",
    "6c:b0:ce": "Netgear",
    "74:44:01": "Netgear",
    "84:1b:5e": "Netgear",
    "a0:21:b7": "Netgear",
    "c0:3f:0e": "Netgear",
    "c4:04:15": "Netgear",
    "e0:46:9a": "Netgear",
    "e4:f4:c6": "Netgear",
    "e8:65:d4": "TP-Link",
    "ec:08:6b": "TP-Link",
    "f4:f2:6d": "TP-Link",
    "54:c8:0f": "TP-Link",
    "64:70:02": "TP-Link",
    "6c:5a:b0": "TP-Link",
    "74:da:38": "TP-Link",
    "80:35:c1": "TP-Link",
    "90:f6:52": "TP-Link",
    "94:d9:b3": "TP-Link",
    "a0:f3:c1": "TP-Link",
    "ac:84:c6": "TP-Link",
    "b0:48:7a": "TP-Link",
    "b4:b0:24": "TP-Link",
    "c4:e9:84": "TP-Link",
    "d8:07:b6": "TP-Link",
    "f8:1a:67": "TP-Link",
    "00:90:4c": "Epson",
    "00:26:ab": "Epson",
    "00:04:ac": "IBM",
    "00:06:29": "IBM",
}

def get_vendor(mac):
    if not mac:
        return "Unknown"
    prefix = mac[:8].lower()
    return OUI_TABLE.get(prefix, "Unknown")

def get_band(channel):
    if channel and channel > 14:
        return "5G"
    return "2.4G"

def fingerprint_device(elt_layer):
    """Fingerprint device OS/type from 802.11 Information Elements.
    Based on real-world probe request analysis."""
    ht  = False
    vht = False
    he  = False
    vendor_ouis = []
    ie_order = []

    elt = elt_layer
    while elt and hasattr(elt, "ID"):
        ie_order.append(elt.ID)
        if elt.ID == 45:
            ht = True
        elif elt.ID == 191:
            vht = True
        elif elt.ID == 255:
            he = True
        elif elt.ID == 221:
            try:
                oui = elt.info[:3].hex()
                vendor_ouis.append(oui)
            except:
                pass
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except:
            break

    # OUI signatures (from real captures)
    has_apple  = "8cfdf0" in vendor_ouis  # Apple Inc - definitive
    has_ms     = "0050f2" in vendor_ouis  # Microsoft WPS
    has_wfd    = "506f9a" in vendor_ouis  # Wi-Fi Alliance P2P/Direct (Android)

    # WiFi generation
    if he:
        wifi_gen = "WiFi 6"
    elif vht:
        wifi_gen = "WiFi 5"
    elif ht:
        wifi_gen = "WiFi 4"
    else:
        wifi_gen = "WiFi 3"

    # iOS/iPhone — Apple OUI present
    if has_apple and has_ms:
        if he:
            return {"os": "iPhone", "type": "iPhone (iOS 14+)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}
        elif vht:
            return {"os": "iPhone", "type": "iPhone (iOS 11-13)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}
        else:
            return {"os": "iPhone", "type": "iPhone (older iOS)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    if has_apple:
        return {"os": "Apple", "type": "Apple Device", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    # iOS without Apple OUI (privacy mode, no VHT quirk)
    if not vendor_ouis and he and not vht and ie_order[:4] == [0, 1, 50, 3]:
        return {"os": "iPhone", "type": "iPhone (privacy mode)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    # Android — Wi-Fi Direct OUI present
    if has_wfd and has_ms:
        if he:
            return {"os": "Android", "type": "Android (v10+)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}
        elif vht:
            return {"os": "Android", "type": "Android (v7-9)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}
        else:
            return {"os": "Android", "type": "Android (older)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    if has_wfd:
        return {"os": "Android", "type": "Android Device", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    # Microsoft WPS only — Windows or older Android
    if has_ms and not has_wfd:
        if ht and not vht:
            return {"os": "Android/Win", "type": "Android or Windows", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}
        return {"os": "Unknown", "type": "WPS Device", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    # No vendor IEs
    if not vendor_ouis:
        if he:
            return {"os": "Unknown", "type": "Unknown (WiFi 6)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}
        elif ht:
            return {"os": "Unknown", "type": "Unknown (WiFi 4)", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}

    return {"os": "Unknown", "type": "Unknown Device", "wifi_gen": wifi_gen, "ht": ht, "vht": vht, "he": he}


class WiFiScanner:
    def __init__(self, interface="wlan1"):
        self.interface = interface
        self.devices = {}
        self.clients = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._channel_thread = None
        self.current_channel = 1
        self.locked_channel = None
        self.probes = {}

        self.channels_24 = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 13]
        self.channels_5  = [36, 40, 44, 48, 52, 56, 60, 64,
                            100, 104, 108, 112, 116, 120, 124, 128,
                            132, 136, 140, 149, 153, 157, 161, 165]
        # 2.4GHz first then 5GHz - reduces band switching instability
        self.all_channels = self.channels_24 + self.channels_5
        self._chan_index = 0

    def _parse_packet(self, pkt):
        is_beacon   = pkt.haslayer(Dot11Beacon)
        is_probe_resp = pkt.haslayer(Dot11ProbeResp)
        is_probe_req  = pkt.haslayer(Dot11ProbeReq)
        if not is_beacon and not is_probe_resp and not is_probe_req:
            return
        # Handle probe requests separately
        if is_probe_req:
            try:
                mac  = pkt[Dot11].addr2
                if not mac or mac.startswith("ff:"):
                    return
                ssid = ""
                try:
                    ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace").strip()
                except:
                    pass
                rssi = -100
                if pkt.haslayer(RadioTap):
                    try:
                        rssi = int(pkt[RadioTap].dBm_AntSignal)
                    except:
                        pass

                # IE fingerprinting
                fp = {"os": "Unknown", "type": "Unknown Device", "wifi_gen": "Unknown", "ht": False, "vht": False, "he": False}
                try:
                    if pkt.haslayer(Dot11Elt):
                        fp = fingerprint_device(pkt.getlayer(Dot11Elt))
                except:
                    pass

                with self._lock:
                    existing = self.probes.get(mac)
                    if existing:
                        rssi = int((existing["rssi"] + rssi) / 2)
                    self.probes[mac] = {
                        "mac":       mac,
                        "ssid":      ssid or "<broadcast>",
                        "rssi":      rssi,
                        "vendor":    get_vendor(mac),
                        "os":        fp["os"],
                        "dev_type":  fp["type"],
                        "wifi_gen":  fp["wifi_gen"],
                        "last_seen": time.time(),
                    }
            except Exception:
                pass
            return
        try:
            bssid = pkt[Dot11].addr3
            if not bssid:
                return

            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace").strip()
                    except:
                        ssid = "[decode error]"
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            rssi = -100
            if pkt.haslayer(RadioTap):
                try:
                    rssi = int(pkt[RadioTap].dBm_AntSignal)
                except:
                    pass

            channel = self.current_channel
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3 and len(elt.info) == 1:
                    channel = ord(elt.info)
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            hidden = (ssid == "" or ssid == "\x00")
            display_ssid = "[hidden]" if hidden else ssid
            band = get_band(channel)
            vendor = get_vendor(bssid)

            device = {
                "ssid":      display_ssid,
                "bssid":     bssid,
                "rssi":      rssi,
                "channel":   channel,
                "band":      band,
                "vendor":    vendor,
                "hidden":    hidden,
                "last_seen": time.time(),
            }

            with self._lock:
                existing = self.devices.get(bssid)
                if existing:
                    device["rssi"] = int((existing["rssi"] + rssi) / 2)
                self.devices[bssid] = device

        except Exception:
            pass

    def _parse_client(self, pkt):
        try:
            if not pkt.haslayer(Dot11):
                return

            dot11 = pkt[Dot11]

            if dot11.type == 2:
                fc      = dot11.FCfield
                to_ds   = fc & 0x01
                from_ds = fc & 0x02

                if to_ds and not from_ds:
                    bssid  = dot11.addr1
                    client = dot11.addr2
                elif from_ds and not to_ds:
                    bssid  = dot11.addr2
                    client = dot11.addr1
                else:
                    return

                if not bssid or not client:
                    return
                if client.startswith("ff:ff") or client.startswith("01:"):
                    return

                rssi = -100
                if pkt.haslayer(RadioTap):
                    try:
                        rssi = int(pkt[RadioTap].dBm_AntSignal)
                    except:
                        pass

                with self._lock:
                    if bssid not in self.clients:
                        self.clients[bssid] = {}
                    self.clients[bssid][client] = {
                        "mac":       client,
                        "rssi":      rssi,
                        "vendor":    get_vendor(client),
                        "last_seen": time.time(),
                    }

            elif dot11.type == 0 and dot11.subtype == 4:
                client = dot11.addr2
                if client and not client.startswith("ff:"):
                    rssi = -100
                    if pkt.haslayer(RadioTap):
                        try:
                            rssi = int(pkt[RadioTap].dBm_AntSignal)
                        except:
                            pass
                    with self._lock:
                        if "probes" not in self.clients:
                            self.clients["probes"] = {}
                        self.clients["probes"][client] = {
                            "mac":       client,
                            "rssi":      rssi,
                            "vendor":    get_vendor(client),
                            "last_seen": time.time(),
                        }

        except Exception:
            pass

    def _channel_hopper(self):
        # Hop 2.4GHz channels first, then 5GHz, with longer dwell
        # This reduces band switching which destabilizes mt76x0u
        while self._running:
            if self.locked_channel is not None:
                ch = self.locked_channel
                dwell = 0.5
            else:
                ch = self.all_channels[self._chan_index % len(self.all_channels)]
                self._chan_index += 1
                # Longer dwell on 5GHz to reduce band switch frequency
                dwell = 1.0 if ch > 14 else 0.5

            self.current_channel = ch
            try:
                subprocess.run(
                    ["iw", "dev", self.interface, "set", "channel", str(ch)],
                    capture_output=True,
                    timeout=0.5
                )
            except Exception:
                pass
            time.sleep(dwell)

    def _scan_loop(self):
        def handle(pkt):
            self._parse_packet(pkt)
            self._parse_client(pkt)

        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    prn=handle,
                    store=False,
                    filter="type mgt or type data",
                    stop_filter=lambda p: not self._running
                )
            except Exception as e:
                if self._running:
                    time.sleep(1)  # Brief pause then retry

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._channel_thread = threading.Thread(target=self._channel_hopper, daemon=True)
        self._thread.start()
        self._channel_thread.start()

    def stop(self):
        self._running = False

    def get_devices(self, band_filter=None, sort_by="rssi"):
        if not self._lock.acquire(timeout=0.5):
            return []
        try:
            devs = list(self.devices.values())
        finally:
            self._lock.release()
        now = time.time()
        devs = [d for d in devs if now - d["last_seen"] < 30]
        if band_filter:
            devs = [d for d in devs if d["band"] == band_filter]
        if sort_by == "rssi":
            devs.sort(key=lambda d: d["rssi"], reverse=True)
        elif sort_by == "ssid":
            devs.sort(key=lambda d: d["ssid"].lower())
        elif sort_by == "channel":
            devs.sort(key=lambda d: d["channel"])
        return devs

    def get_probes(self):
        if not self._lock.acquire(timeout=0.5):
            return []
        try:
            probes = list(self.probes.values())
        finally:
            self._lock.release()
        now = time.time()
        probes = [p for p in probes if now - p["last_seen"] < 30]
        probes.sort(key=lambda p: p["rssi"], reverse=True)
        return probes

    def get_clients(self, bssid):
        if not self._lock.acquire(timeout=0.5):
            return []
        try:
            ap_clients = dict(self.clients.get(bssid, {}))
        finally:
            self._lock.release()
        now = time.time()
        active = {
            mac: info for mac, info in ap_clients.items()
            if now - info["last_seen"] < 60
        }
        return sorted(active.values(), key=lambda c: c["rssi"], reverse=True)
