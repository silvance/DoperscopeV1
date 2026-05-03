"""ZigbeeScanner.status() detection tests — mock lsusb output to
exercise every state without needing a real nRF dongle attached."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class _FakeRun:
    """Replacement for subprocess.run that returns canned lsusb stdout."""
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


def _patch_lsusb(stdout):
    return lambda *a, **kw: _FakeRun(stdout)


class ZigbeeStatusTests(unittest.TestCase):
    def setUp(self):
        # Ensure we're loading a fresh ZigbeeScanner instance per test
        # so its internal status cache doesn't carry over.
        for m in list(sys.modules):
            if m.startswith("zigbee_scanner"):
                del sys.modules[m]
        from zigbee_scanner import ZigbeeScanner
        self.ZigbeeScanner = ZigbeeScanner
        self._orig_run = subprocess.run

    def tearDown(self):
        subprocess.run = self._orig_run

    def test_no_dongle_when_lsusb_empty(self):
        subprocess.run = _patch_lsusb("")
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "absent")
        self.assertFalse(z.is_available())

    def test_open_bootloader_nordic_521f(self):
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 004: ID 1915:521f Nordic Semiconductor Open DFU Bootloader\n"
        )
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "bootloader")
        self.assertFalse(z.is_available())

    def test_open_bootloader_adafruit_239a(self):
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 003: ID 239a:0029 Adafruit nRF52840 Bootloader\n"
        )
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "bootloader")

    def test_ble_sniffer_firmware(self):
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 003: ID 1915:522a Nordic Semiconductor ASA nRF Sniffer for Bluetooth LE\n"
        )
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "ble_sniffer")
        self.assertFalse(z.is_available())  # not 802.15.4-ready

    def test_802154_sniffer_firmware(self):
        subprocess.run = _patch_lsusb(
            "Bus 002 Device 005: ID 1d6b:0003 Linux Foundation 3.0 root hub\n"
            "Bus 001 Device 006: ID 1915:c00a Nordic Semiconductor ASA\n"
        )
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "sniffer")
        self.assertTrue(z.is_available())

    def test_sniffer_wins_when_both_firmwares_appear(self):
        # Defensive: if somehow both VID:PIDs show up, prefer the 802.15.4
        # one since that's what we can actually use.
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 003: ID 1915:522a Nordic\n"
            "Bus 001 Device 005: ID 1915:c00a Nordic\n"
        )
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "sniffer")

    def test_lsusb_failure_returns_absent(self):
        def boom(*a, **kw):
            raise FileNotFoundError("lsusb not installed")
        subprocess.run = boom
        z = self.ZigbeeScanner()
        self.assertEqual(z.status(), "absent")


if __name__ == "__main__":
    unittest.main()
