"""SDRScanner.status() detection tests — mock lsusb to exercise every
state without needing a real RTL-SDR plugged in."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class _FakeRun:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


def _patch_lsusb(stdout):
    return lambda *a, **kw: _FakeRun(stdout)


class SDRStatusTests(unittest.TestCase):
    def setUp(self):
        for m in list(sys.modules):
            if m.startswith("sdr_scanner"):
                del sys.modules[m]
        from sdr_scanner import SDRScanner
        self.SDRScanner = SDRScanner
        self._orig_run = subprocess.run

    def tearDown(self):
        subprocess.run = self._orig_run

    def test_no_dongle_when_lsusb_empty(self):
        subprocess.run = _patch_lsusb("")
        s = self.SDRScanner()
        self.assertEqual(s.status(), "absent")
        self.assertFalse(s.is_available())

    def test_present_rtl2832u_2838(self):
        # The most common RTL-SDR v3/v4 enumeration: 0bda:2838.
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 006: ID 0bda:2838 Realtek Semiconductor Corp. RTL2832U DVB-T\n"
        )
        s = self.SDRScanner()
        self.assertEqual(s.status(), "present")
        self.assertTrue(s.is_available())

    def test_present_rtl2832u_2832(self):
        # Older RTL2832U variants enumerate with 0bda:2832.
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 007: ID 0bda:2832 Realtek Semiconductor Corp. RTL2832U\n"
        )
        s = self.SDRScanner()
        self.assertEqual(s.status(), "present")

    def test_scanning_when_capture_active(self):
        # Once the capture loop has parsed at least one cell, _capturing
        # is True and status() should flip from "present" to "scanning".
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 006: ID 0bda:2838 Realtek RTL2832U\n"
        )
        s = self.SDRScanner()
        s._capturing = True
        self.assertEqual(s.status(), "scanning")

    def test_scanning_drops_to_absent_when_dongle_yanked(self):
        # If the operator yanks the RTL-SDR mid-scan, status must NOT
        # keep reporting "scanning" off the cached _capturing flag —
        # the lsusb check is the source of truth for hardware presence.
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 006: ID 0bda:2838 Realtek RTL2832U\n"
        )
        s = self.SDRScanner()
        s._capturing = True
        self.assertEqual(s.status(), "scanning")
        # Bust the 5s status cache and report no dongle.
        s._status_cached = None
        subprocess.run = _patch_lsusb("")
        self.assertEqual(s.status(), "absent")

    def test_absent_when_only_unrelated_devices(self):
        # Random Realtek Ethernet, Bluetooth hub, etc. — should not trip
        # on Realtek VID alone.
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 005: ID 0bda:8153 Realtek USB Ethernet\n"
            "Bus 001 Device 009: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
        )
        s = self.SDRScanner()
        self.assertEqual(s.status(), "absent")

    def test_lsusb_failure_returns_absent(self):
        def boom(*a, **kw):
            raise FileNotFoundError("lsusb not installed")
        subprocess.run = boom
        s = self.SDRScanner()
        self.assertEqual(s.status(), "absent")

    def test_status_cached_for_repeated_calls(self):
        # First call hits lsusb; second call (within the 5s TTL) should
        # not — verify by swapping the fake out between calls.
        subprocess.run = _patch_lsusb(
            "Bus 001 Device 006: ID 0bda:2838 Realtek RTL2832U\n"
        )
        s = self.SDRScanner()
        self.assertEqual(s.status(), "present")
        # Replace with empty output; cached "present" should survive.
        subprocess.run = _patch_lsusb("")
        self.assertEqual(s.status(), "present")


if __name__ == "__main__":
    unittest.main()
