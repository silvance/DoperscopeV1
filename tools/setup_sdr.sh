#!/bin/bash
# One-time setup for RTL-SDR v4 cellular cell-search on a Pi 4B running
# Raspberry Pi OS (Bookworm). Installs the three pieces Doperscope's
# stage-2 cell capture path will subprocess against:
#
#   1. RTL-SDR userland (rtl-sdr + librtlsdr-dev) — driver + tools
#   2. srsRAN_4G — LTE cell discovery + SIB1 decode for stage 2
#   3. gr-gsm — 2G cell enumeration / IMSI catcher heuristics
#
# srsRAN_4G is the previous-generation LTE stack and the one that runs
# reliably on Pi 4B with an RTL-SDR. The newer srsRAN_Project is 5G-NR
# focused and harder to bring up on this hardware.
#
# Reboot after running this — the udev rules and dialout group changes
# take effect on next login.
#
# Usage:
#   sudo bash tools/setup_sdr.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run with sudo." >&2
    exit 1
fi

REAL_USER="${SUDO_USER:-${USER}}"

echo "==> 1/4: apt packages"
# Most of the runtime dependencies for the cell-capture path. srsRAN
# itself is built from source below.
#
# SoapySDR is the critical-but-easy-to-miss piece: without
# libsoapysdr-dev + soapysdr-module-rtlsdr present at srsRAN build
# time, cmake silently configures the build with NO RF support and
# the resulting cell_search binary can only read IQ from a file —
# it can't open the RTL-SDR at runtime. The "Compiling pdsch_ue with
# no RF support" pragma in the build output is the smoking gun.
apt-get update
apt-get install -y --no-install-recommends \
    build-essential cmake git pkg-config \
    libfftw3-dev libmbedtls-dev libboost-program-options-dev \
    libconfig++-dev libsctp-dev \
    libusb-1.0-0-dev \
    rtl-sdr librtlsdr-dev \
    libsoapysdr-dev soapysdr-module-rtlsdr soapysdr-tools \
    gr-gsm \
    python3-pip

# RTL-SDR udev rules so the operator user can open the device without root.
echo "==> 2/4: udev rules + dialout group"
cat >/etc/udev/rules.d/20-rtlsdr.rules <<'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", MODE:="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2832", MODE:="0666"
EOF
udevadm control --reload-rules
udevadm trigger
usermod -a -G plugdev "$REAL_USER" || true

# Blacklist the in-kernel DVB-T driver — it grabs the dongle before
# rtl-sdr can use it and silently steals our SDR access.
cat >/etc/modprobe.d/blacklist-rtl.conf <<'EOF'
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF

echo "==> 3/4: srsRAN_4G from source"
# Skip only if BOTH srsue AND cell_search are already on PATH.
# Doperscope's SDR scanner shells out to cell_search — an example binary
# that srsRAN_4G's `make install` does not put on PATH by default — so
# we need both present to consider this step complete.
if command -v srsue >/dev/null 2>&1 && command -v cell_search >/dev/null 2>&1; then
    echo "    srsue + cell_search already on PATH, skipping build"
else
    cd /tmp
    rm -rf srsRAN_4G
    git clone --depth=1 https://github.com/srsran/srsRAN_4G.git
    cd srsRAN_4G
    mkdir -p build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .. 2>&1 | tee cmake.log
    # Fail fast if cmake couldn't find an RF backend. Without this the
    # build still succeeds but cell_search ends up unable to open any
    # radio at runtime — operator-hostile to discover after a 45-minute
    # build. Soapy is the path we install above; UHD is acceptable too.
    if grep -qiE "RF_FOUND=FALSE|no.*rf.*support" cmake.log && \
       ! grep -qiE "(soapy|uhd).*found" cmake.log; then
        echo "ERROR: srsRAN cmake did not find SoapySDR or UHD." >&2
        echo "       cell_search will build but won't open the RTL-SDR." >&2
        echo "       Install libsoapysdr-dev + soapysdr-module-rtlsdr and re-run." >&2
        exit 1
    fi
    # Pi 4B has 4 cores; -j4 keeps the build under an hour without OOM.
    make -j4
    make install
    # srsRAN_4G doesn't install the example binaries by default. Copy
    # cell_search onto PATH so sdr_scanner.py can invoke it directly.
    if [ -x lib/examples/cell_search ]; then
        install -m 0755 lib/examples/cell_search /usr/local/bin/cell_search
    else
        echo "    WARN: cell_search example binary not found in build tree."
        echo "          LTE cell discovery will be disabled until you install it manually."
    fi
    ldconfig
    cd /
    rm -rf /tmp/srsRAN_4G
fi

echo "==> 4/4: OpenCellID snapshot directory"
# Stage 3 uses this as the legitimacy baseline for rogue-cell scoring.
# The snapshot itself is operator-supplied — opencellid.org distributes
# a free global CSV (https://opencellid.org/downloads.php — requires
# registration for an API key). Filter to US MCCs (310/311/312/313) and
# drop the result at ocid_us.csv in this directory. Without it the
# heuristics still run (MCC plausibility, 2G-in-LTE downgrade) but they
# can't catch a legitimate-looking but unknown cell ID.
DATA_DIR="$(getent passwd "$REAL_USER" | cut -d: -f6)/.doperscope"
install -o "$REAL_USER" -g "$REAL_USER" -m 0700 -d "$DATA_DIR/opencellid"

cat <<EOF

==================================================================
SDR setup complete. REBOOT now so:
  - the rtl-sdr kernel blacklist takes effect (otherwise the DVB-T
    driver grabs the dongle and srsRAN can't open it)
  - $REAL_USER picks up the plugdev group membership

After reboot, smoke-test:
  lsusb | grep -i realtek                       # 0bda:2838 (or :2832)
  rtl_test -t                                    # 'Found 1 device(s)'
  SoapySDRUtil --probe="driver=rtlsdr"          # Soapy <-> RTL-SDR bridge
  grgsm_scanner --help                           # 2G enumeration binary
  cell_search -h                                 # LTE cell-search binary

Then drop an OpenCellID US snapshot at (used by stage 3):
  $DATA_DIR/opencellid/ocid_us.csv

Doperscope's Cell tab should switch from NO SDR to SCANNING within the
first ~30s after launch and start populating the live cell list as it
cycles US bands.
==================================================================
EOF
