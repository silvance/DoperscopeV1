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
apt-get update
apt-get install -y --no-install-recommends \
    build-essential cmake git pkg-config \
    libfftw3-dev libmbedtls-dev libboost-program-options-dev \
    libconfig++-dev libsctp-dev \
    libusb-1.0-0-dev \
    rtl-sdr librtlsdr-dev \
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
# Skip if it's already installed.
if command -v srsue >/dev/null 2>&1; then
    echo "    srsue already on PATH, skipping build"
else
    cd /tmp
    rm -rf srsRAN_4G
    git clone --depth=1 https://github.com/srsran/srsRAN_4G.git
    cd srsRAN_4G
    mkdir -p build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
    # Pi 4B has 4 cores; -j4 keeps the build under an hour without OOM.
    make -j4
    make install
    ldconfig
    cd /
    rm -rf /tmp/srsRAN_4G
fi

echo "==> 4/4: OpenCellID snapshot directory"
# Stage 3 will look for the legitimacy baseline here. The snapshot
# itself is operator-supplied — opencellid.org distributes a free
# global CSV (filter to MCC=310/311/312 etc for the US) that should
# go in this directory as ocid_us.csv. Not auto-downloaded because
# OCID requires registration for the API key.
DATA_DIR="$(getent passwd "$REAL_USER" | cut -d: -f6)/.doperscope"
install -o "$REAL_USER" -g "$REAL_USER" -m 0700 -d "$DATA_DIR/opencellid"

cat <<EOF

==================================================================
SDR setup complete. REBOOT now so:
  - the rtl-sdr kernel blacklist takes effect (otherwise the DVB-T
    driver grabs the dongle and srsRAN can't open it)
  - $REAL_USER picks up the plugdev group membership

After reboot, smoke-test:
  lsusb | grep -i realtek        # should show 0bda:2838 (or :2832)
  rtl_test -t                    # should report 'Found 1 device(s)'
  srsue --help                   # should print srsue's CLI

Then drop an OpenCellID US snapshot at:
  $DATA_DIR/opencellid/ocid_us.csv

Doperscope's Cell tab should switch from NO SDR to FW OK / NO CAPTURE
after reboot. Stage 2 will start populating the live cell list.
==================================================================
EOF
