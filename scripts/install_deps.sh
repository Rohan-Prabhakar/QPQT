#!/bin/bash
# scripts/install_deps.sh
# Installs liboqs from source. Run once before building QPQT.
# Tested on Ubuntu 22.04 / Debian 12 / Kaggle CPU instances.

set -e

echo "=== Installing QPQT dependencies ==="

# Build tools
apt-get update -qq
apt-get install -y cmake ninja-build libssl-dev build-essential git

# Check if liboqs already installed
if [ -f /usr/local/include/oqs/oqs.h ]; then
    echo "liboqs already installed — skipping"
    exit 0
fi

# Build liboqs from source
echo "Building liboqs..."
git clone --depth 1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs_build
mkdir -p /tmp/liboqs_build/build && cd /tmp/liboqs_build/build
cmake -GNinja \
      -DOQS_DIST_BUILD=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_BUILD_TYPE=Release \
      .. > /dev/null 2>&1
ninja install > /dev/null 2>&1
rm -rf /tmp/liboqs_build
echo "liboqs installed to /usr/local"
echo "=== Done ==="
