#!/usr/bin/env bash
# fetch.sh — obtain and unpack the Suricata source tree used by rail B
# (full-capability detection on HIL/gateway hosts).
#
# The release tarball is committed in this directory so offline /
# slow-network build servers do not need to re-download it. This script
# exists to (a) document provenance and (b) re-fetch/verify when needed.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=8.0.6
TARBALL="suricata-${VERSION}.tar.gz"
URL="https://www.openinfosecfoundation.org/download/suricata-${VERSION}.tar.gz"

if [[ ! -f "$TARBALL" ]]; then
    echo "downloading $URL"
    curl -fL --retry 3 -o "$TARBALL" "$URL"
fi

if [[ -f "${TARBALL}.sha256" ]]; then
    echo "verifying sha256"
    sha256sum -c "${TARBALL}.sha256"
fi

if [[ ! -d "suricata-${VERSION}" ]]; then
    echo "unpacking"
    tar xzf "$TARBALL"
fi

echo "ready: suricata-${VERSION}/"
echo "build (official autotools path, NOT the project CMake):"
echo "  cd suricata-${VERSION}"
echo "  ./configure --prefix=/opt/suricata --disable-nfqueue --disable-nflog \\"
echo "              --disable-suricata-update --disable-python --disable-af-xdp"
echo "  make -j\$(nproc) && sudo make install"
