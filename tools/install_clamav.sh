#!/bin/bash
# install_clamav.sh
# Installs ClamAV (2nd detector) if missing, and enables its daemons
# either way - fresh install or already present. Single source of
# truth, called by install.sh (--with-clamav) and by the Webmin
# "Install" button (install_clamav.cgi).
set -euo pipefail

# Canonical path the clamav-daemon .deb installs clamdscan to - checked
# directly rather than via `command -v`, which proved unreliable for
# maldet specifically when run from this Perl/CGI context.
CLAMDSCAN_BIN=/usr/bin/clamdscan

if [ ! -x "$CLAMDSCAN_BIN" ]; then
    echo "==> ClamAV not found - installing..."
    apt-get update -qq
    apt-get install -y -qq clamav-daemon clamav-freshclam
else
    echo "==> ClamAV already installed: $CLAMDSCAN_BIN"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now clamav-daemon clamav-freshclam 2>/dev/null || true
fi

echo "==> ClamAV ready: $CLAMDSCAN_BIN"
