#!/bin/bash
# install_clamav.sh
# Installs ClamAV (2nd detector) if missing, and enables its daemons
# either way - fresh install or already present. Single source of
# truth, called unconditionally by install.sh (fresh install AND every
# self-update) and by the Webmin "Install" button (install_clamav.cgi).
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

# AppArmor attach_disconnected.path + upload-sized clamd limits (see
# clamd_tune.py). Non-fatal: inspectfile.sh still works via --stream.
python3 "$(dirname "$0")/clamd_tune.py" || echo "==> WARNING: clamd_tune.py failed"

# A clamav-daemon package upgrade (e.g. unattended-upgrades, outside any
# OpenXS self-update) reinstalls its maintainer-default AppArmor profile,
# silently dropping the fix above - this run only catches it if an OpenXS
# self-update happens to land around the same time. Hook it to the actual
# trigger instead: rerun clamd_tune.py (idempotent, non-fatal) after every
# apt/dpkg transaction, so a reverted profile never outlives one apt run.
HOOK_FILE=/etc/apt/apt.conf.d/85-openxs-clamd-tune
HOOK_LINE='DPkg::Post-Invoke:: "test -f /opt/php-malware-finder/clamd_tune.py && python3 /opt/php-malware-finder/clamd_tune.py >/dev/null 2>&1 || true";'
if [ "$(cat "$HOOK_FILE" 2>/dev/null)" != "$HOOK_LINE" ]; then
    echo "$HOOK_LINE" > "$HOOK_FILE"
fi

echo "==> ClamAV ready: $CLAMDSCAN_BIN"
