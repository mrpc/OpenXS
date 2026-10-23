#!/bin/bash
# install_maldet.sh
# Installs Linux Malware Detect (maldet) if missing, and applies OpenXS's
# recommended config either way (fresh install or already present) -
# single source of truth, called by install.sh (--with-maldet) and by
# the Webmin "Install" button (install_maldet.cgi).
set -euo pipefail

# The canonical path maldet's own installer always uses - checked directly
# (rather than relying on a second `command -v` lookup after installing,
# which was unreliable specifically when this script runs via a Perl
# backtick from the Webmin UI, for reasons not fully pinned down).
MALDET_BIN=/usr/local/sbin/maldet

if [ ! -x "$MALDET_BIN" ]; then
    echo "==> maldet not found - installing from rfxn.com..."
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    curl -fsSL https://www.rfxn.com/downloads/maldetect-current.tar.gz -o "$tmpdir/maldetect.tar.gz"
    tar -xzf "$tmpdir/maldetect.tar.gz" -C "$tmpdir"
    (cd "$tmpdir"/maldetect-*/ && bash ./install.sh)
else
    echo "==> maldet already installed: $MALDET_BIN"
fi

# Applied idempotently, whether this was a fresh install or maldet was
# already present (e.g. on a server it was installed on long before
# OpenXS existed):
#
# scan_clamscan=0: maldet uses ClamAV as its own default scan engine
# when available. OpenXS already runs ClamAV directly (clamav_scan() in
# pmf_scan.py) for every scan maldet is also asked to check, so without
# this every file gets ClamAV-scanned twice in the same pass.
CONF=/usr/local/maldetect/conf.maldet
if [ -f "$CONF" ] && grep -q '^scan_clamscan="1"' "$CONF"; then
    sed -i 's/^scan_clamscan="1"/scan_clamscan="0"/' "$CONF"
    echo "==> Set scan_clamscan=0 (OpenXS already runs ClamAV separately - avoids double-scanning)"
fi

echo "==> maldet ready: $MALDET_BIN ($("$MALDET_BIN" --help 2>&1 | sed -n '2p' | xargs))"
