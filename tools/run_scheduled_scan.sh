#!/bin/bash
# Daily scan: php-malware-finder (YARA) over the configured directory.
# Alert-only (no quarantine/auto-delete) - email sent only if real hits are found.
set -euo pipefail

CONFIG=/etc/openxs/openxs.conf
EMAIL="root@localhost"
SCAN_PATH="/var/www"
QUARANTINE_ENABLED="0"
[ -f "$CONFIG" ] && source "$CONFIG"

HOST=$(hostname -f)
cd /opt/php-malware-finder

find "$SCAN_PATH" -type f -name '*.php' > filelist.txt
export OPENXS_SCAN_LABEL="$SCAN_PATH"
export OPENXS_QUARANTINE_ENABLED="$QUARANTINE_ENABLED"
python3 pmf_scan.py scan php.yar filelist.txt > scan_results.txt 2> scan.log

hits=$(grep -c . scan_results.txt || true)

if [ "$hits" -gt 0 ]; then
    {
        echo "OpenXS: $hits genuine hit(s) on $HOST ($SCAN_PATH)"
        echo ""
        cat scan_results.txt
    } | mail -s "[$HOST] OpenXS: $hits hit(s)" "$EMAIL"
fi
