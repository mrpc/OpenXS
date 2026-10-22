#!/bin/bash
# Daily scan: php-malware-finder (YARA) over the configured directory.
# Alert-only (no quarantine/auto-delete) - email sent only if real hits are found.
set -euo pipefail

CONFIG=/etc/openxs/openxs.conf
EMAIL="root@localhost"
SCAN_PATH="/var/www"
SCAN_MODE="path"
ACCOUNTS_DIR="/home"
ACCOUNTS_SUBPATH="public_html"
QUARANTINE_ENABLED="0"
FAST_PHP_ONLY="0"
CHANGED_HOURS=""
THROTTLE_LOAD=""
QUIET="0"
QUARANTINE_CATEGORIES="virus,yara"
# Parsed as plain data, not `source`-d: the config file is writable via the
# Webmin settings form, and `source` would execute $()/`` in any value as
# real shell code (e.g. a crafted EMAIL value running arbitrary commands
# as root on the next cron run).
if [ -f "$CONFIG" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            EMAIL) EMAIL="$value" ;;
            SCAN_PATH) SCAN_PATH="$value" ;;
            SCAN_MODE) SCAN_MODE="$value" ;;
            ACCOUNTS_DIR) ACCOUNTS_DIR="$value" ;;
            ACCOUNTS_SUBPATH) ACCOUNTS_SUBPATH="$value" ;;
            QUARANTINE_ENABLED) QUARANTINE_ENABLED="$value" ;;
            FAST_PHP_ONLY) FAST_PHP_ONLY="$value" ;;
            CHANGED_HOURS) CHANGED_HOURS="$value" ;;
            THROTTLE_LOAD) THROTTLE_LOAD="$value" ;;
            QUIET) QUIET="$value" ;;
            QUARANTINE_CATEGORIES) QUARANTINE_CATEGORIES="$value" ;;
        esac
    done < "$CONFIG"
fi

HOST=$(hostname -f)
cd /opt/php-malware-finder

# "accounts" mode mirrors cxs's --allusers/--www: one hosting account per
# subdirectory of ACCOUNTS_DIR (e.g. /home/<user>), restricted to each
# account's web root (ACCOUNTS_SUBPATH, blank = whole account) rather than
# also wading through mail/backups/logs under the same home directory.
if [ "$SCAN_MODE" = "accounts" ]; then
    SCAN_TARGETS=("$ACCOUNTS_DIR"/*"${ACCOUNTS_SUBPATH:+/$ACCOUNTS_SUBPATH}")
    SCAN_LABEL="$ACCOUNTS_DIR (accounts mode, */$ACCOUNTS_SUBPATH)"
    FS_SCAN_ROOT="$ACCOUNTS_DIR"
else
    SCAN_TARGETS=("$SCAN_PATH")
    SCAN_LABEL="$SCAN_PATH"
    FS_SCAN_ROOT="$SCAN_PATH"
fi

# Scans every file by default, not just *.php: a webshell saved with a
# disguised extension (avatar.jpg containing real <?php ... ?>) would
# otherwise never even reach YARA/ClamAV, since find would filter it out
# by name alone before either engine sees its content. FAST_PHP_ONLY=1
# trades that off for speed on very large sites.
: > filelist.txt
for target in "${SCAN_TARGETS[@]}"; do
    [ -d "$target" ] || continue
    if [ "$FAST_PHP_ONLY" = "1" ]; then
        find "$target" -type f -name '*.php' >> filelist.txt
    else
        find "$target" -type f >> filelist.txt
    fi
done
export OPENXS_SCAN_LABEL="$FS_SCAN_ROOT"
export OPENXS_QUARANTINE_ENABLED="$QUARANTINE_ENABLED"
export OPENXS_CHANGED_HOURS="$CHANGED_HOURS"
export OPENXS_THROTTLE_LOAD="$THROTTLE_LOAD"
export OPENXS_QUIET="$QUIET"
export OPENXS_QUARANTINE_CATEGORIES="$QUARANTINE_CATEGORIES"
export OPENXS_FAST_PHP_ONLY="$FAST_PHP_ONLY"
python3 pmf_scan.py scan php.yar filelist.txt > scan_results.txt 2> scan.log

hits=$(grep -c . scan_results.txt || true)

if [ "$hits" -gt 0 ]; then
    {
        echo "OpenXS: $hits genuine hit(s) on $HOST ($SCAN_LABEL)"
        echo ""
        cat scan_results.txt
    } | mail -s "[$HOST] OpenXS: $hits hit(s)" "$EMAIL"
fi
