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
QUARANTINE_CATEGORIES="virus,yara_exploit,maldet"
SCAN_MAILBOXES="0"
MAILBOX_RECENT_HOURS=""
VERSION_SCAN_ENABLED="1"
APT_SECURITY_ENABLED="1"
VMRSS_MAX_MB="2000"
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
            SCAN_MAILBOXES) SCAN_MAILBOXES="$value" ;;
            MAILBOX_RECENT_HOURS) MAILBOX_RECENT_HOURS="$value" ;;
            VERSION_SCAN_ENABLED) VERSION_SCAN_ENABLED="$value" ;;
            APT_SECURITY_ENABLED) APT_SECURITY_ENABLED="$value" ;;
            VMRSS_MAX_MB) VMRSS_MAX_MB="$value" ;;
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
export OPENXS_VMRSS_MAX_KB=$((VMRSS_MAX_MB * 1024))
python3 pmf_scan.py scan php.yar filelist.txt > scan_results.txt 2> scan.log

# Proactive whitelist-drift check: a whitelisted file whose content has
# since changed would start matching again anyway on its own next scan -
# this flags it clearly and separately, as "needs re-validation" rather
# than mixed in as an unexplained new hit.
drift_output=$(python3 check_whitelist_drift.py whitelist.yar 2>&1) || true
drift_count=$(echo "$drift_output" | grep -c '^CHANGED\|^MISSING' || true)

# File integrity monitoring: configured files/dirs (/etc/openxs/fim_paths)
# checked against their last recorded baseline - unlike the whitelist
# drift check above, this watches arbitrary important files (configs,
# framework core, OpenXS's own code), not just our own exploit-scan
# whitelist entries. Nothing to check until someone runs
# `openxs_fim.py baseline` at least once (empty config = no-op, exit 0).
fim_output=$(python3 openxs_fim.py 2>&1) || true
echo "$fim_output" > fim_results.txt
fim_count=$(echo "$fim_output" | grep -c '^CHANGED\|^REMOVED\|^ADDED' || true)

# WordPress core / composer package version check (initial
# sversionscan-equivalent - see version_scan.py's own docstring).
version_output=""
version_count=0
if [ "$VERSION_SCAN_ENABLED" = "1" ]; then
    version_output=$(python3 version_scan.py "$FS_SCAN_ROOT" 2>&1) || true
    echo "$version_output" > version_results.txt
    version_count=$(echo "$version_output" | grep -c '^OUTDATED' || true)
fi

# Pending apt security updates - OS-level, not application-layer like
# the checks above (and not tied to SCAN_PATH/ACCOUNTS_DIR at all).
apt_output=""
apt_count=0
if [ "$APT_SECURITY_ENABLED" = "1" ]; then
    apt_output=$(python3 apt_security_check.py 2>&1) || true
    echo "$apt_output" > apt_security_results.txt
    apt_count=$(echo "$apt_output" | grep -c '^SECURITY' || true)
fi

# Mailbox virus scanning - opt-in, cxs's separate "virusscan" feature
# (ClamAV only, not the YARA ruleset - email attachments aren't PHP
# webshells). Off by default: not every server even has Maildir-format
# mail under ACCOUNTS_DIR, and some already scan at delivery time via
# amavisd/clamav-milter - mailbox_scan.py notes that, but never assumes
# it (confirmed on balrog: neither was active there despite being our
# largest mail-handling server).
mailbox_output=""
mailbox_count=0
if [ "$SCAN_MAILBOXES" = "1" ]; then
    export OPENXS_MAILBOX_RECENT_HOURS="$MAILBOX_RECENT_HOURS"
    mailbox_output=$(python3 mailbox_scan.py "$ACCOUNTS_DIR" 2>&1) || true
    echo "$mailbox_output" > mailbox_results.txt
    mailbox_count=$(echo "$mailbox_output" | grep -c '^VIRUS' || true)
fi

hits=$(grep -c . scan_results.txt || true)

if [ "$hits" -gt 0 ] || [ "$drift_count" -gt 0 ] || [ "$fim_count" -gt 0 ] || [ "$version_count" -gt 0 ] || [ "$apt_count" -gt 0 ] || [ "$mailbox_count" -gt 0 ]; then
    {
        if [ "$hits" -gt 0 ]; then
            echo "OpenXS: $hits genuine hit(s) on $HOST ($SCAN_LABEL)"
            echo ""
            cat scan_results.txt
            echo ""
        fi
        if [ "$drift_count" -gt 0 ]; then
            echo "=== Whitelist drift: $drift_count file(s) changed since being whitelisted (need re-validation) ==="
            echo "$drift_output"
            echo ""
        fi
        if [ "$fim_count" -gt 0 ]; then
            echo "=== File integrity: $fim_count file(s) differ from their baseline ==="
            echo "$fim_output"
            echo ""
        fi
        if [ "$version_count" -gt 0 ]; then
            echo "=== Outdated WordPress core: $version_count install(s) ==="
            echo "$version_output"
            echo ""
        fi
        if [ "$apt_count" -gt 0 ]; then
            echo "=== Pending apt security updates: $apt_count package(s) ==="
            echo "$apt_output"
            echo ""
        fi
        if [ "$mailbox_count" -gt 0 ]; then
            echo "=== Mailbox virus scan: $mailbox_count infected file(s) ==="
            echo "$mailbox_output"
        fi
    } | mail -s "[$HOST] OpenXS: $hits hit(s), $drift_count drift, $fim_count integrity, $version_count outdated, $apt_count apt-security, $mailbox_count mail-virus" "$EMAIL"
fi
