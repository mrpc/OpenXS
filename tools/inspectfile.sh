#!/bin/bash
# mod_security @inspectFile hook, invoked on every file upload (FILES_TMPNAMES).
#
# Two detectors, YARA first then ClamAV (cxs's exploitscan + virusscan
# equivalents):
#   1. openxs-scand - a persistent daemon that keeps the compiled YARA
#      ruleset in memory, instead of spawning a fresh `yara` process that
#      would recompile the ruleset on every single upload.
#   2. clamdscan - only runs if YARA found nothing, since it's a single-file
#      check (no batching benefit here, unlike the bulk scheduled scan).
#      Silently skipped if ClamAV isn't installed.
#
# Protocol note: @inspectFile does NOT read the exit code. It reads one line
# from stdout: "1" = approve/clean, "0 <reason>" = reject/malware detected.
FILE="$1"

RESULT=$(python3 /opt/php-malware-finder/openxs-scan-client.py "$FILE")
if [[ "$RESULT" != 1* ]]; then
    echo "$RESULT"
    exit 0
fi

if command -v clamdscan >/dev/null 2>&1; then
    # Only a "<path>: <sig> FOUND" line is a detection (same parsing as
    # pmf_scan.py's clamav_scan). clamd also prints "<path>: <reason> ERROR"
    # lines, which must not be mistaken for a hit: e.g. Apache's PrivateTmp
    # makes the upload a "disconnected path" for clamd's AppArmor profile,
    # so every --fdpass check of it fails with "Not a regular file ERROR".
    # In that case retry with --stream, which sends the content over the
    # socket and so never needs clamd to resolve the path.
    CLAM_OUT=$(clamdscan --fdpass --no-summary --infected "$FILE" 2>/dev/null)
    if ! grep -q ' FOUND$' <<<"$CLAM_OUT" && grep -q ' ERROR$' <<<"$CLAM_OUT"; then
        CLAM_OUT=$(clamdscan --stream --no-summary --infected "$FILE" 2>/dev/null)
    fi
    CLAM_OUT=$(grep ' FOUND$' <<<"$CLAM_OUT")
    if [ -n "$CLAM_OUT" ]; then
        SIG=$(echo "$CLAM_OUT" | head -1 | sed -E 's/^.*: (.+) FOUND$/\1/')
        echo "0 openxs-scan: $SIG (ClamAV)"
        exit 0
    fi
fi

echo "1"
