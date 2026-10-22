#!/bin/bash
# mod_security @inspectFile hook, invoked on every file upload (FILES_TMPNAMES).
# Runs the php-malware-finder YARA ruleset against the uploaded file.
#
# Protocol note: @inspectFile does NOT read the exit code. It reads one line
# from stdout: "1" = approve/clean, "0 <reason>" = reject/malware detected.
RULESET=/opt/php-malware-finder/php.yar
FILE="$1"

MATCH=$(yara -r "$RULESET" "$FILE" 2>/dev/null | head -1)
if [ -n "$MATCH" ]; then
    echo "0 openxs-scan: $MATCH"
else
    echo "1"
fi
exit 0
