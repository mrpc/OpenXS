#!/bin/bash
# mod_security @inspectFile hook, invoked on every file upload (FILES_TMPNAMES).
#
# Talks to openxs-scand (a persistent daemon that keeps the compiled YARA
# ruleset in memory) over a Unix socket, instead of spawning a fresh `yara`
# process that would recompile the ruleset on every single upload.
#
# Protocol note: @inspectFile does NOT read the exit code. It reads one line
# from stdout: "1" = approve/clean, "0 <reason>" = reject/malware detected.
# We just forward the daemon's response verbatim - same format.
exec python3 /opt/php-malware-finder/openxs-scan-client.py "$1"
