#!/bin/bash
# openxs_alert.sh <unit-name>
# Wired via OnFailure= in openxs-watchd.service/openxs-scand.service - fires
# on ANY failure of either unit, including the kernel-enforced MemoryMax/
# MemorySwapMax=0 OOM-kill (which gives the daemon's own Python code no
# chance to run anything before SIGKILL - this is the only way to notify
# for that specific case). Also fires for the daemon's own graceful
# self-exit (check_rss_guard/OPENXS_SCAND_MAX_RSS_MB), which is otherwise
# harmless noise here since that path already logs its own reason.
set -euo pipefail

UNIT="${1:?usage: openxs_alert.sh <unit-name>}"
CONFIG=/etc/openxs/openxs.conf
EMAIL="root@localhost"
if [ -f "$CONFIG" ]; then
    while IFS='=' read -r key value; do
        [ "$key" = "EMAIL" ] && EMAIL="$value"
    done < "$CONFIG"
fi
HOST=$(hostname -f)

{
    echo "$UNIT failed on $HOST at $(date '+%Y-%m-%d %H:%M:%S')."
    echo
    echo "Likely cause: either the kernel killed it for exceeding its memory"
    echo "limit (MemoryMax), or it exited itself after crossing its own"
    echo "configured RSS backstop - systemd's Restart=on-failure should"
    echo "already have brought it back up. Recent log:"
    echo
    systemctl status "$UNIT" --no-pager -l 2>&1 | tail -20
} | mail -s "[$HOST] $UNIT failed" "$EMAIL"
