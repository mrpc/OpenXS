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

# The unit's own log since shortly before the failure, minus the
# per-file RATE-LIMITED noise, is where the real reason is - by now systemd
# has usually restarted it already, so `systemctl status` alone shows the
# new instance, not why the old one died.
LOG=$(journalctl -u "$UNIT" --since "-3min" --no-pager -o short-iso 2>&1 | grep -v "RATE-LIMITED" | tail -60 || true)
if grep -qiE "oom-kill|oom_memcg|Memory limit" <<<"$LOG"; then
    CAUSE="the kernel killed it for exceeding its memory limit (MemoryMax)."
elif grep -q "RSS exceeded" <<<"$LOG"; then
    CAUSE="it exited itself after crossing its own configured RSS backstop."
elif grep -q "Traceback" <<<"$LOG"; then
    CAUSE="an unhandled Python exception (crash) - traceback below."
else
    CAUSE="unknown - see the log below."
fi

{
    echo "$UNIT failed on $HOST at $(date '+%Y-%m-%d %H:%M:%S')."
    echo
    echo "Cause: $CAUSE"
    echo "systemd's Restart=on-failure should already have brought it back up."
    echo
    systemctl status "$UNIT" --no-pager 2>&1 | head -5
    echo
    echo "Recent log:"
    if grep -q "Traceback" <<<"$LOG"; then
        sed -n '/Traceback/,$p' <<<"$LOG" | tail -40
    else
        tail -25 <<<"$LOG"
    fi
} | mail -s "[$HOST] $UNIT failed" "$EMAIL"
