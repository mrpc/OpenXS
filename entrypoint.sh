#!/bin/bash
set -e

mkdir -p /run/openxs
python3 /opt/php-malware-finder/openxs-scand.py > /var/log/openxs-scand.log 2>&1 &
# give it a moment to compile the ruleset and bind the socket before Apache
# starts accepting uploads
for i in $(seq 1 20); do
    [ -S /run/openxs/scan.sock ] && break
    sleep 0.5
done

# ClamAV: download signatures if missing, then start the daemon - in the
# background since this can take a while and container/Apache startup
# shouldn't block on it. The YARA-only path already works without it;
# pmf_scan.py/inspectfile.sh degrade gracefully if clamd isn't up yet.
(
    if [ ! -s /var/lib/clamav/main.cvd ] && [ ! -s /var/lib/clamav/main.cld ]; then
        freshclam --quiet || true
    fi
    service clamav-daemon start || true
) &

service apache2 start
service cron start
service webmin start
/etc/init.d/csf start 2>&1 || echo "csf start: $?"
/etc/init.d/lfd start 2>&1 || echo "lfd start: $?"

echo "Ready. Webmin: https://localhost:10000  Apache: http://localhost:80"
tail -f /var/log/apache2/error.log /var/log/lfd.log /var/log/openxs-scand.log 2>/dev/null
