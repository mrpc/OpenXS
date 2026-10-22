#!/bin/bash
set -e

service apache2 start
service cron start
service webmin start
/etc/init.d/csf start 2>&1 || echo "csf start: $?"
/etc/init.d/lfd start 2>&1 || echo "lfd start: $?"

echo "Ready. Webmin: https://localhost:10000  Apache: http://localhost:80"
tail -f /var/log/apache2/error.log /var/log/lfd.log 2>/dev/null
