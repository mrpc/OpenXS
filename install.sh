#!/bin/bash
# OpenXS install script for a real (non-container) Debian/Ubuntu server.
#
# Installs: detection engine (php-malware-finder + our fix), the scan daemon
# (systemd service), ClamAV (virus scanning, cxs's "virusscan" equivalent),
# the scheduled scan + cron job, and the Webmin management module (if
# Webmin is present).
#
# Does NOT install mod_security or the CSF firewall hook - those are
# optional, install them from the Webmin dashboard once this is in place
# (same reasoning cxs itself used: virus/exploit scanning is the core, the
# firewall integration is an add-on).
#
# Safe to re-run (idempotent).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PMF_DIR=/opt/php-malware-finder

echo "==> Installing packages..."
apt-get update -qq
apt-get install -y -qq git python3 python3-yara yara mailutils cron \
    clamav-daemon clamav-freshclam

echo "==> Detection engine (php-malware-finder)..."
if [ ! -d "$PMF_DIR/.git" ]; then
    rm -rf "$PMF_DIR"
    git clone --depth 1 https://github.com/nbs-system/php-malware-finder.git /tmp/pmf-src-$$
    mv /tmp/pmf-src-$$/php-malware-finder "$PMF_DIR"
    mv /tmp/pmf-src-$$/.git "$PMF_DIR/.git"
    rm -rf /tmp/pmf-src-$$
else
    (cd "$PMF_DIR" && git pull -q)
fi
# Upstream bug: IsWhitelisted doesn't reference its own Custom rule (idempotent fix)
if ! grep -q "Misc or" "$PMF_DIR/whitelist.yar"; then
    sed -i 's/^        Misc$/        Misc or\n        Custom/' "$PMF_DIR/whitelist.yar"
fi

echo "==> Our own tools..."
cp "$HERE"/tools/*.py "$HERE"/tools/*.sh "$PMF_DIR/"
chmod +x "$PMF_DIR"/*.py "$PMF_DIR"/*.sh

echo "==> Settings + scan-history database..."
mkdir -p /etc/openxs /var/lib/openxs
if [ ! -f /etc/openxs/openxs.conf ]; then
    printf 'EMAIL=root@localhost\nSCAN_PATH=/var/www\n' > /etc/openxs/openxs.conf
fi

echo "==> Scan daemon (systemd service)..."
if command -v systemctl >/dev/null 2>&1; then
    cp "$HERE/tools/openxs-scand.service" /etc/systemd/system/openxs-scand.service
    systemctl daemon-reload
    systemctl enable --now openxs-scand
    echo "==> ClamAV..."
    systemctl enable --now clamav-daemon clamav-freshclam 2>/dev/null || true
else
    echo "    systemd not available on this host - start the daemon manually:"
    echo "    python3 $PMF_DIR/openxs-scand.py &"
fi

echo "==> Daily scheduled scan (cron)..."
cat > /etc/cron.d/openxs-scan <<'EOF'
17 2 * * * root /opt/php-malware-finder/run_scheduled_scan.sh >> /opt/php-malware-finder/cron.log 2>&1
EOF
chmod 644 /etc/cron.d/openxs-scan

if [ -d /usr/share/webmin ]; then
    echo "==> Webmin module..."
    cp -r "$HERE/webmin/openxs" /usr/share/webmin/openxs
    chmod +x /usr/share/webmin/openxs/*.cgi
    if [ -f /etc/webmin/webmin.acl ] && ! grep -q "^root:.*openxs" /etc/webmin/webmin.acl; then
        sed -i 's/^root: /root: openxs /' /etc/webmin/webmin.acl
    fi
    systemctl restart webmin 2>/dev/null || service webmin restart 2>/dev/null || true
else
    echo "==> Webmin not found - skipping UI module (CLI/cron still fully functional)"
fi

echo "==> Done."
echo "    mod_security + CSF firewall hook are optional - install them from"
echo "    the OpenXS Webmin dashboard if/when you want real-time upload blocking."
