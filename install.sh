#!/bin/bash
# OpenXS install script for a real (non-container) Debian/Ubuntu server.
#
# Installs: detection engine (php-malware-finder + our fix), the scan daemon
# (systemd service), ClamAV (virus scanning, cxs's "virusscan" equivalent),
# the scheduled scan + cron job, and the Webmin management module (if
# Webmin is present).
#
# mod_security and the CSF firewall hook are optional (real-time upload
# blocking) - pass --with-modsecurity and/or --with-csf-hook to install them
# now, or install them later from the Webmin dashboard.
#
# Safe to re-run (idempotent).
set -euo pipefail

WITH_MODSECURITY=0
WITH_CSF_HOOK=0
for arg in "$@"; do
    case "$arg" in
        --with-modsecurity) WITH_MODSECURITY=1 ;;
        --with-csf-hook) WITH_CSF_HOOK=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this script must be run as root (e.g. with sudo)." >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "ERROR: apt-get not found. OpenXS's install.sh currently only supports" >&2
    echo "       Debian/Ubuntu (apt-based) systems. See the README roadmap." >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PMF_DIR=/opt/php-malware-finder

echo "==> Installing packages..."
if ! apt-get update -qq; then
    echo "ERROR: apt-get update failed - check network/apt sources and retry." >&2
    exit 1
fi
apt-get install -y -qq git python3 python3-yara yara mailutils cron \
    clamav-daemon clamav-freshclam

echo "==> Detection engine (php-malware-finder)..."
if [ -d "$PMF_DIR" ] && [ ! -d "$PMF_DIR/.git" ]; then
    backup="${PMF_DIR}.bak-$(date +%Y%m%d%H%M%S)"
    echo "    $PMF_DIR exists but isn't our git clone - moving it aside to $backup"
    mv "$PMF_DIR" "$backup"
fi
if [ ! -d "$PMF_DIR/.git" ]; then
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
    printf 'EMAIL=root@localhost\nSCAN_PATH=/var/www\nQUARANTINE_ENABLED=0\n' > /etc/openxs/openxs.conf
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
    rm -rf /usr/share/webmin/openxs
    cp -r "$HERE/webmin/openxs" /usr/share/webmin/openxs
    chmod +x /usr/share/webmin/openxs/*.cgi
    if [ -f /etc/webmin/webmin.acl ] && ! grep -q "^root:.*openxs" /etc/webmin/webmin.acl; then
        sed -i 's/^root: /root: openxs /' /etc/webmin/webmin.acl
    fi
    systemctl restart webmin 2>/dev/null || service webmin restart 2>/dev/null || true
else
    echo "==> Webmin not found - skipping UI module (CLI/cron still fully functional)."
    echo "    mod_security/CSF-hook install (if requested below) has no Webmin"
    echo "    dashboard to manage from later, but still works via cron/CLI."
fi

echo "==> mod_security (real-time upload blocking)..."
if [ "$WITH_MODSECURITY" = "1" ]; then
    bash "$PMF_DIR/install_modsecurity.sh"
else
    echo "    Skipped (pass --with-modsecurity, or install later from the Webmin dashboard)."
fi

echo "==> CSF firewall hook..."
if [ -f /etc/csf/csf.conf ]; then
    echo "    CSF detected."
    if [ "$WITH_CSF_HOOK" = "1" ]; then
        python3 "$PMF_DIR/install_csf_hook.py"
    else
        echo "    Skipped (pass --with-csf-hook, or install later from the Webmin dashboard)."
    fi
else
    echo "    CSF not found on this server - nothing to hook into. Skipping."
fi

echo "==> Done."
