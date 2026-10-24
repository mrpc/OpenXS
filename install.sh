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
# now, or install them later from the Webmin dashboard. maldet (a third,
# independent detector) is also optional - pass --with-maldet, or install
# it later from the dashboard the same way.
#
# Safe to re-run (idempotent).
set -euo pipefail

# Pinned to our own fork, not upstream HEAD - see Dockerfile for why. Forks
# do NOT auto-sync with upstream; bump this deliberately after reviewing
# the upstream diff. To use our fork's latest commit instead of the pinned
# one, override with the branch name: PMF_COMMIT=master sudo -E ./install.sh
PMF_FORK=https://github.com/mrpc/php-malware-finder.git
PMF_COMMIT="${PMF_COMMIT:-ab4d7622714c6bdfc992339a5e6925207b5071b8}"

WITH_MODSECURITY=0
WITH_CSF_HOOK=0
WITH_MALDET=0
for arg in "$@"; do
    case "$arg" in
        --with-modsecurity) WITH_MODSECURITY=1 ;;
        --with-csf-hook) WITH_CSF_HOOK=1 ;;
        --with-maldet) WITH_MALDET=1 ;;
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
apt-get install -y -qq git python3 python3-yara yara mailutils cron inotify-tools

echo "==> Detection engine (php-malware-finder)..."
if [ -d "$PMF_DIR" ] && [ ! -d "$PMF_DIR/.git" ]; then
    backup="${PMF_DIR}.bak-$(date +%Y%m%d%H%M%S)"
    echo "    $PMF_DIR exists but isn't our git clone - moving it aside to $backup"
    mv "$PMF_DIR" "$backup"
fi
if [ ! -d "$PMF_DIR/.git" ]; then
    git init -q "/tmp/pmf-src-$$"
    (cd "/tmp/pmf-src-$$" \
        && git remote add origin "$PMF_FORK" \
        && git fetch -q --depth 1 origin "$PMF_COMMIT" \
        && git checkout -q FETCH_HEAD)
    mv "/tmp/pmf-src-$$/php-malware-finder" "$PMF_DIR"
    mv "/tmp/pmf-src-$$/.git" "$PMF_DIR/.git"
    rm -rf "/tmp/pmf-src-$$"
else
    # Pinned to a specific commit (not a branch - deliberately, see the
    # comment on PMF_COMMIT above), so the clone is in detached-HEAD
    # state: plain 'git pull' fails there ("You are not currently on a
    # branch"). Re-fetch whatever $PMF_COMMIT currently is - a no-op if
    # already there, moves forward if a newer OpenXS release bumped the
    # pin. A plain 'git checkout FETCH_HEAD' would write files to their
    # real paths in the commit's tree (top-level README.md/debian/ AND
    # a php-malware-finder/ subdirectory) - but PMF_DIR's working tree
    # only ever held that subdirectory's own contents, flattened up a
    # level, ever since the very first install below did the same move.
    # 'git archive | tar --strip-components' extracts just that
    # subdirectory's files to their flattened paths instead, matching
    # what's actually on disk; HEAD is moved separately so git log and
    # the dashboard's commit display stay accurate.
    (cd "$PMF_DIR" && git fetch -q origin "$PMF_COMMIT" \
        && git archive FETCH_HEAD -- php-malware-finder | tar -x --strip-components=1 \
        && git update-ref HEAD FETCH_HEAD)
fi
# Upstream bug: IsWhitelisted doesn't reference its own Custom rule (idempotent fix)
if ! grep -q "Misc or" "$PMF_DIR/whitelist.yar"; then
    sed -i 's/^        Misc$/        Misc or\n        Custom/' "$PMF_DIR/whitelist.yar"
fi

echo "==> Our own tools..."
cp "$HERE"/tools/*.py "$HERE"/tools/*.sh "$PMF_DIR/"
chmod +x "$PMF_DIR"/*.py "$PMF_DIR"/*.sh
cp -r "$HERE"/tools/openxs-rules "$PMF_DIR/"
cp -r "$HERE"/tools/wp_checksums "$PMF_DIR/"

echo "==> ClamAV (2nd detector)..."
bash "$PMF_DIR/install_clamav.sh"

echo "==> Settings + scan-history database..."
mkdir -p /etc/openxs /var/lib/openxs
if [ ! -f /etc/openxs/openxs.conf ]; then
    VERSION_SCAN_ENABLED=1
    APT_SECURITY_ENABLED=1
    SCAN_MAILBOXES=0
    if [ -t 0 ]; then
        read -r -p "Enable nightly WordPress/composer version + apt security update checks? [Y/n] " answer
        if [ "$answer" = "n" ] || [ "$answer" = "N" ]; then
            VERSION_SCAN_ENABLED=0
            APT_SECURITY_ENABLED=0
        fi
        read -r -p "Enable nightly mailbox virus scanning (ClamAV, cxs's separate 'virusscan')? [y/N] " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            SCAN_MAILBOXES=1
        fi
    else
        echo "    Not running interactively - defaulting to version/apt checks on, mailbox scan off."
        echo "    Change any of these later in the Webmin Settings page."
    fi
    if [ -d /etc/webmin/virtual-server ]; then
        # Virtualmin detected - real sites live under /home/<user>/public_html,
        # not /var/www (Debian's default, empty/stock on a Virtualmin box).
        # Scanning /var/www by default here would scan nothing real at all.
        echo "    Virtualmin detected - defaulting the scheduled scan to every account (/home/*/public_html)."
        printf 'EMAIL=root@localhost\nSCAN_PATH=/var/www\nQUARANTINE_ENABLED=0\nVERSION_SCAN_ENABLED=%s\nAPT_SECURITY_ENABLED=%s\nSCAN_MAILBOXES=%s\nSCAN_MODE=accounts\nACCOUNTS_DIR=/home\nACCOUNTS_SUBPATH=public_html\n' \
            "$VERSION_SCAN_ENABLED" "$APT_SECURITY_ENABLED" "$SCAN_MAILBOXES" > /etc/openxs/openxs.conf
    else
        printf 'EMAIL=root@localhost\nSCAN_PATH=/var/www\nQUARANTINE_ENABLED=0\nVERSION_SCAN_ENABLED=%s\nAPT_SECURITY_ENABLED=%s\nSCAN_MAILBOXES=%s\n' \
            "$VERSION_SCAN_ENABLED" "$APT_SECURITY_ENABLED" "$SCAN_MAILBOXES" > /etc/openxs/openxs.conf
    fi
fi
# Always refresh OPENXS_SRC (even on a re-run/upgrade, in case this clone
# moved) - self-update (Webmin dashboard) needs to know where to git pull.
if grep -q '^OPENXS_SRC=' /etc/openxs/openxs.conf 2>/dev/null; then
    sed -i "s|^OPENXS_SRC=.*|OPENXS_SRC=$HERE|" /etc/openxs/openxs.conf
else
    echo "OPENXS_SRC=$HERE" >> /etc/openxs/openxs.conf
fi

echo "==> File integrity monitoring - initial baseline..."
if [ ! -f /etc/openxs/fim_paths ]; then
    cp "$HERE/tools/fim_paths.default" /etc/openxs/fim_paths
fi
python3 "$PMF_DIR/openxs_fim.py" baseline || true

echo "==> Scan daemon (systemd service)..."
if command -v systemctl >/dev/null 2>&1; then
    cp "$HERE/tools/openxs-scand.service" /etc/systemd/system/openxs-scand.service
    # Watch daemon: service file installed but not started - it exits
    # immediately until WATCH_PATHS is set (Webmin Settings or
    # /etc/openxs/openxs.conf), so enabling it by default would be a
    # no-op that just confuses `systemctl status`.
    cp "$HERE/tools/openxs-watchd.service" /etc/systemd/system/openxs-watchd.service
    # Alert-on-failure template unit, triggered by both of the above via
    # OnFailure= - covers the kernel MemoryMax OOM-kill case, which gives
    # the daemon's own Python code no chance to send anything itself.
    cp "$HERE/tools/openxs-alert@.service" /etc/systemd/system/openxs-alert@.service
    systemctl daemon-reload
    systemctl enable --now openxs-scand
else
    echo "    systemd not available on this host - start the daemon manually:"
    echo "    python3 $PMF_DIR/openxs-scand.py &"
fi

echo "==> Daily scheduled scan (cron)..."
cat > /etc/cron.d/openxs-scan <<'EOF'
17 2 * * * root /opt/php-malware-finder/run_scheduled_scan.sh >> /opt/php-malware-finder/cron.log 2>&1
EOF
chmod 644 /etc/cron.d/openxs-scan

echo "==> Log rotation..."
cp "$HERE/tools/openxs-logrotate.conf" /etc/logrotate.d/openxs

if [ -d /usr/share/webmin ]; then
    echo "==> Webmin module..."
    rm -rf /usr/share/webmin/openxs
    cp -r "$HERE/webmin/openxs" /usr/share/webmin/openxs
    chmod +x /usr/share/webmin/openxs/*.cgi
    if [ -f /etc/webmin/webmin.acl ] && ! grep -q "^root:.*openxs" /etc/webmin/webmin.acl; then
        sed -i 's/^root: /root: openxs /' /etc/webmin/webmin.acl
    fi
    systemctl restart webmin 2>/dev/null || service webmin restart 2>/dev/null || true

    if [ -d /etc/webmin/status ]; then
        echo "    Adding to Webmin's Servers Status dashboard widget..."
        mkdir -p /etc/webmin/status/services
        cat > /etc/webmin/status/services/openxs-watchd.serv <<'EOF'
id=openxs-watchd
type=init
action=openxs-watchd
desc=OpenXS Watch Daemon
depends=openxs
EOF
        cat > /etc/webmin/status/services/openxs-scand.serv <<'EOF'
id=openxs-scand
type=init
action=openxs-scand
desc=OpenXS Scan Daemon
depends=openxs
EOF
    fi
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

echo "==> maldet (third, independent detector)..."
if [ "$WITH_MALDET" = "1" ]; then
    bash "$PMF_DIR/install_maldet.sh"
else
    echo "    Skipped (pass --with-maldet, or install/reconfigure later from the Webmin dashboard)."
fi

if [ "$(systemctl is-active maldet 2>/dev/null)" = "active" ]; then
    echo "==> Note: maldet's own --monitor daemon (maldet.service) is already running on this server."
    echo "    If you later enable OpenXS's own watch daemon (watchd), both would watch the same"
    echo "    directories independently (double inotify watches, double work per file change) -"
    echo "    watchd already gets 100% of maldet's detection value via its own integration. The"
    echo "    Webmin dashboard will offer to disable maldet's monitor the first time you start watchd."
fi

echo "==> Checking for an existing cxs (ConfigServer eXploit Scanner) install..."
cxs_preview=$(python3 "$PMF_DIR/migrate_from_cxs.py" disable-cxs 2>/dev/null) || true
if echo "$cxs_preview" | grep -q '^+ '; then
    echo "$cxs_preview"
    echo
    if [ -t 0 ]; then
        read -r -p "Disable cxs entirely (every cron entry above, and its Watch daemon), since OpenXS already replaces it? [y/N] " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            python3 "$PMF_DIR/migrate_from_cxs.py" disable-cxs --apply
        else
            echo "    Skipped. Re-run later: python3 $PMF_DIR/migrate_from_cxs.py disable-cxs --apply"
        fi
    else
        echo "    Not running interactively - skipped."
        echo "    Re-run later: python3 $PMF_DIR/migrate_from_cxs.py disable-cxs --apply"
    fi
fi

echo "==> Done."
