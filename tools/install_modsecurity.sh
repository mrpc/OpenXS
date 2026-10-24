#!/bin/bash
# Installs mod_security2, enables it, configures upload retention (required
# for @inspectFile to have a real file to scan), and installs our rule.
# Used both by install.sh (--with-modsecurity) and by the Webmin dashboard's
# "Install" button (install_modsecurity.cgi) - single source of truth.
set -euo pipefail

MODSEC_RULE=/etc/modsecurity/openxs.conf

echo "==> Installing mod_security..."
apt-get update -qq
apt-get install -y -qq apache2 libapache2-mod-security2
a2enmod security2
cp -n /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
mkdir -p /opt/modsecurity/var/upload
chown www-data:www-data /opt/modsecurity/var/upload
sed -i \
    -e 's|^#SecUploadDir /opt/modsecurity/var/upload/|SecUploadDir /opt/modsecurity/var/upload/|' \
    -e 's|^#SecUploadKeepFiles RelevantOnly|SecUploadKeepFiles On|' \
    -e 's|^#SecUploadFileMode 0600|SecUploadFileMode 0600|' \
    /etc/modsecurity/modsecurity.conf

# A dedicated include point loaded AFTER the CRS rule files
# (/usr/share/modsecurity-crs/*.load, included a few lines above this in
# security2.conf) - SecRuleUpdateTargetById (openxs_modsec_rule_exclusions.py)
# targets an already-defined rule ID, so it has to run after CRS defines
# it; the existing /etc/modsecurity/*.conf include loads BEFORE CRS and
# silently no-ops such a directive (confirmed by hand on anotherserver.com's
# incident, 2026-10-24 - apachectl configtest passes either way, only an
# actual request shows whether it took effect).
#
# Edits mods-available/, NOT mods-enabled/ - a2enmod/a2dismod expect
# mods-enabled/*.conf to stay a symlink to mods-available/*.conf; `sed -i`
# on the symlink path replaces it with a real file (sed -i writes a new
# file then renames over the original path), silently breaking that
# tracking - confirmed by hand, 2026-10-24 (a2enmod then refuses to
# touch it: "is a real file, not touching it").
mkdir -p /etc/modsecurity/after-crs
if ! grep -q 'after-crs' /etc/apache2/mods-available/security2.conf; then
    sed -i '/IncludeOptional \/usr\/share\/modsecurity-crs\/\*.load/a\\tIncludeOptional /etc/modsecurity/after-crs/*.conf' \
        /etc/apache2/mods-available/security2.conf
fi

cat > "$MODSEC_RULE" <<'EOF'
SecRule FILES_TMPNAMES "@inspectFile /opt/php-malware-finder/inspectfile.sh" \
  "id:9000001,phase:2,t:none,log,deny,status:403,msg:'openxs-scan detected malicious upload [id \"9000001\"]'"
EOF
echo "Wrote $MODSEC_RULE"

# PHP2Shell (CVE-2026-109618/109619) request/response-pattern blocking -
# vendored from https://github.com/ikow/php2shell-poc (MIT), see that
# file's own header. /etc/modsecurity/*.conf is already auto-included
# by Apache's security2.conf, so just dropping it there is enough.
# Only installed if at least one PHP version here is actually exposed -
# minimizes false-positive surface on a server that's already fully
# patched, where the vulnerability itself can't be triggered at all.
rm -f /etc/modsecurity/openxs-php2shell.conf
if python3 "$(dirname "$0")/php2shell_check.py"; then
    echo "All installed PHP versions already protected against PHP2Shell - skipping its ModSecurity rules."
else
    cp "$(dirname "$0")/modsec-rules/php2shell.conf" /etc/modsecurity/openxs-php2shell.conf
    echo "Wrote /etc/modsecurity/openxs-php2shell.conf (at least one unprotected PHP version found)"
fi

python3 "$(dirname "$0")/openxs_modsec_mode.py" > /dev/null
python3 "$(dirname "$0")/openxs_modsec_rule_exclusions.py" > /dev/null
python3 "$(dirname "$0")/openxs_modsec_exclusions.py" > /dev/null

apachectl configtest
systemctl restart apache2 2>/dev/null || service apache2 restart
echo "Apache restarted."

# Its periodic upkeep (daily block-count history, the "grouped by
# host/path/rule" view's cache) runs as a job inside openxs_collector.py,
# whose own single cron entry already exists from install.sh - just do
# an immediate first run now so the dashboard isn't empty until that
# cron next fires.
python3 /opt/php-malware-finder/openxs_modsec_record.py 2>&1 || true
