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

apachectl configtest
systemctl restart apache2 2>/dev/null || service apache2 restart
echo "Apache restarted."

# Persists daily block counts into openxs.db - without this, the Stats
# page's mod_security chart/column would only ever show whatever's
# still in the current (unrotated) Apache error logs, silently losing
# older days once logrotate does its thing. Scheduled before 02:17's
# scan and well before a typical distro's default logrotate run.
cat > /etc/cron.d/openxs-modsec-record <<'EOF'
10 2 * * * root python3 /opt/php-malware-finder/openxs_modsec_record.py >> /opt/php-malware-finder/cron.log 2>&1
EOF
chmod 644 /etc/cron.d/openxs-modsec-record
python3 /opt/php-malware-finder/openxs_modsec_record.py 2>&1 || true
