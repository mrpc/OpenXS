FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-security2 \
    perl \
    libwww-perl \
    liblwp-protocol-https-perl \
    libgd-graph-perl \
    libnet-cidr-perl \
    curl \
    wget \
    git \
    gnupg2 \
    iproute2 \
    dnsutils \
    mailutils \
    clamav-daemon \
    clamav-freshclam \
    python3 \
    python3-yara \
    yara \
    sudo \
    iptables \
    cron \
    procps \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Webmin (official install script - unrelated company/domain, not affected by the
# ConfigServer shutdown)
RUN curl -o /tmp/webmin-setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repos.sh \
    && sh /tmp/webmin-setup-repos.sh -f \
    && apt-get update \
    && apt-get install -y webmin --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# CSF v15.00 GPLv3 (the final official release from Way to the Web before it shut down,
# community-mirrored here since download.configserver.com is dead - see README)
# install.sh does not auto-register CSF's own Webmin module even though
# webmin is already present at this point, so we copy it in ourselves.
RUN git clone --depth 1 https://github.com/centminmod/configserver-scripts.git /tmp/csf-fork \
    && cd /tmp/csf-fork && tar -xzf csf.tgz -C /tmp && cd /tmp/csf && sh install.sh \
    && cp -r /tmp/csf-fork/csf/webmin/csf /usr/share/webmin/csf \
    && chmod +x /usr/share/webmin/csf/*.cgi \
    && sed -i 's/^root: /root: csf /' /etc/webmin/webmin.acl \
    && rm -rf /tmp/csf-fork /tmp/csf*

# Cross-link: add an "Open OpenXS" button to CSF's own module page (GPLv3,
# fine to patch - unlike cxs, nothing here is obfuscated or license-restricted)
COPY csf-integration/patch_csf_link.py /tmp/patch_csf_link.py
RUN python3 /tmp/patch_csf_link.py && rm /tmp/patch_csf_link.py

# mod_security: enable + OWASP core rules as a baseline starting point.
# SecUploadKeepFiles is off by default, which means @inspectFile (used below)
# never gets a real file on disk to scan - it must be turned on explicitly.
RUN a2enmod security2 \
    && cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf \
    && sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf \
    && mkdir -p /opt/modsecurity/var/upload && chown www-data:www-data /opt/modsecurity/var/upload \
    && sed -i \
         -e 's|^#SecUploadDir /opt/modsecurity/var/upload/|SecUploadDir /opt/modsecurity/var/upload/|' \
         -e 's|^#SecUploadKeepFiles RelevantOnly|SecUploadKeepFiles On|' \
         -e 's|^#SecUploadFileMode 0600|SecUploadFileMode 0600|' \
         /etc/modsecurity/modsecurity.conf

# php-malware-finder (LGPL-3.0, nbs-system) - third-party tool, not vendored here
# Upstream bug: whitelist.yar/IsWhitelisted doesn't reference its own "Custom" rule -
# whitelisting silently does nothing without this fix.
RUN git clone --depth 1 https://github.com/nbs-system/php-malware-finder.git /tmp/pmf-src \
    && mv /tmp/pmf-src/php-malware-finder /opt/php-malware-finder \
    && mv /tmp/pmf-src/.git /opt/php-malware-finder/.git \
    && rm -rf /tmp/pmf-src \
    && sed -i 's/^        Misc$/        Misc or\n        Custom/' /opt/php-malware-finder/whitelist.yar

# our own tools (glue code on top of php-malware-finder)
COPY tools/ /opt/php-malware-finder/
RUN chmod +x /opt/php-malware-finder/*.sh /opt/php-malware-finder/*.py

# default settings + scan-history database location
RUN mkdir -p /etc/openxs /var/lib/openxs \
    && printf 'EMAIL=root@localhost\nSCAN_PATH=/var/www\n' > /etc/openxs/openxs.conf

# daily scheduled scan (alert-only, uses the settings above)
RUN echo '17 2 * * * root /opt/php-malware-finder/run_scheduled_scan.sh >> /opt/php-malware-finder/cron.log 2>&1' \
    > /etc/cron.d/openxs-scan \
    && chmod 644 /etc/cron.d/openxs-scan

# CSF <-> mod_security firewall integration (see csf-integration/README.md)
COPY csf-integration/modsecurity-openxs.conf /etc/modsecurity/openxs.conf
COPY csf-integration/regex.custom.pm /etc/csf/regex.custom.pm
RUN sed -i 's|CUSTOM1_LOG = "/var/log/customlog"|CUSTOM1_LOG = "/var/log/apache2/error.log"|' /etc/csf/csf.conf \
    && sed -i 's/^TESTING = "1"/TESTING = "0"/' /etc/csf/csf.conf \
    && sed -i 's/,993,995"/,993,995,10000"/' /etc/csf/csf.conf

# OpenXS Webmin module
COPY webmin/openxs/ /usr/share/webmin/openxs/
RUN chmod +x /usr/share/webmin/openxs/*.cgi \
    && sed -i 's/^root: /root: openxs /' /etc/webmin/webmin.acl

EXPOSE 80 443 10000

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
