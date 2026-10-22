#!/usr/bin/perl
# install_modsecurity.cgi
# Installs mod_security2, enables it, configures upload retention (required
# for @inspectFile to have a real file to scan), and installs our rule.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Installing mod_security...");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";

my @steps = (
	"apt-get update -qq",
	"apt-get install -y -qq apache2 libapache2-mod-security2",
	"a2enmod security2",
	"cp -n /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf",
	"sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf",
	"mkdir -p /opt/modsecurity/var/upload",
	"chown www-data:www-data /opt/modsecurity/var/upload",
	"sed -i -e 's|^#SecUploadDir /opt/modsecurity/var/upload/|SecUploadDir /opt/modsecurity/var/upload/|' ".
	  "-e 's|^#SecUploadKeepFiles RelevantOnly|SecUploadKeepFiles On|' ".
	  "-e 's|^#SecUploadFileMode 0600|SecUploadFileMode 0600|' /etc/modsecurity/modsecurity.conf",
	);
foreach my $cmd (@steps) {
	print &html_escape("\$ $cmd\n");
	my $out = `$cmd 2>&1`;
	print &html_escape($out) if ($out ne "");
	}

open(my $fh, '>', $modsec_rule);
print $fh <<EOF;
SecRule FILES_TMPNAMES "\@inspectFile /opt/php-malware-finder/inspectfile.sh" \\
  "id:9000001,phase:2,t:none,log,deny,status:403,msg:'openxs-scan detected malicious upload [id \\"9000001\\"]'"
EOF
close($fh);
print &html_escape("Wrote $modsec_rule\n");

my $out = `apachectl configtest 2>&1`;
print &html_escape($out);
system("service apache2 restart >/dev/null 2>&1");
print "Apache restarted.\n";

print "</pre>";
print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
