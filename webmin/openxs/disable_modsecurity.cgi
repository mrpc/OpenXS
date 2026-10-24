#!/usr/bin/perl
# disable_modsecurity.cgi
# Symmetric counterpart to install_modsecurity.cgi - a2dismod (keeps
# every config file in place, including the openxs.conf upload-scan
# hook and any exclusions/rule-exclusions/mode overrides already set
# up), so re-"Install"ing later (a2enmod + idempotent reapply) picks
# up exactly where this left off.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Disabling mod_security...");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";
my $out = `a2dismod security2 2>&1 && (apache2ctl -t 2>&1 && (systemctl reload apache2 2>&1 || service apache2 reload 2>&1))`;
print &html_escape($out);
print "</pre>";
print "<p>mod_security disabled (Apache module unloaded, config files left untouched). ".
	"Use \"Install\" / \"Re-apply recommended config\" on the dashboard to re-enable it.</p>\n";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
