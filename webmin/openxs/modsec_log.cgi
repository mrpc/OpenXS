#!/usr/bin/perl
# modsec_log.cgi
# Summary of recent ModSecurity blocks across every Apache error log on
# the box (shared + per-Virtualmin-domain), grouped by host/uri/rule -
# see tools/openxs_modsec_log.py for why it's grouped this way.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;

print &ui_subheading("mod_security blocks - grouped by host/path/rule");
print "<p>A repeated block on the SAME host+path is worth a closer look - either a real false " .
	"positive (exclude it in <a href='settings.cgi'>Settings</a>), or an underlying issue " .
	"ModSecurity is correctly catching (this is how a real information-leak bug on a live site " .
	"was found and fixed this way). Scattered one-off hits across many different paths are " .
	"usually just attack-scanner noise being correctly blocked.</p>\n";

my $out = `python3 $pmf_dir/openxs_modsec_log.py 2>&1`;
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:500px;overflow:auto'>";
print $out ne "" ? &html_escape($out) : "(no ModSecurity blocks found in any log on this server)";
print "</pre>";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
