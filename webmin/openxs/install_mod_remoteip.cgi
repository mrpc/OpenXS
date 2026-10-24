#!/usr/bin/perl
# install_mod_remoteip.cgi
# Thin wrapper around tools/install_mod_remoteip.sh (same script
# install.sh calls with --with-remoteip) - single source of truth for
# the logic. Safe to re-run (refreshes Cloudflare's published IP
# ranges and re-applies the config).

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Installing mod_remoteip...");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";
my $out = `bash $pmf_dir/install_mod_remoteip.sh 2>&1`;
print &html_escape($out);
print "</pre>";

print "<p><a href='settings.cgi'>&laquo; Back to Settings</a></p>\n";
&ui_print_footer("/", "Webmin index page");
