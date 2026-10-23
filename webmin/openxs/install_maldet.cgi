#!/usr/bin/perl
# install_maldet.cgi
# Thin wrapper around tools/install_maldet.sh (same script install.sh
# calls with --with-maldet) - single source of truth for the logic.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Installing maldet...");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";
my $out = `bash $pmf_dir/install_maldet.sh 2>&1`;
print &html_escape($out);
print "</pre>";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
