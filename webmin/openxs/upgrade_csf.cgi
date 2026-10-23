#!/usr/bin/perl
# upgrade_csf.cgi
# Upgrades an old (pre-GPLv3, < v15.00) CSF install to the pinned
# open-source release - see tools/upgrade_csf.py for the actual steps
# and why they're safe (confirmed against the fork's own migration
# guide, not guessed).

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Upgrading CSF...");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:500px;overflow:auto'>";
my $out = `python3 $pmf_dir/upgrade_csf.py --apply 2>&1`;
print &html_escape($out);
print "</pre>";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
