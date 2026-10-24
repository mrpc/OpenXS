#!/usr/bin/perl
# false_positive_export.cgi
# Dumps every recorded "mark false positive" click as ready-to-paste
# Markdown (tools/openxs_fp_export.py) - there's no real telemetry
# pipeline yet, so this is the manual stand-in: copy this and paste it
# into a new issue on https://github.com/mrpc/OpenXS/issues/new to help
# improve detection rules upstream.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Export false positive reports");
print "<p>Every \"Mark false positive\"/\"Exclude rule\"/\"Exclude path\" click on this server, as a Markdown ".
	"table. Copy the text below and paste it into ".
	"<a href='https://github.com/mrpc/OpenXS/issues/new' target='_blank' rel='noopener'>a new GitHub issue</a> - ".
	"this helps improve detection rules upstream, since there's no automatic telemetry yet.</p>\n";

my $out = `python3 $pmf_dir/openxs_fp_export.py 2>&1`;
print "<textarea rows='20' cols='120' style='font-family:monospace' onclick='this.select()' readonly>" .
	&html_escape($out) . "</textarea>\n";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
