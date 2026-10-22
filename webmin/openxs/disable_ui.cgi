#!/usr/bin/perl
# disable_ui.cgi
# cxs's /etc/cxs/cxs.disableui equivalent: a one-way kill-switch for this
# module's entire web UI. Checked in openxs-lib.pl, required by every page.

require './openxs-lib.pl';
&ReadParse();

open(my $fh, '>', $ui_disabled_file) || die "Could not create $ui_disabled_file: $!";
close($fh);

&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print "<p>This UI is now disabled. Remove <code>$ui_disabled_file</code> on the server to re-enable it.</p>\n";
&ui_print_footer("/", "Webmin index page");
