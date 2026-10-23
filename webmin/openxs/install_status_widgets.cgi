#!/usr/bin/perl
# install_status_widgets.cgi
# Adds openxs-watchd/openxs-scand to Webmin's own "Servers Status"
# dashboard widget (the status module) - same .serv files install.sh
# writes on a fresh install, for someone upgrading an older OpenXS
# install that predates this feature.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Adding to Webmin's Servers Status widget...");

if (!-d "/etc/webmin/status") {
	print "<p>Webmin's Status module isn't installed on this server - nothing to add.</p>\n";
	}
else {
	mkdir("/etc/webmin/status/services", 0700) if (!-d "/etc/webmin/status/services");
	open(my $fh, ">", "/etc/webmin/status/services/openxs-watchd.serv") or die $!;
	print $fh "id=openxs-watchd\ntype=init\naction=openxs-watchd\ndesc=OpenXS Watch Daemon\ndepends=openxs\n";
	close($fh);
	open($fh, ">", "/etc/webmin/status/services/openxs-scand.serv") or die $!;
	print $fh "id=openxs-scand\ntype=init\naction=openxs-scand\ndesc=OpenXS Scan Daemon\ndepends=openxs\n";
	close($fh);
	print "<p>Done - openxs-watchd and openxs-scand will now show on the main Webmin status page.</p>\n";
	}

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
