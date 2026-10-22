#!/usr/bin/perl
# scan.cgi
# Run a manual scan against a given directory

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $path = $in{'path'};
$path =~ s/[^a-zA-Z0-9\/_.\-]//g;  # strip anything that isn't a plain path character

print &ui_subheading("Scan results for <code>" . &html_escape($path) . "</code>");

if (!$path || !-d $path) {
	print "<p style='color:red'>Not a valid directory.</p>\n";
	}
else {
	my $filelist = "/tmp/openxs-webmin-scan-$$.txt";
	system("find " . quotemeta($path) . " -type f -name '*.php' > $filelist");
	my %cfg = &openxs_read_config();
	$ENV{'OPENXS_SCAN_LABEL'} = $path;
	$ENV{'OPENXS_QUARANTINE_ENABLED'} = ($cfg{'QUARANTINE_ENABLED'} || '0') eq '1' ? '1' : '0';
	my $out = `python3 /opt/php-malware-finder/pmf_scan.py scan $ruleset $filelist 2>&1`;
	unlink($filelist);
	print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";
	print $out ne "" ? &html_escape($out) : "(no output)";
	print "</pre>";
	}

print "<p><a href='index.cgi'>&laquo; Back</a></p>\n";
&ui_print_footer("/", "Webmin index page");
