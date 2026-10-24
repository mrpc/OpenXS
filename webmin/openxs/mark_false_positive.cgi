#!/usr/bin/perl
# mark_false_positive.cgi
# "Mark false positive" for a YARA/ClamAV/maldet/version-check finding -
# records it (false_positive_reports, for later review/aggregation -
# e.g. a future telemetry step) AND, where a suppression mechanism
# actually exists, applies it automatically (adds the exact file path
# to /etc/openxs/ignore) - same idea as mod_security's quick-exclude
# buttons, just for the scan-side detectors instead. A version-check
# "(oldversion)" finding has no suppression mechanism (there's nothing
# to toggle - the package genuinely is outdated), so only the telemetry
# record happens for that source.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $source = $in{'source'};
my $path = $in{'path'};
my $detail = $in{'detail'};

if ($source !~ /^(finding|oldversion)$/ || $path eq '') {
	print "<p style='color:red'>Missing or invalid parameters.</p>\n";
	}
else {
	my $action_taken;
	if ($source eq 'finding') {
		my $ignore_file = '/etc/openxs/ignore';
		my @existing = -e $ignore_file ? @{ &read_file_lines($ignore_file, 1) } : ();
		if (grep { $_ eq $path } @existing) {
			$action_taken = "already in ignore file";
			}
		else {
			open(my $fh, '>>', $ignore_file) || print "<p style='color:red'>Could not write $ignore_file: $!</p>\n";
			if (fileno($fh)) {
				print $fh "$path\n";
				close($fh);
				$action_taken = "added to ignore file";
				}
			}
		}
	else {
		$action_taken = undef;
		}

	my @cmd = ($pmf_dir . '/openxs_mark_false_positive.py', $source, $path, $detail);
	push(@cmd, $action_taken) if (defined($action_taken));
	system('python3', @cmd);

	print "<p style='color:green'>Marked as false positive" .
		(defined($action_taken) ? " - $action_taken (future scans will skip this exact path)." : " - recorded (no automatic suppression exists for version-check findings).") .
		"</p>\n";
	}

print "<p><a href='findings.cgi'>&laquo; Back to findings</a></p>\n";
&ui_print_footer("/", "Webmin index page");
