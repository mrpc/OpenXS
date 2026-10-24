#!/usr/bin/perl
# mark_false_positive.cgi
# "Mark false positive" for a finding (YARA/ClamAV/maldet/version-check)
# or a mod_security block - always records it (false_positive_reports,
# for later review/aggregation - e.g. a future telemetry step) AND,
# where a suppression mechanism actually exists, applies it
# automatically. Deliberately separate from mod_security's own quick-
# exclude buttons (modsec_quick_exclude.cgi) - excluding something
# isn't always because it's a false positive (could be an accepted
# risk, a known-noisy but legitimate pattern), so this is its own
# explicit action, not implied by clicking "Exclude".
#
# source=finding: adds the exact file path to /etc/openxs/ignore.
# source=oldversion: no suppression mechanism exists (the package
# genuinely is outdated) - telemetry only.
# source=modsec: applies the same rule-exclusion (path=rule_id, detail=uri)
# as modsec_quick_exclude.cgi's "rule" action would.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $source = $in{'source'};
my $path = $in{'path'};
my $detail = $in{'detail'};

if ($source !~ /^(finding|oldversion|modsec)$/ || $path eq '') {
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
	elsif ($source eq 'modsec') {
		# path is the rule_id here, detail is the uri - see the URL
		# builder in openxs_modsec_quick_exclude_links().
		my $rule_file = '/etc/openxs/modsec_rule_exclusions';
		my $line = "$path ARGS";
		my @existing = -e $rule_file ? @{ &read_file_lines($rule_file, 1) } : ();
		if (grep { $_ eq $line } @existing) {
			$action_taken = "already excluded (rule)";
			}
		else {
			open(my $fh, '>>', $rule_file) || print "<p style='color:red'>Could not write $rule_file: $!</p>\n";
			if (fileno($fh)) {
				print $fh "$line\n";
				close($fh);
				my $out = `python3 $pmf_dir/openxs_modsec_rule_exclusions.py 2>&1`;
				system("apache2ctl -t 2>/dev/null && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null)");
				print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" . &html_escape($out) . "</pre>";
				$action_taken = "rule exclusion applied ($line)";
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
		(defined($action_taken) ? " - $action_taken." : " - recorded (no automatic suppression exists for version-check findings).") .
		"</p>\n";
	}

my $back = $source eq 'modsec' ? 'modsec_log.cgi' : 'findings.cgi';
print "<p><a href='$back'>&laquo; Back</a></p>\n";
&ui_print_footer("/", "Webmin index page");
