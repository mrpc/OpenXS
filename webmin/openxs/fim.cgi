#!/usr/bin/perl
# fim.cgi
# Baseline or check File Integrity Monitoring on demand - the same logic
# the scheduled scan already runs daily (see run_scheduled_scan.sh),
# triggered immediately instead of waiting for the next cron run.

require './openxs-lib.pl';
&ReadParse();

my $action = $in{'action'};
if ($action !~ /^(baseline|check)$/) {
	&openxs_result_page("Invalid request.", 1);
	}

my $out = `cd $pmf_dir && python3 openxs_fim.py $action 2>&1`;
my $exit_code = $? >> 8;

if ($action eq "baseline") {
	&openxs_result_page($exit_code == 0 ? "Baseline recorded." : "Baseline failed - see details below.",
		$exit_code != 0, "Back to dashboard", "index.cgi", $out);
	}
else {
	# A non-zero exit from 'check' means drift was found - not a failure
	# of the check itself, but worth the same red/attention styling as
	# any other real finding elsewhere in this module.
	&openxs_result_page($exit_code == 0 ? "No integrity drift found." : "Integrity drift found - see details below.",
		$exit_code != 0, "Back to dashboard", "index.cgi", $out);
	}
