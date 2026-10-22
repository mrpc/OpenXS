#!/usr/bin/perl
# quarantine.cgi
# Quarantine / restore / delete a single finding's file.

require './openxs-lib.pl';
&ReadParse();

my $action = $in{'action'};
my $id = $in{'id'};
$id =~ s/[^0-9]//g;

my $back_url = $in{'scan_id'} ne "" ? "reports.cgi?scan_id=$in{'scan_id'}" : "reports.cgi?view=quarantine";
my $back_label = $in{'scan_id'} ne "" ? "Back to scan report" : "View quarantine";

if ($id eq "" || $action !~ /^(quarantine|restore|delete)$/) {
	&openxs_result_page("Invalid request.", 1, $back_label, $back_url);
	}

my $func = $action eq "quarantine" ? "quarantine_file"
         : $action eq "restore"    ? "restore_file"
         : "delete_quarantined";
# openxs_db.*() return "True"/"False"/a path on their own stdout line, so
# the result of the actual operation is visible here instead of being
# assumed to have succeeded just because the subprocess didn't crash.
my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
print(openxs_db.$func($id))
"`;
chomp($out);
my $ok = $out ne "" && $out ne "None" && $out ne "False";

my %verbs = ('quarantine' => 'Quarantined', 'restore' => 'Restored', 'delete' => 'Deleted');
if ($ok) {
	&openxs_result_page("$verbs{$action} finding #$id.", 0, $back_label, $back_url);
	}
else {
	&openxs_result_page(
		"Could not $action finding #$id - the file may already have been moved, restored, or deleted outside this UI.",
		1, $back_label, $back_url);
	}
