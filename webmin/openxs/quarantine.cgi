#!/usr/bin/perl
# quarantine.cgi
# Quarantine / restore / delete a single finding's file.

require './openxs-lib.pl';
&ReadParse();

my $action = $in{'action'};
my $id = $in{'id'};
$id =~ s/[^0-9]//g;

my $back = $in{'scan_id'} ne "" ? "reports.cgi?scan_id=$in{'scan_id'}" : "reports.cgi?view=quarantine";

if ($id eq "" || $action !~ /^(quarantine|restore|delete)$/) {
	&openxs_redirect_with_message($back, "Invalid request.", 1);
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
	&openxs_redirect_with_message($back, "$verbs{$action} finding #$id.", 0);
	}
else {
	&openxs_redirect_with_message($back,
		"Could not $action finding #$id - the file may already have been moved, restored, or deleted outside this UI.", 1);
	}
