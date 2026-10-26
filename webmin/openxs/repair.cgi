#!/usr/bin/perl
# repair.cgi
# "Restore to pristine version" - replaces a finding's file with its
# official upstream content (Composer package or Drupal 7 core so far -
# see restore_pristine.py's docstring), backing the current content up
# via the normal quarantine mechanism first.

require './openxs-lib.pl';
&ReadParse();

my $id = $in{'id'};
$id =~ s/[^0-9]//g;

my $back_url = $in{'scan_id'} ne "" ? "reports.cgi?scan_id=$in{'scan_id'}" : "findings.cgi";
my $back_label = $in{'scan_id'} ne "" ? "Back to scan report" : "Back to findings";

if ($id eq "") {
	&openxs_result_page("Invalid request.", 1, $back_label, $back_url);
	exit;
	}

my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import restore_pristine
ok, err = restore_pristine.repair_file($id)
print('OK' if ok else ('ERR\t' + (err or 'unknown error')))
"`;
chomp($out);

if ($out eq "OK") {
	&openxs_result_page("Finding #$id repaired - the file was replaced with its official pristine content, "
		. "and the previous content was backed up to quarantine (Restore from there if this was wrong).",
		0, $back_label, $back_url);
	}
else {
	my ($tag, $msg) = split(/\t/, $out, 2);
	&openxs_result_page("Could not repair finding #$id: " . &html_escape($msg || $out), 1, $back_label, $back_url);
	}
