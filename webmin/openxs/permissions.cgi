#!/usr/bin/perl
# permissions.cgi
# Fix / restore a single "world-writable directory" finding's permission
# (strips just the world-write bit - a directory can't be quarantined
# the way a file can, moving it would take the whole site down with it).

require './openxs-lib.pl';
&ReadParse();

my $action = $in{'action'};
my $id = $in{'id'};
$id =~ s/[^0-9]//g;

my $back_url = $in{'scan_id'} ne "" ? "reports.cgi?scan_id=$in{'scan_id'}" : "findings.cgi?cat=fs";
my $back_label = $in{'scan_id'} ne "" ? "Back to scan report" : "Back to Findings";

if ($id eq "" || $action !~ /^(fix|restore)$/) {
	&openxs_result_page("Invalid request.", 1, $back_label, $back_url);
	}

my $func = $action eq "fix" ? "fix_world_writable_permission" : "restore_permission";
my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
print(openxs_db.$func($id))
"`;
chomp($out);
my $ok = $out ne "" && $out ne "None" && $out ne "False";

if ($ok && $action eq "fix") {
	&openxs_result_page("Fixed finding #$id - world-write bit removed (mode now " . sprintf("%03o", $out) . ").",
		0, $back_label, $back_url);
	}
elsif ($ok) {
	&openxs_result_page("Restored finding #${id}'s original permissions.", 0, $back_label, $back_url);
	}
else {
	&openxs_result_page(
		"Could not $action finding #$id - the path may no longer exist, no longer be a directory, ".
		"or (for restore) may not have an active fix to undo.",
		1, $back_label, $back_url);
	}
