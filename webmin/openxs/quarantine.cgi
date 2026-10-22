#!/usr/bin/perl
# quarantine.cgi
# Quarantine / restore / delete a single finding's file.

require './openxs-lib.pl';
&ReadParse();

my $action = $in{'action'};
my $id = $in{'id'};
$id =~ s/[^0-9]//g;

if ($id ne "" && $action =~ /^(quarantine|restore|delete)$/) {
	my $func = $action eq "quarantine" ? "quarantine_file"
	         : $action eq "restore"    ? "restore_file"
	         : "delete_quarantined";
	system("python3 -c \"
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
openxs_db.$func($id)
\"");
	}

my $back = $in{'scan_id'} ne "" ? "reports.cgi?scan_id=$in{'scan_id'}" : "reports.cgi?view=quarantine";
&redirect($back);
