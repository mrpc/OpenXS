#!/usr/bin/perl
# rebuild_stats.cgi
# Recomputes daily_stats from scratch - needed once after upgrading to a
# version with this feature (existing scan history predates the table),
# or to repair it if it's ever gotten out of sync. Safe to re-run any time.

require './openxs-lib.pl';
&ReadParse();

my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
openxs_db.rebuild_daily_stats()
print('Rebuilt.')
" 2>&1`;
my $ok = $out =~ /Rebuilt\./;

&openxs_result_page($ok ? "Statistics rebuilt from scan history." : "Rebuild failed - see details below.",
	!$ok, "Back to statistics", "stats.cgi", $out);
