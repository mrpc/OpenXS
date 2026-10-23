#!/usr/bin/perl
# stats.cgi
# Daily statistics - mirrors cxs's own cxsscan_counters/cxswatch_counters
# (daily aggregate counters, not raw per-scan rows) with a simple inline
# SVG chart. No external JS/CDN - some of our servers have no outbound
# internet access at all, and a chart library is unwarranted for one
# bar chart.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print $openxs_nav;

my $days = $in{'days'};
$days =~ s/[^0-9]//g;
$days = 30 if ($days eq '' || $days < 1);

my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
for row in openxs_db.daily_stats_filled($days):
    date, scan_count, files_scanned, hits, quarantined, avg_duration = row
    print(date + '\\t' + str(scan_count) + '\\t' + str(files_scanned) + '\\t' + str(hits) +
          '\\t' + str(quarantined) + '\\t' + ('%.1f' % avg_duration if avg_duration is not None else '-'))
"`;
my @rows = grep { $_ ne "" } split(/\n/, $out);

my $modsec_available = -d '/etc/modsecurity';
my %modsec_by_date;
if ($modsec_available) {
	my $mout = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
for date, blocks in openxs_db.modsec_daily_stats_filled($days):
    print(date + '\\t' + str(blocks))
"`;
	foreach my $line (split(/\n/, $mout)) {
		my ($date, $blocks) = split(/\t/, $line);
		$modsec_by_date{$date} = $blocks if (defined($date));
		}
	}

print &ui_subheading("Daily statistics (last $days days)");
print &ui_form_start("stats.cgi", "get") .
	"<label>Show last " . &ui_select("days", $days, [["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["365", "365 days"]]) . "</label> " .
	&ui_submit("Go", "go") .
	&ui_form_end();

{
	# Always exactly $days rows now (daily_stats_filled() fills any gap
	# with zeroes) - asking for 30 days should always show 30 days, not
	# just however many happened to have a scan recorded.
	my @parsed = map { [ split(/\t/, $_) ] } @rows;
	my @dates = map { $_->[0] } @parsed;
	my @hits = map { $_->[3] } @parsed;

	print &ui_subheading("Hits per day");
	print &openxs_bar_chart(\@dates, \@hits, '#b30000');

	if ($modsec_available) {
		my @modsec_values = map { $modsec_by_date{$_} || 0 } @dates;
		print &ui_subheading("mod_security blocks per day");
		print &openxs_bar_chart(\@dates, \@modsec_values, '#8a5a1f');
		print "<p><a href='modsec_log.cgi'>View grouped by host/path/rule &raquo;</a></p>\n";
		}

	print &ui_subheading("Table");
	my @headers = ("Date", "Scans", "Files scanned", "Hits", "Quarantined", "Avg duration (s)");
	push(@headers, "mod_security blocks") if ($modsec_available);
	print &ui_columns_start(\@headers);
	foreach my $r (reverse @parsed) {
		my ($date, $scan_count, $files_scanned, $hits, $quarantined, $avg_duration) = @$r;
		my $hits_html = $hits > 0 ? "<b style='color:#b30000'>$hits</b>" : "0";
		my @cells = (&html_escape($date), $scan_count, $files_scanned, $hits_html, $quarantined, $avg_duration);
		if ($modsec_available) {
			my $mb = $modsec_by_date{$date} || 0;
			push(@cells, $mb > 0 ? "<b style='color:#8a5a1f'>$mb</b>" : "0");
			}
		print &ui_columns_row(\@cells);
		}
	print &ui_columns_end();
	}

print &ui_form_start("rebuild_stats.cgi", "post") . &ui_submit("Rebuild stats from scan history", "go") . &ui_form_end();
print "<p><a href='reports.cgi'>Full scan history &raquo;</a></p>\n";
print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
