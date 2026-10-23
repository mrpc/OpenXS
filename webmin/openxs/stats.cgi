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
	my $max_hits = 1;
	foreach my $r (@parsed) { $max_hits = $r->[3] if ($r->[3] > $max_hits); }

	print &ui_subheading("Hits per day");
	my $n = scalar(@parsed);
	my $bar_w = $n > 60 ? 10 : ($n > 30 ? 16 : 32);
	my $gap = $bar_w > 16 ? 8 : 3;
	my $plot_h = 160;          # bar area only, above the baseline
	my $top_pad = 24;          # room for each bar's value label
	my $label_h = 28;          # room for the date label below the baseline
	my $chart_w = $n * ($bar_w + $gap) + $gap;
	my $chart_h = $top_pad + $plot_h + $label_h;
	my $baseline_y = $top_pad + $plot_h;

	print "<svg width='$chart_w' height='$chart_h' style='background:#fff;border:1px solid #ddd;border-radius:4px' font-family='sans-serif'>\n";
	# Light horizontal gridlines (25/50/75/100%) so a bar's height means something at a glance
	foreach my $frac (0.25, 0.5, 0.75, 1.0) {
		my $gy = $baseline_y - $plot_h * $frac;
		print "<line x1='0' y1='$gy' x2='$chart_w' y2='$gy' stroke='#eee' stroke-width='1'/>\n";
		}
	print "<line x1='0' y1='$baseline_y' x2='$chart_w' y2='$baseline_y' stroke='#ccc' stroke-width='1'/>\n";

	my $x = $gap;
	my $label_every = $n > 14 ? int($n / 14) + 1 : 1;  # thin out date labels so they don't overlap on a wide range
	my $i = 0;
	foreach my $r (@parsed) {
		my ($date, $scan_count, $files_scanned, $hits, $quarantined, $avg_duration) = @$r;
		my $bar_h = $hits > 0 ? ($hits / $max_hits) * ($plot_h - 4) : 0;
		my $y = $baseline_y - $bar_h;
		my $color = $hits > 0 ? '#b30000' : '#ddd';
		my $cx = $x + $bar_w / 2;
		print "<rect x='$x' y='$y' width='$bar_w' height='" . ($bar_h || 2) . "' rx='2' fill='$color'>".
			"<title>$date: $hits hit(s), $scan_count scan(s), $files_scanned file(s) scanned</title></rect>\n";
		if ($hits > 0) {
			print "<text x='$cx' y='" . ($y - 6) . "' font-size='11' fill='#333' text-anchor='middle'>$hits</text>\n";
			}
		if ($i % $label_every == 0) {
			my $short_date = $date;
			$short_date =~ s/^\d{4}-//;  # "10-23" instead of "2026-10-23" - the year rarely matters day to day
			print "<text x='$cx' y='" . ($baseline_y + 16) . "' font-size='10' fill='#666' text-anchor='middle' ".
				"transform='rotate(45 $cx " . ($baseline_y + 16) . ")'>$short_date</text>\n";
			}
		$x += $bar_w + $gap;
		$i++;
		}
	print "</svg>\n";

	print &ui_subheading("Table");
	print &ui_columns_start(["Date", "Scans", "Files scanned", "Hits", "Quarantined", "Avg duration (s)"]);
	foreach my $r (reverse @parsed) {
		my ($date, $scan_count, $files_scanned, $hits, $quarantined, $avg_duration) = @$r;
		my $hits_html = $hits > 0 ? "<b style='color:#b30000'>$hits</b>" : "0";
		print &ui_columns_row([&html_escape($date), $scan_count, $files_scanned, $hits_html, $quarantined, $avg_duration]);
		}
	print &ui_columns_end();
	}

print &ui_form_start("rebuild_stats.cgi", "post") . &ui_submit("Rebuild stats from scan history", "go") . &ui_form_end();
print "<p><a href='reports.cgi'>Full scan history &raquo;</a></p>\n";
print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
