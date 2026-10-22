#!/usr/bin/perl
# reports.cgi
# Scan history (equivalent of cxs's "View Scan Reports"), backed by a small
# local SQLite database.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $scan_id = $in{'scan_id'};

if ($scan_id) {
	print &ui_subheading("Findings for scan #" . &html_escape($scan_id));
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
for f, r in openxs_db.findings_for_scan($scan_id):
    print(f + '\\t' + r)
"`;
	print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";
	print $out ne "" ? &html_escape($out) : "(no findings recorded for this scan)";
	print "</pre>";
	print "<p><a href='reports.cgi'>&laquo; All scans</a></p>\n";
	}
else {
	print &ui_subheading("Scan history");
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db, time
for sid, ts, path, total, hits in openxs_db.recent_scans():
    t = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
    print(str(sid) + '\\t' + t + '\\t' + path + '\\t' + str(total) + '\\t' + str(hits))
"`;
	my @rows = split(/\n/, $out);
	if (!@rows) {
		print "<p>No scans recorded yet.</p>\n";
		}
	else {
		print &ui_columns_start(["Scan", "When", "Path", "Files scanned", "Hits"]);
		foreach my $row (@rows) {
			my ($sid, $when, $path, $total, $hits) = split(/\t/, $row);
			my $hits_html = $hits > 0 ? "<b style='color:#b30000'>$hits</b>" : "0";
			print &ui_columns_row([
				"<a href='reports.cgi?scan_id=$sid'>#$sid</a>",
				&html_escape($when),
				&html_escape($path),
				$total,
				$hits_html,
				]);
			}
		print &ui_columns_end();
		}
	}

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
