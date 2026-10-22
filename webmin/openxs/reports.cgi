#!/usr/bin/perl
# reports.cgi
# Scan history + quarantine view (equivalent of cxs's "View Scan Reports" /
# "In Quarantine"), backed by a small local SQLite database.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print "<p><a href='index.cgi'>Dashboard</a> | <a href='reports.cgi'>Scan history</a> | ".
      "<a href='reports.cgi?view=quarantine'>Quarantine</a></p>\n";

my $scan_id = $in{'scan_id'};
$scan_id =~ s/[^0-9]//g;
my $view_quarantine = $in{'view'} eq 'quarantine';

sub quarantine_action_links
{
my ($fid, $qpath) = @_;
if ($qpath eq "__deleted__") {
	return "<i>Deleted</i>";
	}
elsif ($qpath ne "") {
	return "<b style='color:#b30000'>Quarantined</b><br>".
	       "<a href='quarantine.cgi?action=restore&id=$fid'>Restore</a> | ".
	       "<a href='quarantine.cgi?action=delete&id=$fid' ".
	       "onclick=\"return confirm('Permanently delete this file?')\">Delete</a>";
	}
else {
	return "<a href='quarantine.cgi?action=quarantine&id=$fid'>Quarantine now</a>";
	}
}

if ($view_quarantine) {
	print &ui_subheading("Quarantined files");
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
for fid, f, r, q in openxs_db.quarantined_files():
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + q)
"`;
	my @rows = grep { $_ ne "" } split(/\n/, $out);
	if (!@rows) {
		print "<p>Nothing in quarantine.</p>\n";
		}
	else {
		print &ui_columns_start(["Original path", "Rule", "Status"]);
		foreach my $row (@rows) {
			my ($fid, $f, $r, $q) = split(/\t/, $row);
			print &ui_columns_row([&html_escape($f), &html_escape($r), &quarantine_action_links($fid, $q)]);
			}
		print &ui_columns_end();
		}
	print "<p><a href='reports.cgi'>&laquo; Scan history</a></p>\n";
	}
elsif ($scan_id) {
	print &ui_subheading("Findings for scan #" . &html_escape($scan_id));
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
for fid, f, r, q in openxs_db.findings_for_scan($scan_id):
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + (q or ''))
"`;
	my @rows = grep { $_ ne "" } split(/\n/, $out);
	if (!@rows) {
		print "<p>(no findings recorded for this scan)</p>\n";
		}
	else {
		print &ui_columns_start(["File", "Rule", "Quarantine"]);
		foreach my $row (@rows) {
			my ($fid, $f, $r, $q) = split(/\t/, $row);
			print &ui_columns_row([&html_escape($f), &html_escape($r), &quarantine_action_links($fid, $q)]);
			}
		print &ui_columns_end();
		}
	print "<p><a href='reports.cgi'>&laquo; All scans</a></p>\n";
	}
else {
	print &ui_subheading("Scan history");
	print "<p><a href='reports.cgi?view=quarantine'>View quarantined files &raquo;</a></p>\n";
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db, time
for sid, ts, path, total, hits in openxs_db.recent_scans():
    t = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
    print(str(sid) + '\\t' + t + '\\t' + path + '\\t' + str(total) + '\\t' + str(hits))
"`;
	my @rows = grep { $_ ne "" } split(/\n/, $out);
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
