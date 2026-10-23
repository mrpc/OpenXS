#!/usr/bin/perl
# reports.cgi
# Scan history + quarantine view (equivalent of cxs's "View Scan Reports" /
# "In Quarantine"), backed by a small local SQLite database.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print $openxs_nav;

my $scan_id = $in{'scan_id'};
$scan_id =~ s/[^0-9]//g;
my $view_quarantine = $in{'view'} eq 'quarantine';

sub quarantine_action_form
{
# A POST form, not a plain <a href> - a raw link navigates out of
# Webmin's themed frame entirely instead of staying inside it, the same
# way every other action on this module already works via mini_form().
my ($action, $fid, $label, $tags) = @_;
# display:inline-block - these sit next to each other in the Status
# column (e.g. Restore + Delete), not one per line making every row of
# a 50-row page needlessly tall.
return &ui_form_start("quarantine.cgi", "post", undef, "style='display:inline-block;margin-right:4px'") .
	&ui_hidden("action", $action) . &ui_hidden("id", $fid) .
	&ui_hidden("scan_id", $scan_id) .
	&ui_submit($label, "go", 0, $tags) .
	&ui_form_end();
}

sub quarantine_action_links
{
my ($fid, $qpath) = @_;
if ($qpath eq "__deleted__") {
	return "<i>Deleted</i>";
	}
elsif ($qpath ne "") {
	return "<b style='color:#b30000'>Quarantined</b><br>".
	       &quarantine_action_form("restore", $fid, "Restore") .
	       &quarantine_action_form("delete", $fid, "Delete",
	       	"onclick=\"return confirm('Permanently delete this file?')\"");
	}
else {
	return &quarantine_action_form("quarantine", $fid, "Quarantine now");
	}
}

if ($view_quarantine) {
	print &ui_subheading("Quarantined files");
	my $page = $in{'qpage'};
	$page =~ s/[^0-9]//g;
	$page = 0 if ($page eq '');
	my $page_size = 50;
	my $offset = $page * $page_size;
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
total = openxs_db.quarantined_files_count()
print('TOTAL\\t' + str(total))
for fid, f, r, q, ts in openxs_db.quarantined_files(limit=$page_size, offset=$offset):
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + q + '\\t' + str(ts))
"`;
	my @all_lines = grep { $_ ne "" } split(/\n/, $out);
	my $total = 0;
	if (@all_lines && $all_lines[0] =~ /^TOTAL\t(\d+)$/) {
		$total = $1;
		shift(@all_lines);
		}
	my @rows = @all_lines;
	if (!@rows) {
		print "<p>Nothing in quarantine.</p>\n";
		}
	else {
		print "<p>$total file(s) in quarantine - showing " . ($offset + 1) . "-" . ($offset + scalar(@rows)) . "</p>\n";
		print &ui_columns_start(["Quarantined", "Original path", "Rule", "Status"]);
		foreach my $row (@rows) {
			my ($fid, $f, $r, $q, $ts) = split(/\t/, $row);
			my $date = $ts ne '' && $ts ne 'None' ? &make_date($ts, 1) : "<i>unknown</i>";
			print &ui_columns_row([$date, &html_escape($f), &html_escape($r), &quarantine_action_links($fid, $q)]);
			}
		print &ui_columns_end();
		print "<p>";
		print "<a href='reports.cgi?view=quarantine&qpage=" . ($page - 1) . "'>&laquo; Previous</a> " if ($page > 0);
		print "<a href='reports.cgi?view=quarantine&qpage=" . ($page + 1) . "'>Next &raquo;</a>" if ($offset + $page_size < $total);
		print "</p>\n";
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
for sid, ts, path, total, hits, duration, load_avg in openxs_db.recent_scans():
    t = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
    d = ('%.1fs' % duration) if duration is not None else '-'
    la = ('%.2f' % load_avg) if load_avg is not None else '-'
    print(str(sid) + '\\t' + t + '\\t' + path + '\\t' + str(total) + '\\t' + str(hits) + '\\t' + d + '\\t' + la)
"`;
	my @rows = grep { $_ ne "" } split(/\n/, $out);
	if (!@rows) {
		print "<p>No scans recorded yet.</p>\n";
		}
	else {
		print &ui_columns_start(["Scan", "When", "Path", "Files scanned", "Hits", "Duration", "Load avg"]);
		foreach my $row (@rows) {
			my ($sid, $when, $path, $total, $hits, $duration, $load_avg) = split(/\t/, $row);
			my $hits_html = $hits > 0 ? "<b style='color:#b30000'>$hits</b>" : "0";
			print &ui_columns_row([
				"<a href='reports.cgi?scan_id=$sid'>#$sid</a>",
				&html_escape($when),
				&html_escape($path),
				$total,
				$hits_html,
				&html_escape($duration),
				&html_escape($load_avg),
				]);
			}
		print &ui_columns_end();
		}
	}

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
