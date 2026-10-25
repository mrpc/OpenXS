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

# "world-writable directory" findings go through the same permission-fix
# UI here as they do on the Findings page (findings.cgi) - missed here
# at first (reports.cgi has its own separate rendering), which is why
# clicking "Fix permissions" from a scan's own findings list (not the
# unified Findings page) failed with "Invalid request." - the button it
# showed was actually still the quarantine one, which doesn't apply to
# a directory at all.
sub quarantine_action_links
{
my ($fid, $qpath, $rule, $perm_fix_new_mode) = @_;
return ($rule eq 'world-writable directory')
	? &openxs_permission_action_links($fid, $perm_fix_new_mode)
	: &openxs_quarantine_action_links($fid, $qpath, $scan_id, $rule);
}

sub quarantine_sort_header
{
my ($sort, $order, $col, $label) = @_;
my $next_order = ($sort eq $col && $order eq 'desc') ? 'asc' : 'desc';
my $arrow = $sort eq $col ? ($order eq 'desc' ? ' &#9660;' : ' &#9650;') : '';
return "<a href='reports.cgi?view=quarantine&qsort=$col&qorder=$next_order'>$label$arrow</a>";
}

if ($view_quarantine) {
	print &ui_subheading("Quarantined files");
	my $page = $in{'qpage'};
	$page =~ s/[^0-9]//g;
	$page = 0 if ($page eq '');
	my $page_size = 50;
	my $offset = $page * $page_size;
	my $sort = $in{'qsort'};
	$sort = "date" unless ($sort =~ /^(date|path|size|rule)$/);
	my $order = $in{'qorder'} eq 'asc' ? 'asc' : 'desc';  # default: newest first
	my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
total = openxs_db.quarantined_files_count()
print('TOTAL\\t' + str(total))
for fid, f, r, q, ts, size, scan_path in openxs_db.quarantined_files(limit=$page_size, offset=$offset, sort='$sort', order='$order'):
    user = openxs_db.derive_user(f) or ''
    source = openxs_db.derive_source(scan_path)
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + q + '\\t' + str(ts) + '\\t' + user + '\\t' + source + '\\t' + str(size or ''))
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
		# Clicking a sortable header: same column again flips asc/desc,
		# a different column starts it at desc (newest/largest/Z-first).
		print &ui_columns_start([
			&quarantine_sort_header($sort, $order, "date", "Quarantined"), "User", "Source",
			&quarantine_sort_header($sort, $order, "path", "Original path"),
			&quarantine_sort_header($sort, $order, "rule", "Rule"),
			&quarantine_sort_header($sort, $order, "size", "Size"), "Status"]);
		foreach my $row (@rows) {
			my ($fid, $f, $r, $q, $ts, $user, $source, $size) = split(/\t/, $row);
			my $date = $ts ne '' && $ts ne 'None' ? &make_date($ts, 1) : "<i>unknown</i>";
			my $size_h = $size ne '' ? "${size}B" : "-";
			print &ui_columns_row([$date, &html_escape($user), &html_escape($source),
				&html_escape($f), &html_escape($r), $size_h, &quarantine_action_links($fid, $q, $r, undef)]);
			}
		print &ui_columns_end();
		print &openxs_flush_mini_forms();
		print "<p>";
		my $sort_qs = "qsort=$sort&qorder=$order";
		print "<a href='reports.cgi?view=quarantine&$sort_qs&qpage=" . ($page - 1) . "'>&laquo; Previous</a> " if ($page > 0);
		print "<a href='reports.cgi?view=quarantine&$sort_qs&qpage=" . ($page + 1) . "'>Next &raquo;</a>" if ($offset + $page_size < $total);
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
    perm_fix = openxs_db.permission_fix_for(fid) if r == 'world-writable directory' else None
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + (q or '') + '\\t' + (str(perm_fix[1]) if perm_fix else ''))
"`;
	my @rows = grep { $_ ne "" } split(/\n/, $out);
	if (!@rows) {
		print "<p>(no findings recorded for this scan)</p>\n";
		}
	else {
		print &ui_columns_start(["File", "Rule", "Quarantine"]);
		foreach my $row (@rows) {
			my ($fid, $f, $r, $q, $perm_fix_new_mode) = split(/\t/, $row);
			print &ui_columns_row([&html_escape($f), &html_escape($r), &quarantine_action_links($fid, $q, $r, $perm_fix_new_mode)]);
			}
		print &ui_columns_end();
		print &openxs_flush_mini_forms();
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
