#!/usr/bin/perl
# findings.cgi
# Unified findings browser - every finding ever recorded, with category
# tabs (All/Exploits/Virus/maldet/Old Versions/Filesystem), a filename
# search box, and bulk actions - mirrors cxs's own tabbed findings view
# (Exploits/Others/Old Versions/Probability/In Quarantine). Probability
# (Bayesian scoring) has no OpenXS equivalent yet, deliberately deferred.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print $openxs_nav;

my $cat = $in{'cat'};
$cat = "" unless ($cat =~ /^(yara_exploit|yara_heuristic|virus|maldet|oldversion|fs)$/);
my $search = $in{'search'};
$search =~ s/[\r\n]//g;
my $page = $in{'fpage'};
$page =~ s/[^0-9]//g;
$page = 0 if ($page eq '');
my $page_size = 50;
my $offset = $page * $page_size;
my $sort = $in{'fsort'};
$sort = "date" unless ($sort =~ /^(date|path|size|rule)$/);
my $order = $in{'forder'} eq 'asc' ? 'asc' : 'desc';

sub findings_sort_header
{
my ($sort, $order, $base_qs, $col, $label) = @_;
my $next_order = ($sort eq $col && $order eq 'desc') ? 'asc' : 'desc';
my $arrow = $sort eq $col ? ($order eq 'desc' ? ' &#9660;' : ' &#9650;') : '';
return "<a href='findings.cgi?$base_qs&fsort=$col&forder=$next_order'>$label$arrow</a>";
}

print &ui_subheading("Findings");

my @tabs = (["", "All"], ["yara_exploit", "Exploits"], ["yara_heuristic", "Suspicious patterns"],
            ["virus", "Virus"], ["maldet", "maldet"], ["oldversion", "Old Versions"], ["fs", "Filesystem"]);

# Red/orange/gray by how much attention a category deserves: exploit/
# virus/maldet are the ones that get auto-quarantined by default (real
# signal); yara_heuristic is the generic-pattern bucket known to recur
# on common legitimate software (see default_ignore, RULE_PARANOIA_LEVEL);
# fs is filesystem hygiene, not a malware signal at all. Shown on every
# row (not just as a tab) so "All" doesn't read as one undifferentiated
# wall of findings - the whole point of a flat "N hit(s)" count being
# misleading is that it hides exactly this distinction.
my %category_badge = (
	'yara_exploit'   => "<span style='background:#fdeef0;color:#9a3b4a;border:1px solid #edc3cc;padding:1px 6px;border-radius:3px;font-size:11px;white-space:nowrap'>Exploit</span>",
	'virus'          => "<span style='background:#fdeef0;color:#9a3b4a;border:1px solid #edc3cc;padding:1px 6px;border-radius:3px;font-size:11px;white-space:nowrap'>Virus</span>",
	'maldet'         => "<span style='background:#fdeef0;color:#9a3b4a;border:1px solid #edc3cc;padding:1px 6px;border-radius:3px;font-size:11px;white-space:nowrap'>maldet</span>",
	'yara_heuristic' => "<span style='background:#fdf3e7;color:#8a5a1f;border:1px solid #edd6b3;padding:1px 6px;border-radius:3px;font-size:11px;white-space:nowrap'>Suspicious pattern</span>",
	'oldversion'     => "<span style='background:#eef3fa;color:#2b5a8c;border:1px solid #c3d6ea;padding:1px 6px;border-radius:3px;font-size:11px;white-space:nowrap'>Old version</span>",
	'fs'             => "<span style='background:#f0f0f0;color:#666;border:1px solid #ddd;padding:1px 6px;border-radius:3px;font-size:11px;white-space:nowrap'>Filesystem</span>",
	);
print "<p>";
foreach my $t (@tabs) {
	my ($val, $label) = @$t;
	my $style = ($val eq $cat) ? "font-weight:bold;text-decoration:underline" : "";
	print "<a href='findings.cgi?cat=$val' style='margin-right:10px;$style'>$label</a>";
	}
print "</p>";

print &ui_form_start("findings.cgi", "get") .
	&ui_hidden("cat", $cat) .
	"<label>Search filename: " . &ui_textbox("search", $search, 40) . "</label> " .
	&ui_submit("Search", "go") .
	(($search ne "") ? " <a href='findings.cgi?cat=$cat'>&laquo; Clear</a>" : "") .
	&ui_form_end();

my $search_arg = $search eq "" ? "None" : "'" . ($search =~ s/'/\\'/gr) . "'";
my $cat_arg = $cat eq "" ? "None" : "'$cat'";
my $out = `python3 -c "
import sys, os
sys.path.insert(0, '$pmf_dir')
import openxs_db
import pmf_scan
rows, total = openxs_db.search_findings(category=$cat_arg, search=$search_arg, limit=$page_size, offset=$offset, sort='$sort', order='$order')
print('TOTAL\\t' + str(total))
for fid, f, r, q, size, ts, scan_path in rows:
    user = openxs_db.derive_user(f) or ''
    source = openxs_db.derive_source(scan_path)
    # Same path view_file.cgi would read - a quarantined file is gone
    # from its original location by design, so check the quarantine
    # copy for those; only flag it \"gone\" if neither copy exists.
    check_path = q if (q and q not in ('', '__deleted__')) else f
    gone = int(not os.path.exists(check_path))
    category = pmf_scan.categorize(r)
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + (q or '') + '\\t' + str(size or '') + '\\t' + str(ts) + '\\t' + user + '\\t' + source + '\\t' + str(gone) + '\\t' + category)
"`;
my @all_lines = grep { $_ ne "" } split(/\n/, $out);
my $total = 0;
if (@all_lines && $all_lines[0] =~ /^TOTAL\t(\d+)$/) {
	$total = $1;
	shift(@all_lines);
	}

if (!@all_lines) {
	print "<p>No findings" . ($cat ne "" || $search ne "" ? " match this filter" : " recorded yet") . ".</p>\n";
	}
else {
	print "<p>$total finding(s) - showing " . ($offset + 1) . "-" . ($offset + scalar(@all_lines)) . "</p>\n";
	print &ui_form_start("bulk_action.cgi", "post");
	print &ui_hidden("cat", $cat) . &ui_hidden("search", $search) . &ui_hidden("fpage", $page);
	my $base_qs = "cat=$cat&search=$search";
	print &ui_columns_start(["", &findings_sort_header($sort, $order, $base_qs, "date", "Date"), "User", "Source",
		&findings_sort_header($sort, $order, $base_qs, "path", "File"),
		&findings_sort_header($sort, $order, $base_qs, "rule", "Rule"),
		&findings_sort_header($sort, $order, $base_qs, "size", "Size"), "Status"]);
	my $ignored_paths = { map { $_ => 1 } (-e '/etc/openxs/ignore' ? @{ &read_file_lines('/etc/openxs/ignore', 1) } : ()) };
	foreach my $row (@all_lines) {
			my ($fid, $f, $r, $q, $size, $ts, $user, $source, $gone, $category) = split(/\t/, $row);
			my $date = $ts ne '' && $ts ne 'None' ? &make_date($ts, 1) : "<i>unknown</i>";
			my $size_h = $size ne '' ? "${size}B" : "-";
			my $btn_style = "display:inline-block;margin:2px 4px 2px 0;padding:2px 8px;font-size:11px;".
				"border-radius:3px;text-decoration:none;white-space:nowrap";
			my $view_btn = "<a href='view_file.cgi?id=$fid' style='$btn_style;background:#eef3fa;color:#2b5a8c;border:1px solid #c3d6ea'>View</a>";
			my $logs_btn = "<a href='finding_logs.cgi?id=$fid' style='$btn_style;background:#fdf3e7;color:#8a5a1f;border:1px solid #edd6b3'>Who hit this?</a>";
			my $is_oldversion = $r =~ /\(oldversion\)$/;
			my $fp_btn;
			if (!$is_oldversion && $ignored_paths->{$f}) {
				$fp_btn = "<span style='$btn_style;background:#eef7ee;color:#2e7d32;border:1px solid #c3e0c3'>&#10003; Ignored</span>";
				}
			else {
				my $fp_url = "mark_false_positive.cgi?source=" . ($is_oldversion ? 'oldversion' : 'finding') .
					"&path=" . &urlize($f) . "&detail=" . &urlize($r);
				my $confirm_msg = $is_oldversion
					? 'Mark as false positive? (recorded for review - no automatic suppression exists for version-check findings)'
					: "Mark as false positive and add '$f' to the ignore file? (future scans will skip this exact path)";
				$fp_btn = "<a href='$fp_url' style='$btn_style;background:#fdeef0;color:#9a3b4a;border:1px solid #edc3cc' ".
					"onclick=\"return confirm('" . $confirm_msg . "')\">Mark false positive</a>";
				}
			my $links = "<div style='margin-top:3px'>" .
				($gone eq '1' ? "<span style='$btn_style;background:#f0f0f0;color:#888;border:1px solid #ddd'>file gone</span> " : "$view_btn ") .
				$logs_btn . " " . $fp_btn . "</div>";
			my $status = ($gone eq '1' && $q eq '')
				? "<i style='color:#888'>File gone</i>"
				: &openxs_quarantine_action_links($fid, $q, undef);
			print &ui_columns_row([
				&ui_checkbox("id", $fid, "", 0),
				$date, &html_escape($user), &html_escape($source),
				&html_escape($f) . " " . $links, ($category_badge{$category} || "") . " " . &html_escape($r), $size_h,
				$status,
				]);
			}
	print &ui_columns_end();
	print "<p>" .
		&ui_submit("Quarantine selected", "bulk_quarantine") . " " .
		&ui_submit("Restore selected", "bulk_restore") . " " .
		&ui_submit("Delete selected", "bulk_delete", 0, "onclick=\"return confirm('Permanently delete all selected files?')\"") .
		"</p>";
	print &ui_form_end();
	print "<p>";
	my $qs = "cat=$cat&search=$search";
	print "<a href='findings.cgi?$qs&fpage=" . ($page - 1) . "'>&laquo; Previous</a> " if ($page > 0);
	print "<a href='findings.cgi?$qs&fpage=" . ($page + 1) . "'>Next &raquo;</a>" if ($offset + $page_size < $total);
	print "</p>\n";
	}

print "<p><a href='reports.cgi'>Scan history</a> | <a href='reports.cgi?view=quarantine'>Quarantine view</a></p>\n";
&ui_print_footer("/", "Webmin index page");
