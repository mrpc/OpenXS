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
$cat = "" unless ($cat =~ /^(yara|virus|maldet|oldversion|fs)$/);
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

my @tabs = (["", "All"], ["yara", "Exploits"], ["virus", "Virus"], ["maldet", "maldet"],
            ["oldversion", "Old Versions"], ["fs", "Filesystem"]);
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
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
rows, total = openxs_db.search_findings(category=$cat_arg, search=$search_arg, limit=$page_size, offset=$offset, sort='$sort', order='$order')
print('TOTAL\\t' + str(total))
for fid, f, r, q, size, ts, scan_path in rows:
    user = openxs_db.derive_user(f) or ''
    source = openxs_db.derive_source(scan_path)
    print(str(fid) + '\\t' + f + '\\t' + r + '\\t' + (q or '') + '\\t' + str(size or '') + '\\t' + str(ts) + '\\t' + user + '\\t' + source)
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
	foreach my $row (@all_lines) {
		my ($fid, $f, $r, $q, $size, $ts, $user, $source) = split(/\t/, $row);
		my $date = $ts ne '' && $ts ne 'None' ? &make_date($ts, 1) : "<i>unknown</i>";
		my $size_h = $size ne '' ? "${size}B" : "-";
		print &ui_columns_row([
			&ui_checkbox("id", $fid, "", 0),
			$date, &html_escape($user), &html_escape($source),
				&html_escape($f) . " <a href='view_file.cgi?id=$fid'>[View]</a>", &html_escape($r), $size_h,
			&openxs_quarantine_action_links($fid, $q, undef),
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
