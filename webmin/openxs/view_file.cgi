#!/usr/bin/perl
# view_file.cgi
# Shows a finding's actual file content (bounded, read-only, HTML-escaped)
# so the user can judge a match without needing shell access - requested
# directly after looking at a regex-rule finding in the Findings browser
# and wanting to see what exactly matched before deciding if it's a real
# problem. For a "Custom rule: <pattern>" finding, re-runs that exact
# pattern (through pmf_scan's own SIGALRM-protected search - this page
# must not be able to hang/explode on the same kind of pathological rule
# that caused a real production incident earlier) and highlights the
# line the match starts on. YARA/ClamAV/maldet findings only store a
# bare rule/signature name, not a matched offset, so those just show the
# content for the admin to read - no auto-highlight is possible there.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;

my $fid = $in{'id'};
$fid =~ s/[^0-9]//g;
if ($fid eq '') {
	print "<p>No finding id given.</p>\n";
	&ui_print_footer("findings.cgi", "Back to findings");
	exit;
	}

my $out = `python3 -c "
import sys, os, re
sys.path.insert(0, '$pmf_dir')
import openxs_db, pmf_scan

row = openxs_db.finding_by_id($fid)
if not row:
    print('NOTFOUND')
    sys.exit()
file_path, rule_name, quarantine_path, size = row
read_path = file_path
if quarantine_path and quarantine_path not in ('', '__deleted__') and os.path.exists(quarantine_path):
    read_path = quarantine_path

MAX_PREVIEW = 2 * 1024 * 1024
try:
    with open(read_path, 'rb') as f:
        data = f.read(MAX_PREVIEW + 1)
except OSError as e:
    kind = 'NOTEXIST' if e.errno == 2 else 'OTHER'
    print(f'ERROR\\t{kind}\\t{e}')
    sys.exit()

truncated = len(data) > MAX_PREVIEW
data = data[:MAX_PREVIEW]

match_line = ''
m = re.match(r'^Custom rule: (.+)\$', rule_name)
if m:
    try:
        pat = re.compile(m.group(1).encode())
        mobj = pmf_scan._search_with_timeout(pat, data, read_path, seconds=2)
        if mobj:
            match_line = str(data[:mobj.start()].count(b'\\n') + 1)
    except re.error:
        pass

print(f'OK\\t{read_path}\\t{int(truncated)}\\t{match_line}')
print('---CONTENT---')
sys.stdout.flush()
sys.stdout.buffer.write(data)
" 2>&1`;

my ($header, $content) = split(/---CONTENT---\n/, $out, 2);
my @hlines = split(/\n/, $header);

if ($hlines[0] eq 'NOTFOUND') {
	print "<p>No such finding.</p>\n";
	}
elsif ($hlines[0] =~ /^ERROR\tNOTEXIST\t/) {
	print "<p>This file no longer exists on disk - it may have been deleted, moved, " .
		"or cleaned up since this finding was recorded (common for older, migrated findings).</p>\n";
	}
elsif ($hlines[0] =~ /^ERROR\t[A-Z]+\t(.+)$/) {
	print "<p>Could not read the file: " . &html_escape($1) . "</p>\n";
	}
elsif ($hlines[0] =~ /^OK\t([^\t]*)\t([01])\t(\d*)$/) {
	my ($read_path, $truncated, $match_line) = ($1, $2, $3);
	print &ui_subheading("Viewing: " . &html_escape($read_path));
	print "<p><i>Read-only preview" . ($truncated ? " - truncated at 2MB" : "") .
		($match_line ne '' ? ", match starts around line $match_line (highlighted below)" : "") . ".</i></p>\n";
	print "<div style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:600px;overflow:auto;".
		"font-family:monospace;white-space:pre-wrap;word-break:break-all'>\n";
	my $n = 0;
	foreach my $line (split(/\n/, $content, -1)) {
		$n++;
		my $is_match = ($match_line ne '' && $n == $match_line);
		my $style = $is_match ? "background:#5a3d00;display:block" : "display:block";
		printf("<span style='%s'><span style='color:#777'>%4d</span> %s</span>\n", $style, $n, &html_escape($line));
		}
	print "</div>\n";
	}
else {
	print "<p>Unexpected error reading this finding.</p>\n";
	}

print "<p><a href='findings.cgi'>&laquo; Back to findings</a></p>\n";
&ui_print_footer("/", "Webmin index page");
