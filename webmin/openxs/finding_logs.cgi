#!/usr/bin/perl
# finding_logs.cgi
# "Who hit this file?" - correlates a finding with Apache/Virtualmin
# access logs, grouped by IP, with a one-click Ban button per IP.
# Deliberately NOT automatic - a false match (e.g. Googlebot crawling a
# flagged file before it was caught) would otherwise risk banning
# something harmless. The admin reviews the list and decides.

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
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db, openxs_logsearch

row = openxs_db.finding_by_id($fid)
if not row:
    print('NOTFOUND')
    sys.exit()
file_path, rule_name, quarantine_path, size = row
hits = openxs_logsearch.find_access_log_hits(file_path)
summary = openxs_logsearch.summarize_by_ip(hits)
print(f'OK\\t{file_path}\\t{len(hits)}')
for ip, s in summary.items():
    print(f'{ip}\\t{s[\\\"count\\\"]}\\t{s[\\\"first\\\"]}\\t{s[\\\"last\\\"]}\\t{s[\\\"sample_path\\\"]}')
"`;

my @lines = grep { $_ ne "" } split(/\n/, $out);

if (!@lines || $lines[0] eq 'NOTFOUND') {
	print "<p>No such finding.</p>\n";
	}
elsif ($lines[0] =~ /^OK\t([^\t]*)\t(\d+)$/) {
	my ($file_path, $hit_count) = ($1, $2);
	shift(@lines);
	print &ui_subheading("Who hit: " . &html_escape($file_path));
	if (!@lines) {
		print "<p>No matching requests found in the access logs on this server " .
			"(the file may predate the logs, or was never requested directly).</p>\n";
		}
	else {
		print "<p>$hit_count total request(s) from " . scalar(@lines) . " distinct IP(s).</p>\n";
		print &ui_columns_start(["IP", "Hits", "First seen", "Last seen", "Sample request", ""]);
		foreach my $line (@lines) {
			my ($ip, $count, $first, $last, $path) = split(/\t/, $line);
			my $reason = "OpenXS: hit flagged file $file_path";
			print &ui_columns_row([
				&html_escape($ip), $count, &html_escape($first), &html_escape($last), &html_escape($path),
				&ui_form_start("ban_ip.cgi", "post") .
					&ui_hidden("ip", $ip) . &ui_hidden("reason", $reason) . &ui_hidden("fid", $fid) .
					&ui_submit("Ban", "go", 0, "onclick=\"return confirm('Block $ip at the firewall?')\"") .
					&ui_form_end(),
				]);
			}
		print &ui_columns_end();
		}
	}
else {
	print "<p>Unexpected error searching the logs.</p>\n";
	}

print "<p><a href='findings.cgi'>&laquo; Back to findings</a></p>\n";
&ui_print_footer("/", "Webmin index page");
