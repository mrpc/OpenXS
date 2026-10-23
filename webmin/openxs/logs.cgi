#!/usr/bin/perl
# logs.cgi
# All OpenXS log files in one place, instead of "check the log on the server".

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;

my $n = $in{'lines'};
$n =~ s/[^0-9]//g;
$n = 100 if ($n eq '' || $n < 1);

my %logs = (
	"Scan daemon (openxs-scand)" => $daemon_log,
	"Watch daemon (openxs-watchd)" => $watchd_log,
	"Scheduled scan (cron)" => "$pmf_dir/cron.log",
	"Scheduled scan - scanner's own stderr" => "$pmf_dir/scan.log",
	"Quarantine actions" => "/var/log/openxs-quarantine.log",
	"File integrity - last check" => "$pmf_dir/fim_results.txt",
);

foreach my $title (sort keys %logs) {
	my $file = $logs{$title};
	print &ui_subheading("$title <small>(<code>$file</code>)</small>");
	print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:300px;overflow:auto'>".
		&html_escape(&openxs_tail($file, $n))."</pre>\n";
	}

if (-d '/etc/modsecurity') {
	print &ui_subheading("mod_security blocks <small>(across every Apache error log on this server)</small>");
	my @rows = &openxs_modsec_rows();
	if (!@rows) {
		print "<p>(no blocks found)</p>\n";
		}
	else {
		my $last = $#rows > $n - 1 ? $n - 1 : $#rows;
		print &ui_columns_start(["Count", "Host", "Path", "Rule"]);
		foreach my $r (@rows[0 .. $last]) {
			print &ui_columns_row([$r->{'count'}, &html_escape($r->{'host'}), &html_escape($r->{'uri'}),
				&openxs_modsec_rule_link($r->{'rule_id'})]);
			}
		print &ui_columns_end();
		}
	print "<p><a href='modsec_log.cgi'>Full view with grouping notes &raquo;</a></p>\n";
	}

print "<p><a href='logs.cgi?lines=" . ($n * 5) . "'>Show more lines (last $n shown)</a></p>\n";
print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
