#!/usr/bin/perl
# tail_text.cgi
# Tiny plain-text endpoint polled by logs.cgi's single-log view to make
# "View full log" an actually-live tail, not a one-off snapshot. Not a
# themed Webmin page - just raw text, same spirit as daemon_stats.cgi.

require './openxs-lib.pl';
&ReadParse();

my %logs = (
	"scand" => $daemon_log,
	"watchd" => $watchd_log,
	"cron" => "$pmf_dir/cron.log",
	"scanlog" => "$pmf_dir/scan.log",
	"quarantine" => "/var/log/openxs-quarantine.log",
	"fim" => "$pmf_dir/fim_results.txt",
);

my $file = $logs{$in{'file'}};
my $n = $in{'lines'};
$n =~ s/[^0-9]//g;
$n = 200 if ($n eq '' || $n < 1);

print "Content-type: text/plain; charset=utf-8\n\n";
print $file ? &openxs_tail($file, $n) : "";
