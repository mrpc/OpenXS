#!/usr/bin/perl
# daemon_stats.cgi
# Tiny JSON endpoint polled every few seconds by index.cgi's own inline
# JS to keep the RAM/CPU widget live without a full page reload. Not a
# themed Webmin page - just a raw JSON response.

require './openxs-lib.pl';
&ReadParse();

sub proc_json
{
my ($pid) = @_;
return { pid => undef } if (!$pid);
my $out = `ps -o rss=,%cpu=,etimes= -p $pid 2>/dev/null`;
$out =~ s/^\s+//;
my ($rss_kb, $cpu, $etimes) = split(/\s+/, $out);
return { pid => undef } if ($rss_kb eq '' || $rss_kb !~ /^\d+$/);
return { pid => $pid + 0, rss_mb => sprintf("%.0f", $rss_kb / 1024) + 0, cpu => $cpu + 0,
	etimes => $etimes + 0 };
}

my %cfg = &openxs_read_config();
my $data = {
	scand => &proc_json(&openxs_daemon_pid()),
	watchd => &proc_json(&openxs_watchd_pid()),
	scan => &proc_json(&openxs_scan_pid()),
	};

print "Content-type: application/json\n\n";
print JSON::PP->new->encode($data);
