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

my @SCAN_STAGES = ('scan', 'clamav', 'maldet', 'fs');

sub scan_progress_json
{
return undef if (!open(my $pf, '<', '/var/lib/openxs/scan_progress'));
my $line = <$pf>;
close($pf);
my ($stage, $done) = split(/\t/, $line || '');
return undef if (!$stage);
$done =~ s/\D//g if (defined($done));
my ($stage_num) = grep { $SCAN_STAGES[$_] eq $stage } 0..$#SCAN_STAGES;
my $result = { stage => $stage, stage_num => ($stage_num // 0) + 1, stage_count => scalar(@SCAN_STAGES) };
if ($stage eq 'scan' && $done ne '' && -f "$pmf_dir/filelist.txt") {
	my $total_files = `wc -l < '$pmf_dir/filelist.txt' 2>/dev/null`;
	$total_files =~ s/\D//g;
	if ($total_files ne '' && $total_files != 0) {
		$result->{'done'} = $done + 0;
		$result->{'total'} = $total_files + 0;
		$result->{'pct'} = sprintf("%.1f", $done / $total_files * 100) + 0;
		}
	}
return $result;
}

my %cfg = &openxs_read_config();
my $data = {
	scand => &proc_json(&openxs_daemon_pid()),
	watchd => &proc_json(&openxs_watchd_pid()),
	scan => &proc_json(&openxs_scan_pid()),
	scan_progress => &scan_progress_json(),
	};

print "Content-type: application/json\n\n";
print JSON::PP->new->encode($data);
