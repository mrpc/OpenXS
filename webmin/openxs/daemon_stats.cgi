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

# "version"/"corefiles"/"dbscan" are version_scan.py's own stages, run
# by run_scheduled_scan.sh right after "fs" - see its _write_progress()
# for why it needs these at all (the file pmf_scan.py itself wrote
# "fs\t0" to and then removed only covered its own run, not the script
# that runs right after it).
my @SCAN_STAGES = ('scan', 'clamav', 'maldet', 'fs', 'version', 'corefiles', 'dbscan');

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

# Stage-equal-slice is a rough guess (clamav/maldet/fs can each take very
# different amounts of real time). Comparing elapsed time against how
# long past full scans actually took is a better "how much is left"
# estimate - cheap to compute (one sqlite query), so just do both and
# let the UI show the sharper one.
sub overall_pct_from_history
{
my ($etimes) = @_;
return undef if (!$etimes);
my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
durations = [d for _, _, _, files, _, d, _ in openxs_db.recent_scans(10) if files and files > 100000 and d]
print(sum(durations) / len(durations) if durations else '')
" 2>/dev/null`;
$out =~ s/\s+//g;
return undef if ($out eq '' || $out !~ /^[\d.]+$/);
return sprintf("%.1f", $etimes / $out * 100) + 0;
}

my %cfg = &openxs_read_config();
my $scan_proc = &proc_json(&openxs_scan_pid());
my $data = {
	scand => &proc_json(&openxs_daemon_pid()),
	watchd => &proc_json(&openxs_watchd_pid()),
	scan => $scan_proc,
	scan_progress => &scan_progress_json(),
	};
if ($data->{'scan_progress'} && $scan_proc->{'pid'}) {
	my $hist_pct = &overall_pct_from_history($scan_proc->{'etimes'});
	$data->{'scan_progress'}->{'overall_pct_from_history'} = $hist_pct if (defined($hist_pct));
	}

print "Content-type: application/json\n\n";
print JSON::PP->new->encode($data);
