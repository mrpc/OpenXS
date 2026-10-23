#!/usr/bin/perl
# ban_ip.cgi
# Blocks one IP at the firewall - CSF if installed, otherwise a direct
# iptables DROP rule. Always a human-reviewed click from finding_logs.cgi,
# never automatic.

require './openxs-lib.pl';
&ReadParse();

my $ip = $in{'ip'};
my $reason = $in{'reason'};
$reason =~ s/[\r\n]//g;
my $fid = $in{'fid'};
$fid =~ s/[^0-9]//g;

if ($ip eq '') {
	&openxs_result_page("No IP given.", 1, "Back", "findings.cgi");
	}

my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_logsearch
ok, method, msg = openxs_logsearch.ban_ip('$ip', '$reason')
print(('OK' if ok else 'FAIL') + '\\t' + (method or '') + '\\t' + msg)
"`;
chomp($out);
my ($status, $method, $msg) = split(/\t/, $out, 3);

my $back_url = $fid ne '' ? "finding_logs.cgi?id=$fid" : "findings.cgi";
if ($status eq 'OK') {
	&openxs_result_page("Blocked $ip via $method: $msg", 0, "Back", $back_url);
	}
else {
	&openxs_result_page("Could not block $ip: $msg", 1, "Back", $back_url);
	}
