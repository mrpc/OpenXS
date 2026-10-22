# openxs-lib.pl
# Shared functions for the OpenXS Webmin module

BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();

our $socket_path = $ENV{'OPENXS_SOCKET'} || '/run/openxs/scan.sock';
our $daemon_script = '/opt/php-malware-finder/openxs-scand.py';
our $daemon_log = '/var/log/openxs-scand.log';
our $ruleset = '/opt/php-malware-finder/php.yar';
our $pmf_dir = '/opt/php-malware-finder';
our $config_file = '/etc/openxs/openxs.conf';
our $modsec_rule = '/etc/modsecurity/openxs.conf';
our $csf_regex = '/etc/csf/regex.custom.pm';

sub openxs_daemon_pid
{
my $out = `pgrep -f '$daemon_script' 2>/dev/null`;
my ($pid) = split(/\s+/, $out);
return $pid;
}

sub openxs_socket_exists
{
return -S $socket_path ? 1 : 0;
}

sub openxs_pmf_installed
{
return -e $ruleset ? 1 : 0;
}

sub openxs_pmf_commit
{
return "" if (!&openxs_pmf_installed());
my $out = `cd $pmf_dir && git log -1 --format=%h 2>/dev/null`;
chomp($out);
return $out;
}

sub openxs_modsecurity_installed
{
return -e '/etc/modsecurity/modsecurity.conf' ? 1 : 0;
}

sub openxs_modsecurity_hook_installed
{
return -e $modsec_rule ? 1 : 0;
}

sub openxs_csf_present
{
return -e '/etc/csf/csf.conf' ? 1 : 0;
}

sub openxs_csf_hook_installed
{
return 0 if (!&openxs_csf_present());
return 0 if (!-e $csf_regex);
my $out = `grep -l openxs $csf_regex 2>/dev/null`;
return $out ne "" ? 1 : 0;
}

# Simple key=value config file, used both by this module and by the shell
# scripts (run as plain `source`-able shell variables).
sub openxs_read_config
{
my %cfg = ( 'EMAIL' => 'root@localhost', 'SCAN_PATH' => '/var/www', 'QUARANTINE_ENABLED' => '0' );
if (open(my $fh, '<', $config_file)) {
	while (<$fh>) {
		chomp;
		next if (/^\s*#/ || !/=/);
		my ($k, $v) = split(/=/, $_, 2);
		$cfg{$k} = $v;
		}
	close($fh);
	}
return %cfg;
}

sub openxs_write_config
{
my (%cfg) = @_;
mkdir('/etc/openxs', 0755) if (!-d '/etc/openxs');
open(my $fh, '>', $config_file) || return 0;
foreach my $k (sort keys %cfg) {
	print $fh "$k=$cfg{$k}\n";
	}
close($fh);
return 1;
}

1;
