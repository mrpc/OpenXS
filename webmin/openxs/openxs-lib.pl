# openxs-lib.pl
# Shared functions for the OpenXS Webmin module

BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();

our $socket_path = $ENV{'OPENXS_SOCKET'} || '/run/openxs/scan.sock';
our $daemon_script = '/opt/php-malware-finder/openxs-scand.py';
our $daemon_log = '/var/log/openxs-scand.log';
our $ruleset = '/opt/php-malware-finder/php.yar';

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

1;
