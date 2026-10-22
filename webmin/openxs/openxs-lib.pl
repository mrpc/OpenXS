# openxs-lib.pl
# Shared functions for the OpenXS Webmin module

BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();

our $socket_path = $ENV{'OPENXS_SOCKET'} || '/run/openxs/scan.sock';
our $daemon_script = '/opt/php-malware-finder/openxs-scand.py';
our $daemon_log = '/var/log/openxs-scand.log';
our $watchd_script = '/opt/php-malware-finder/openxs-watchd.py';
our $watchd_log = '/var/log/openxs-watchd.log';
our $ruleset = '/opt/php-malware-finder/php.yar';
our $pmf_dir = '/opt/php-malware-finder';
our $config_file = '/etc/openxs/openxs.conf';
our $modsec_rule = '/etc/modsecurity/openxs.conf';
our $csf_regex = '/etc/csf/regex.custom.pm';
our $ui_disabled_file = '/etc/openxs/disableui';

# Files editable from edit_file.cgi - an explicit allow-list, never an
# arbitrary path from the request, since this UI can write as root.
our %editable_files = (
	'ignore' => '/etc/openxs/ignore',
	'rules' => '/etc/openxs/rules',
	'path_settings' => '/etc/openxs/path_settings',
	'csf_blocklists' => '/etc/csf/csf.blocklists',
);

sub openxs_ui_disabled
{
return -e $ui_disabled_file ? 1 : 0;
}

# `pgrep -f 'pattern'` run via backticks is itself invoked as
# `sh -c "pgrep -f 'pattern'"` - that wrapper shell's OWN argv contains
# the literal pattern text too, so without this, pgrep matches its own
# invocation and a daemon that was never started looks "already
# running". The classic `ps aux | grep '[p]attern'` bracket trick
# fixes it: a real process's argv still contains plain "pattern" (the
# bracket is a 1-char class matching that same letter), but the
# self-referencing command line has a literal "[p]" there instead,
# which the pattern can't match against itself.
sub pgrep_safe_pattern
{
my ($s) = @_;
$s =~ s/([A-Za-z])/[$1]/;
return $s;
}

sub openxs_daemon_pid
{
my $pattern = &pgrep_safe_pattern($daemon_script);
my $out = `pgrep -f '$pattern' 2>/dev/null`;
my ($pid) = split(/\s+/, $out);
return $pid;
}

sub openxs_watchd_pid
{
my $pattern = &pgrep_safe_pattern($watchd_script);
my $out = `pgrep -f '$pattern' 2>/dev/null`;
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

sub openxs_clamav_installed
{
my $bin = `command -v clamdscan 2>/dev/null`;
return $bin ne "" ? 1 : 0;
}

sub openxs_clamav_running
{
my $out = `pgrep -x clamd 2>/dev/null`;
return $out ne "" ? 1 : 0;
}

# Simple key=value config file, used both by this module and by the shell
# scripts (run as plain `source`-able shell variables).
sub openxs_read_config
{
my %cfg = ( 'EMAIL' => 'root@localhost', 'SCAN_PATH' => '/var/www', 'QUARANTINE_ENABLED' => '0',
            'FAST_PHP_ONLY' => '0', 'SCHEDULE' => '17 2 * * *', 'CHANGED_HOURS' => '',
            'THROTTLE_LOAD' => '', 'QUIET' => '0', 'QUARANTINE_CATEGORIES' => 'virus,yara',
            'WATCH_PATHS' => '' );
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

sub openxs_write_schedule
{
my ($schedule) = @_;
# Minimal sanity check: 5 whitespace-separated fields (standard cron
# syntax). Reject anything else rather than write a cron file that could
# silently never run, or - since this is root's crontab - something that
# isn't actually a schedule at all.
my @fields = split(/\s+/, $schedule);
return 0 if (scalar(@fields) != 5);
foreach my $f (@fields) {
	return 0 if ($f !~ /^[0-9*\/,\-]+$/);
	}
open(my $fh, '>', '/etc/cron.d/openxs-scan') || return 0;
print $fh "$schedule root /opt/php-malware-finder/run_scheduled_scan.sh >> /opt/php-malware-finder/cron.log 2>&1\n";
close($fh);
return 1;
}

# Kill-switch, checked once here (every .cgi requires this file first) so
# no individual page needs its own check: once disabled, nothing short of
# removing the file via shell brings the UI back - if a compromised app
# could re-enable it from the UI itself, the switch would be pointless.
if (&openxs_ui_disabled()) {
	&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
	print "<p style='color:red'><b>This UI has been disabled.</b> Remove <code>$ui_disabled_file</code> on the server to re-enable it.</p>\n";
	&ui_print_footer("/", "Webmin index page");
	exit;
	}

1;
