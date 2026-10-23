# openxs-lib.pl
# Shared functions for the OpenXS Webmin module

BEGIN { push(@INC, ".."); };
use WebminCore;
use JSON::PP;
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
	'fim_paths' => '/etc/openxs/fim_paths',
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
return -x "/usr/bin/clamdscan" ? 1 : 0;
}

sub openxs_clamav_running
{
my $out = `pgrep -x clamd 2>/dev/null`;
return $out ne "" ? 1 : 0;
}

sub openxs_maldet_installed
{
# -x check on the canonical path, not `command -v` via backtick - the
# latter was unreliable specifically when run from this Perl/CGI context
return -x "/usr/local/sbin/maldet" ? 1 : 0;
}

sub openxs_maldet_monitor_active
{
# maldet's own --monitor daemon runs its own separate inotify watch -
# redundant with openxs-watchd if both end up watching the same
# directories (confirmed on prodserver: a real, independent inotify tree,
# not just a stale leftover service).
my $out = `systemctl is-active maldet 2>/dev/null`;
chomp($out);
return $out eq 'active' ? 1 : 0;
}

# Shared by reports.cgi and findings.cgi - every per-finding quarantine
# action (Quarantine now/Restore/Delete) goes through the same themed
# POST form (never a plain <a href> - that navigates out of Webmin's
# theme frame entirely instead of staying inside it).
sub openxs_quarantine_action_form
{
my ($action, $fid, $label, $scan_id, $tags) = @_;
# display:inline-block - these sit next to each other (e.g. Restore +
# Delete), not one per line making every row of a 50-row page
# needlessly tall.
return &ui_form_start("quarantine.cgi", "post", undef, "style='display:inline-block;margin-right:4px'") .
	&ui_hidden("action", $action) . &ui_hidden("id", $fid) .
	&ui_hidden("scan_id", $scan_id) .
	&ui_submit($label, "go", 0, $tags) .
	&ui_form_end();
}

sub openxs_quarantine_action_links
{
my ($fid, $qpath, $scan_id) = @_;
if ($qpath eq "__deleted__") {
	return "<i>Deleted</i>";
	}
elsif ($qpath ne "") {
	return "<b style='color:#b30000'>Quarantined</b><br>".
	       &openxs_quarantine_action_form("restore", $fid, "Restore", $scan_id) .
	       &openxs_quarantine_action_form("delete", $fid, "Delete", $scan_id,
	       	"onclick=\"return confirm('Permanently delete this file?')\"");
	}
else {
	return &openxs_quarantine_action_form("quarantine", $fid, "Quarantine now", $scan_id);
	}
}

# Found a real need for this the hard way: openxs-watchd's own RSS grew
# from ~17MB to over 8.3GB in under 20 minutes (a leak in its rate-
# limiter state, since fixed) with nothing on the dashboard showing it -
# the only way anyone noticed was a server-wide memory check run by hand.
sub openxs_proc_stats
{
my ($pid) = @_;
return "" if (!$pid);
my $out = `ps -o rss=,%cpu= -p $pid 2>/dev/null`;
$out =~ s/^\s+//;
my ($rss_kb, $cpu) = split(/\s+/, $out);
return "" if ($rss_kb eq '' || $rss_kb !~ /^\d+$/);
my $mb = sprintf("%.0f", $rss_kb / 1024);
return " - ${mb}MB RAM, ${cpu}% CPU";
}

sub openxs_full_status
{
# Single source of truth shared with the CLI and the MCP server
# (tools/openxs_status.py) - returns a hashref, or undef on any failure
# (e.g. python3 missing, bad JSON) so callers can fall back gracefully.
my $out = `python3 $pmf_dir/openxs_status.py --json 2>/dev/null`;
my $data = eval { decode_json($out) };
return $data;
}

# Simple key=value config file, used both by this module and by the shell
# scripts (run as plain `source`-able shell variables).
sub openxs_read_config
{
my %cfg = ( 'EMAIL' => 'root@localhost', 'SCAN_PATH' => '/var/www', 'QUARANTINE_ENABLED' => '0',
            'FAST_PHP_ONLY' => '0', 'SCHEDULE' => '17 2 * * *', 'CHANGED_HOURS' => '',
            'THROTTLE_LOAD' => '', 'QUIET' => '0', 'QUARANTINE_CATEGORIES' => 'virus,yara,maldet',
            'WATCH_PATHS' => '', 'SCAN_MODE' => 'path', 'ACCOUNTS_DIR' => '/home',
            'ACCOUNTS_SUBPATH' => 'public_html', 'WATCH_RATE_COUNT' => '5',
            'WATCH_RATE_WINDOW' => '10', 'WATCH_RATE_COOLDOWN' => '60',
            # Both default on - that was the only behavior before these
            # had a toggle at all (run_scheduled_scan.sh ran them
            # unconditionally), so an existing config file with neither
            # key set must keep working exactly as before.
            'VERSION_SCAN_ENABLED' => '1', 'APT_SECURITY_ENABLED' => '1' );
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

# A fire-and-forget redirect after an action (quarantine restore, daemon
# start, ruleset update, ...) was previously silent on failure - the page
# just reloaded looking unchanged, with nothing telling the user whether
# anything actually happened. These two carry a one-line result message
# through the redirect instead.
our $openxs_nav = "<p><a href='index.cgi'>Dashboard</a> | <a href='findings.cgi'>Findings</a> | ".
	"<a href='reports.cgi'>Scan history</a> | <a href='reports.cgi?view=quarantine'>Quarantine</a> | ".
	"<a href='stats.cgi'>Statistics</a> | <a href='logs.cgi'>Logs</a> | <a href='settings.cgi'>Settings</a> | ".
	"<a href='documentation.cgi'>Documentation</a></p>\n";

# Prints the result of an action directly, in the same request, instead of
# an HTTP redirect to another page. Webmin's modern themes navigate between
# pages via client-side AJAX/PJAX, carrying headers (X-Requested-With,
# X-PJAX) and an xnavigation=1 marker that tell the theme to inject the
# response into the persistent sidebar/header shell already on the page.
# A server-side redirect can't carry any of that - the browser just follows
# the Location header as an ordinary top-level navigation, landing on a
# bare, unthemed page with no sidebar at all (confirmed: CSF's own module
# never redirects after an action for exactly this reason - every action
# there renders its result inline, same as this does).
sub openxs_result_page
{
my ($msg, $is_err, $back_label, $back_url, $detail) = @_;
$back_label ||= "Back to dashboard";
$back_url ||= "index.cgi";
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;
my $color = $is_err ? '#b30000' : '#2e7d32';
my $bg = $is_err ? '#fdecea' : '#eaf6ec';
print "<div style='background:$bg;color:$color;border:1px solid $color;border-radius:4px;".
	"padding:12px;font-weight:bold;margin:12px 0'>" . &html_escape($msg) . "</div>\n";
if ($detail ne '') {
	print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:300px;overflow:auto'>".
		&html_escape($detail)."</pre>\n";
	}
print "<p><a href='$back_url' style='display:inline-block;padding:6px 14px;background:#337ab7;".
	"color:#fff;border-radius:4px;text-decoration:none'>$back_label</a></p>\n";
&ui_print_footer("/", "Webmin index page");
exit;
}

sub openxs_tail
{
my ($file, $n) = @_;
$n ||= 40;
return -e $file ? `tail -n $n '$file' 2>&1` : "(no such file: $file)";
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
