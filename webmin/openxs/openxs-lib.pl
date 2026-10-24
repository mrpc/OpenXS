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
	'modsec_exclusions' => '/etc/openxs/modsec_exclusions',
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

# A manual or scheduled scan (pmf_scan.py scan ...) isn't a long-running
# daemon with its own PID file - found the same way, by matching its
# command line, specifically the "scan" subcommand (not "whitelist").
sub openxs_scan_pid
{
my $pattern = &pgrep_safe_pattern("pmf_scan.py scan");
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

# True if this is the old, pre-GPLv3 (< v15.00) licensed line - the
# upstream download/license infrastructure for it is already offline
# (see TIMELINE.md), so staying on it isn't "stable", it's unmaintained.
sub openxs_csf_old
{
my $v = `csf -v 2>/dev/null`;
return 0 if ($v !~ /v(\d+)\.(\d+)/);
return $1 < 15 ? 1 : 0;
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

sub openxs_clamav_apparmor_issue
{
# True only when the profile exists, lacks the attach_disconnected fix
# (see servers/prod-host-3.pramnoshosting.gr.md, 2026-10-24), AND the
# resulting denial has actually fired recently - so this never warns
# about a system that will simply never hit the pattern.
my $profile = '/etc/apparmor.d/usr.sbin.clamd';
return 0 if (!-f $profile);
my $has_fix = `grep -c attach_disconnected '$profile' 2>/dev/null`;
return 0 if ($has_fix + 0 > 0);
my $denied = `dmesg -T 2>/dev/null | grep -c 'clamd.*disconnected path'`;
return $denied + 0 > 0 ? 1 : 0;
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
# directories (confirmed on prod-host-3: a real, independent inotify tree,
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

# Big top-of-dashboard widget version of openxs_proc_stats() - added
# right after a daemon's own memory nearly exhausted the server's free
# RAM with nothing prominent enough on the dashboard to catch it early.
# $limit_mb colors it (green/amber/red) relative to that daemon's own
# configured safety backstop (WATCHD_MAX_RSS_MB et al), so "getting
# close to its own limit" is visible before it actually trips.
sub openxs_resource_widget
{
# $log_key: which logs.cgi?only=... page this box should link to -
# defaults to $key, but the scan widget's own key ("scan") doesn't
# match its log's key ("scanlog"), so callers can override it.
my ($key, $label, $pid, $limit_mb, $log_key) = @_;
$log_key ||= $key;
my $box_style = "flex:1;min-width:200px;border-radius:6px;padding:16px;text-align:center";
my $link_open = "<a href='logs.cgi?only=$log_key' style='text-decoration:none;color:inherit;display:block'>";
my $link_close = "</a>";
if (!$pid) {
	return "<div id='widget-$key' style='$box_style;background:#f5f5f5;border:2px solid #ddd'>$link_open".
		"<div style='font-size:13px;color:#888;margin-bottom:6px'>$label</div>".
		"<div style='font-size:22px;color:#888'>Not running</div>$link_close</div>";
	}
my $out = `ps -o rss=,%cpu= -p $pid 2>/dev/null`;
$out =~ s/^\s+//;
my ($rss_kb, $cpu) = split(/\s+/, $out);
if ($rss_kb eq '' || $rss_kb !~ /^\d+$/) {
	return "<div id='widget-$key' style='$box_style;background:#f5f5f5;border:2px solid #ddd'>$link_open".
		"<div style='font-size:13px;color:#888;margin-bottom:6px'>$label</div>".
		"<div style='font-size:22px;color:#888'>Unknown</div>$link_close</div>";
	}
my $mb = $rss_kb / 1024;
my $pct = $limit_mb ? ($mb / $limit_mb * 100) : 0;
my $color = $pct >= 90 ? '#b30000' : ($pct >= 50 ? '#b38f00' : '#2e7d32');
my $mb_fmt = sprintf("%.0f", $mb);
# id's on the pieces that auto-refresh.cgi JS (see index.cgi) updates in
# place every few seconds, instead of a full page reload - Webmin's
# authentic theme already has a known, pre-existing "refresh resets to
# dashboard" quirk, so this avoids triggering that for something that's
# meant to just tick in the background. The whole box is also a link
# through to that process's own live log view.
return "<div id='widget-$key' style='$box_style;background:#fff;border:2px solid $color' data-limit-mb='" . ($limit_mb || 0) . "'>$link_open".
	"<div style='font-size:13px;color:#555;margin-bottom:6px'>$label (pid <span id='pid-$key'>$pid</span>)</div>".
	"<div id='rss-$key' style='font-size:34px;font-weight:bold;color:$color;line-height:1.1'>${mb_fmt}<span style='font-size:16px'>MB</span></div>".
	"<div style='font-size:12px;color:#888'>RAM" . ($limit_mb ? " of ${limit_mb}MB limit" : "") . "</div>".
	"<div id='cpu-$key' style='font-size:22px;font-weight:bold;margin-top:10px;color:#333'>${cpu}<span style='font-size:14px'>%</span></div>".
	"<div style='font-size:12px;color:#888'>CPU</div>".
	"<div id='extra-$key' style='font-size:12px;color:#888;margin-top:8px'></div>".
	"$link_close</div>";
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
            'THROTTLE_LOAD' => '', 'QUIET' => '0', 'QUARANTINE_CATEGORIES' => 'virus,yara_exploit,maldet',
            'WATCH_PATHS' => '', 'SCAN_MODE' => 'path', 'ACCOUNTS_DIR' => '/home',
            'ACCOUNTS_SUBPATH' => 'public_html', 'WATCH_RATE_COUNT' => '5',
            'WATCH_RATE_WINDOW' => '10', 'WATCH_RATE_COOLDOWN' => '60',
            # Both default on - that was the only behavior before these
            # had a toggle at all (run_scheduled_scan.sh ran them
            # unconditionally), so an existing config file with neither
            # key set must keep working exactly as before.
            'VERSION_SCAN_ENABLED' => '1', 'APT_SECURITY_ENABLED' => '1',
            'WATCHD_MAX_RSS_MB' => '1024', 'OPENXS_SRC' => '', 'AUTO_UPDATE' => '0',
            'VMRSS_MAX_MB' => '2000' );
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

# Pure Perl, no fork+exec of an external tail(1) - under heavy system load
# (e.g. a scan running concurrently) the backtick form was observed to
# intermittently return truncated output, presumably a fork/exec hiccup.
sub openxs_tail
{
my ($file, $n) = @_;
$n ||= 40;
return "(no such file: $file)" if (!-e $file);
open(my $fh, '<', $file) or return "(could not open $file: $!)";
my @lines = <$fh>;
close($fh);
# ponytail: reads the whole file into memory - fine for these logs (a
# few MB at most); switch to a seek-from-end approach if one ever grows large.
my @last = @lines > $n ? @lines[-$n .. -1] : @lines;
return join('', @last);
}

# Parses openxs_modsec_log.py's tab-separated CLI output into row hashes -
# shared by modsec_log.cgi (full table) and logs.cgi (compact preview) so
# both render from the same real data instead of one reformatting raw text.
sub openxs_modsec_rows
{
my $out = `python3 $pmf_dir/openxs_modsec_log.py 2>&1`;
my @rows;
foreach my $line (split(/\n/, $out)) {
	my ($count, $host, $uri, $rule_id, $first, $last) = split(/\t/, $line);
	next if (!defined($rule_id) || $rule_id !~ /^\d+$/);
	push(@rows, { count => $count, host => $host, uri => $uri, rule_id => $rule_id, first => $first, last => $last });
	}
return @rows;
}

# Inline SVG bar chart, no external JS/CDN (some of our servers have no
# outbound internet access at all, and a chart library is unwarranted
# for one bar chart) - factored out of stats.cgi so a second chart
# (mod_security blocks/day) doesn't have to duplicate this ~30 lines.
# \@dates and \@values must be the same length, oldest first.
sub openxs_bar_chart
{
my ($dates, $values, $color) = @_;
my $n = scalar(@$dates);
return "" if ($n == 0);
my $max_v = 1;
foreach my $v (@$values) { $max_v = $v if ($v > $max_v); }

my $bar_w = $n > 60 ? 10 : ($n > 30 ? 16 : 32);
my $gap = $bar_w > 16 ? 8 : 3;
my $plot_h = 160;
my $top_pad = 24;
my $label_h = 28;
my $chart_w = $n * ($bar_w + $gap) + $gap;
my $chart_h = $top_pad + $plot_h + $label_h;
my $baseline_y = $top_pad + $plot_h;

my $svg = "<svg width='$chart_w' height='$chart_h' style='background:#fff;border:1px solid #ddd;border-radius:4px' font-family='sans-serif'>\n";
foreach my $frac (0.25, 0.5, 0.75, 1.0) {
	my $gy = $baseline_y - $plot_h * $frac;
	$svg .= "<line x1='0' y1='$gy' x2='$chart_w' y2='$gy' stroke='#eee' stroke-width='1'/>\n";
	}
$svg .= "<line x1='0' y1='$baseline_y' x2='$chart_w' y2='$baseline_y' stroke='#ccc' stroke-width='1'/>\n";

my $x = $gap;
my $label_every = $n > 14 ? int($n / 14) + 1 : 1;
for (my $i = 0; $i < $n; $i++) {
	my $date = $dates->[$i];
	my $v = $values->[$i];
	my $bar_h = $v > 0 ? ($v / $max_v) * ($plot_h - 4) : 0;
	my $y = $baseline_y - $bar_h;
	my $bar_color = $v > 0 ? $color : '#ddd';
	my $cx = $x + $bar_w / 2;
	$svg .= "<rect x='$x' y='$y' width='$bar_w' height='" . ($bar_h || 2) . "' rx='2' fill='$bar_color'>".
		"<title>$date: $v</title></rect>\n";
	if ($v > 0) {
		$svg .= "<text x='$cx' y='" . ($y - 6) . "' font-size='11' fill='#333' text-anchor='middle'>$v</text>\n";
		}
	if ($i % $label_every == 0) {
		my $short_date = $date;
		$short_date =~ s/^\d{4}-//;
		$svg .= "<text x='$cx' y='" . ($baseline_y + 16) . "' font-size='10' fill='#666' text-anchor='middle' ".
			"transform='rotate(45 $cx " . ($baseline_y + 16) . ")'>$short_date</text>\n";
		}
	$x += $bar_w + $gap;
	}
$svg .= "</svg>\n";
return $svg;
}

# A rule ID on its own means nothing to a human - links to the exact rule
# definition (message, what it's for) in the OWASP Core Rule Set source,
# rather than trying to keep our own copy of every rule's explanation in
# sync with whatever CRS version is actually installed.
sub openxs_modsec_rule_link
{
my ($rule_id) = @_;
return "<a href='https://github.com/coreruleset/coreruleset/search?q=" . &html_escape($rule_id) .
	"' target='_blank' rel='noopener'>rule $rule_id</a>";
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
