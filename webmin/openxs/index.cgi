#!/usr/bin/perl
# index.cgi
# OpenXS dashboard: component status, daemon control, manual scan, settings

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $pid = &openxs_daemon_pid();
my $has_socket = &openxs_socket_exists();
my $pmf_ok = &openxs_pmf_installed();
my $modsec_ok = &openxs_modsecurity_installed();
my $modsec_hook_ok = &openxs_modsecurity_hook_installed();
my $csf_ok = &openxs_csf_present();
my $csf_hook_ok = &openxs_csf_hook_installed();
my $clamav_ok = &openxs_clamav_installed();
my $clamav_running = &openxs_clamav_running();

sub status_cell
{
my ($ok, $yes, $no) = @_;
return $ok ? "<b style='color:green'>$yes</b>" : "<b style='color:#b30000'>$no</b>";
}

sub mini_form
{
my ($action, $buttons_html) = @_;
return &ui_form_start($action, "post") . $buttons_html . &ui_form_end();
}

sub row_value
{
my ($status_html, $action_html) = @_;
return $status_html . ($action_html ne "" ? "<div style='margin-top:4px'>$action_html</div>" : "");
}

print $openxs_nav;

print &ui_subheading("Components");
print &ui_table_start(undef, undef, 1);

print &ui_table_row("Detection engine (php-malware-finder)",
	&row_value(&status_cell($pmf_ok, "Installed (" . &openxs_pmf_commit() . ")", "Not installed"),
		$pmf_ok ? &mini_form("update.cgi",
			&ui_textbox("ruleset_ref", "", 20) . " <i>(blank = latest from our fork; or a specific commit/tag)</i><br>" .
			&ui_submit("Update now", "update"))
		        : "<i>installed as part of the base image</i>"));

print &ui_table_row("ClamAV (virus scanning, 2nd detector)",
	&row_value($clamav_ok ? &status_cell($clamav_running, "Installed, running", "Installed, not running")
	                      : "<i style='color:#888'>Not installed - ran without it (optional, degrades gracefully)</i>", ""));

my $maldet_ok = &openxs_maldet_installed();
print &ui_table_row("maldet (Linux Malware Detect, 3rd detector)",
	&row_value($maldet_ok ? &status_cell(1, "Installed - own MD5/HEX/YARA signature set", "")
	                      : "<i style='color:#888'>Not installed - ran without it (optional, degrades gracefully)</i>", ""));

print &ui_table_row("Scan daemon (openxs-scand, shared YARA engine - powers the upload hook + watch daemon)",
	&row_value($pid ? &status_cell(1, "Running (pid $pid)", "") : &status_cell(0, "", "Not running"),
		&mini_form("daemon.cgi",
			&ui_hidden("which", "scand") .
			&ui_submit("Start", "start") . &ui_submit("Stop", "stop") . &ui_submit("Restart", "restart"))));

my $watchd_pid = &openxs_watchd_pid();
my %cfg_early = &openxs_read_config();
print &ui_table_row("Watch daemon (openxs-watchd, account-wide inotify monitor) <i>early/evolving</i>",
	&row_value($watchd_pid ? &status_cell(1, "Running (pid $watchd_pid)", "")
	           : (($cfg_early{'WATCH_PATHS'} || '') eq '' ? "<i style='color:#888'>Not running - set 'Watch paths' below first</i>"
	                                                       : &status_cell(0, "", "Not running")),
		&mini_form("daemon.cgi",
			&ui_hidden("which", "watchd") .
			&ui_submit("Start", "start") . &ui_submit("Stop", "stop") . &ui_submit("Restart", "restart"))));

print &ui_table_row("mod_security (real-time upload blocking)",
	&row_value(&status_cell($modsec_ok && $modsec_hook_ok, "Installed and hooked up", "Not installed"),
		($modsec_ok && $modsec_hook_ok) ? "" : &mini_form("install_modsecurity.cgi", &ui_submit("Install", "install"))));

print &ui_table_row("CSF firewall auto-block hook",
	&row_value($csf_ok ? &status_cell($csf_hook_ok, "Hooked up", "CSF found, hook not installed")
	                    : "<i style='color:#888'>CSF not found on this server</i>",
		($csf_ok && !$csf_hook_ok) ? &mini_form("install_csf_hook.cgi", &ui_submit("Install", "install")) : "")
	. ($csf_ok && -d "/usr/share/webmin/csf" ? "<div style='margin-top:4px'><a href='../csf/'>Open CSF Firewall module &raquo;</a></div>" : ""));

if ($csf_ok) {
	my $active_feeds = `grep -c '^[A-Z]' /etc/csf/csf.blocklists 2>/dev/null`;
	chomp($active_feeds);
	print &ui_table_row("IP reputation (CSF BLOCKLIST feeds)",
		&row_value("<b>" . ($active_feeds || 0) . "</b> feed(s) active - native CSF feature, not tied to any license",
			"<a href='edit_file.cgi?f=csf_blocklists'>Edit csf.blocklists &raquo;</a>"));
	}

print &ui_table_end();

print &ui_subheading("Scan daemon log (last 30 lines)");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:300px;overflow:auto'>".
	&html_escape(&openxs_tail($daemon_log, 30))."</pre>";
print "<p><a href='logs.cgi'>View all logs &raquo;</a></p>\n";

print &ui_subheading("Run a manual scan");
my %cfg = &openxs_read_config();
print &ui_form_start("scan.cgi", "post");
print &ui_table_start(undef, undef, 2);
print &ui_table_row("Directory to scan", &ui_textbox("path", "/var/www", 50));
print &ui_table_row("...or every account", &ui_checkbox("accounts", "1",
	"Scan all accounts under '" . &html_escape($cfg{'ACCOUNTS_DIR'}) . "/*/" . &html_escape($cfg{'ACCOUNTS_SUBPATH'}) .
	"' instead (ignores 'Directory to scan' above) - see Settings below to change the accounts directory.", 0));
print &ui_table_end();
print &ui_submit("Scan now", "scan");
print &ui_form_end();

print &ui_subheading("Settings");
print &ui_form_start("config.cgi", "post", undef, "autocomplete='off'");
print &ui_table_start(undef, undef, 2);
print &ui_table_row("Alert e-mail address", &ui_textbox("alert_addr", $cfg{'EMAIL'}, 40, 0, 0, "autocomplete='off'"));
print &ui_table_row("Daily cron scan mode", &ui_select("scan_mode", $cfg{'SCAN_MODE'},
	[["path", "Single directory"], ["accounts", "Every account (cxs's --allusers)"]]));
print &ui_table_row("Directory scanned (single-directory mode)", &ui_textbox("scan_path", $cfg{'SCAN_PATH'}, 40, 0, 0, "autocomplete='off'"));
print &ui_table_row("Accounts directory (accounts mode)", &ui_textbox("accounts_dir", $cfg{'ACCOUNTS_DIR'}, 40, 0, 0, "autocomplete='off'") .
	" <i>one subdirectory per hosting account, e.g. /home/&lt;user&gt;</i>");
print &ui_table_row("Web root subfolder per account (accounts mode)", &ui_textbox("accounts_subpath", $cfg{'ACCOUNTS_SUBPATH'}, 40, 0, 0, "autocomplete='off'") .
	" <i>e.g. public_html - blank scans the whole account home dir (mail/backups too, usually not what you want)</i>");
print &ui_table_row("Schedule (cron syntax: min hour day month weekday)",
	&ui_textbox("schedule", $cfg{'SCHEDULE'}, 20, 0, 0, "autocomplete='off'") . " <i>e.g. '17 2 * * *' = 02:17 daily; blank = disable the scheduled scan entirely</i>");
print &ui_table_row("Quarantine", &ui_checkbox("quarantine_enabled", "1",
	"Move flagged files to quarantine (manual + scheduled scans only, not the real-time upload hook)",
	$cfg{'QUARANTINE_ENABLED'} eq '1'));
my %qcats = map { $_ => 1 } split(/,/, $cfg{'QUARANTINE_CATEGORIES'});
print &ui_table_row("...which categories to quarantine",
	&ui_checkbox("qcat_virus", "1", "Viruses (ClamAV)", $qcats{'virus'}) . "<br>" .
	&ui_checkbox("qcat_yara", "1", "Known exploits (YARA + custom rules)", $qcats{'yara'}) . "<br>" .
	&ui_checkbox("qcat_maldet", "1", "Known exploits (maldet - MD5/HEX/YARA)", $qcats{'maldet'}) . "<br>" .
	&ui_checkbox("qcat_fs", "1", "Filesystem indicators (SUID/symlinks/binaries - <b>not recommended</b>: ".
		"these are often legitimate parts of the server)", $qcats{'fs'}));
print &ui_table_row("Fast mode (.php files only)", &ui_checkbox("fast_php_only", "1",
	"Only scan *.php files, instead of everything under the scan path. Faster, but a webshell saved with ".
	"a disguised extension (e.g. avatar.jpg containing real PHP code) would no longer be caught. ".
	"Off by default - scans everything.",
	$cfg{'FAST_PHP_ONLY'} eq '1'));
print &ui_table_row("Only scan files changed in the last N hours",
	&ui_textbox("changed_hours", $cfg{'CHANGED_HOURS'}, 10) . " <i>blank = no time filter, scan everything</i>");
print &ui_table_row("Throttle: pause if 1-min load average exceeds",
	&ui_textbox("throttle_load", $cfg{'THROTTLE_LOAD'}, 10) . " <i>blank = disabled; sleeps 60s at a time until load drops</i>");
print &ui_table_row("Quiet output", &ui_checkbox("quiet", "1",
	"Suppress the scan summary line (useful for cron jobs where only hits should trigger e-mail)",
	$cfg{'QUIET'} eq '1'));
print &ui_table_row("Ignore file", "<a href='edit_file.cgi?f=ignore'>Edit /etc/openxs/ignore &raquo;</a> <i>one path/substring per line to skip</i>");
print &ui_table_row("Custom rule file", "<a href='edit_file.cgi?f=rules'>Edit /etc/openxs/rules &raquo;</a> <i>one extra regex per line to additionally flag</i>");
print &ui_table_row("Per-path settings", "<a href='edit_file.cgi?f=path_settings'>Edit /etc/openxs/path_settings &raquo;</a> <i>one override per line: ".
	"<code>/some/path fast_php_only=1,quarantine_enabled=0</code> - longest matching path wins.</i>");
print &ui_table_row("Watch paths (for the watch daemon above)",
	&ui_textbox("watch_paths", $cfg{'WATCH_PATHS'}, 60, 0, 0, "autocomplete='off'") .
	" <i>comma-separated directories to monitor continuously. Blank = every account's web root ".
	"(Accounts directory/subpath below), same as accounts-mode scanning. ".
	"Restart the watch daemon after changing this.</i>");
print &ui_table_row("Watch daemon rate limit",
	"ignore a file for " . &ui_textbox("watch_rate_cooldown", $cfg{'WATCH_RATE_COOLDOWN'}, 5) .
	"s if it's scanned more than " . &ui_textbox("watch_rate_count", $cfg{'WATCH_RATE_COUNT'}, 5) .
	" times within " . &ui_textbox("watch_rate_window", $cfg{'WATCH_RATE_WINDOW'}, 5) .
	"s <i>(cxs's --Wrateignore - stops a constantly-rewritten file, e.g. a log, from being rescanned on every single write)</i>");
print &ui_table_end();
print &ui_submit("Save", "save");
print &ui_form_end();

print &ui_subheading("Support");
print "<p><a href='support.cgi'>Install Information</a> <i>(diagnostic dump, for troubleshooting)</i></p>\n";

print &ui_subheading("Danger zone");
print &ui_form_start("disable_ui.cgi", "post");
print "<p>" . &ui_submit("Disable this UI completely", "disable") .
	" <i>Cannot be undone from the UI itself - remove <code>$ui_disabled_file</code> on the server to re-enable.</i></p>\n";
print &ui_form_end();

&ui_print_footer("/", "Webmin index page");
