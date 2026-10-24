#!/usr/bin/perl
# settings.cgi
# OpenXS configuration - split out from the dashboard so status/health
# and "how it behaves" don't get mixed on the same page. Also holds
# every component's install/update/on-off toggle (detection engine,
# ClamAV, maldet, mod_security, CSF, OpenXS self-update) - one-time
# setup actions, not something to see on the dashboard every day.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print $openxs_nav;

my %cfg = &openxs_read_config();

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

my ($mail_active, $mail_reason) = split(/\t/, `python3 $pmf_dir/mailbox_scan.py --check-active 2>/dev/null`);
my $mail_note = $mail_active eq '1'
	? "<br><i style='color:#888'>Note: $mail_reason - mail already appears scanned at delivery time, this may be redundant here.</i>"
	: "";
print &ui_table_row("WordPress core / composer package version check (nightly, sversionscan-equivalent)",
	&ui_checkbox("version_scan_enabled", "1", "Enabled", $cfg{'VERSION_SCAN_ENABLED'} eq '1'));
print &ui_table_row("Pending apt security updates check (nightly)",
	&ui_checkbox("apt_security_enabled", "1", "Enabled", $cfg{'APT_SECURITY_ENABLED'} eq '1'));
print &ui_table_row("Scan mailboxes for viruses (cxs's 'virusscan' - ClamAV only, not YARA)",
	&ui_checkbox("scan_mailboxes", "1", "Scan every account's Maildir under 'Accounts directory' above",
		$cfg{'SCAN_MAILBOXES'} eq '1') .
	" only scan mail changed in the last " . &ui_textbox("mailbox_recent_hours", $cfg{'MAILBOX_RECENT_HOURS'}, 5) .
	" hours <i>(blank = scan all mail every time - fine for most mailbox sizes, but a full daily re-scan on a ".
	"very large server can be slow)</i>$mail_note");
print &ui_table_row("Schedule (cron syntax: min hour day month weekday)",
	&ui_textbox("schedule", $cfg{'SCHEDULE'}, 20, 0, 0, "autocomplete='off'") . " <i>e.g. '17 2 * * *' = 02:17 daily; blank = disable the scheduled scan entirely</i>");
print &ui_table_row("Quarantine", &ui_checkbox("quarantine_enabled", "1",
	"Move flagged files to quarantine (manual + scheduled scans only, not the real-time upload hook)",
	$cfg{'QUARANTINE_ENABLED'} eq '1'));
my %qcats = map { $_ => 1 } split(/,/, $cfg{'QUARANTINE_CATEGORIES'});
print &ui_table_row("...which categories to quarantine",
	&ui_checkbox("qcat_virus", "1", "Viruses (ClamAV)", $qcats{'virus'}) . "<br>" .
	&ui_checkbox("qcat_yara_exploit", "1", "Known exploits (YARA fingerprint/custom rules - high confidence)", $qcats{'yara_exploit'}) . "<br>" .
	&ui_checkbox("qcat_yara_heuristic", "1", "Suspicious code patterns (YARA heuristics - <b>not recommended</b>: ".
		"relies on a hash-based CMS whitelist that goes stale as sites update, so an unmodified but newer ".
		"core file can be flagged)", $qcats{'yara_heuristic'}) . "<br>" .
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
if (-d '/etc/modsecurity') {
	print &ui_table_row("mod_security path exclusions", "<a href='edit_file.cgi?f=modsec_exclusions'>Edit /etc/openxs/modsec_exclusions &raquo;</a> ".
		"<i>one path prefix per line (e.g. /admin) - fully disables ModSecurity/CRS for matching requests. ".
		"For a real false positive on a first-party endpoint (analytics beacon, already-authenticated admin area), not a general bypass.</i>");
	print &ui_table_row("mod_security detection-only mode", "<a href='edit_file.cgi?f=modsec_mode'>Edit /etc/openxs/modsec_mode &raquo;</a> ".
		"<i>one '&lt;hostname&gt; &lt;mode&gt;' per line, mode is on/detection/off (e.g. <code>www.example.com detection</code>) - ".
		"DetectionOnly logs what would have been blocked without actually blocking it, while you investigate a false positive and ".
		"narrow it down to a precise rule exclusion below. A bare <code>*</code> hostname sets the server-wide default.</i>");
	print &ui_table_row("mod_security rule exclusions", "<a href='edit_file.cgi?f=modsec_rule_exclusions'>Edit /etc/openxs/modsec_rule_exclusions &raquo;</a> ".
		"<i>one '&lt;rule id&gt; &lt;variable&gt;' per line (e.g. <code>930120 ARGS:scope</code>) - disables one specific ".
		"CRS rule for one specific request variable, everything else about that rule (and every other rule) stays active. The precise ".
		"fix for a confirmed false positive - see <a href='modsec_log.cgi'>mod_security blocks</a> and its own audit log entry ".
		"(<code>grep &lt;unique_id&gt; /var/log/apache2/modsec_audit.log</code>) to find which rule+variable actually misfired. ".
		"<b>Server-wide only</b> - confirmed by hand (2026-10-24) that there's no working way to scope this to one path on this ".
		"stack (neither LocationMatch, &lt;If&gt;, ctl:ruleRemoveById, nor a mod_rewrite env var made a difference). For a false ".
		"positive that genuinely needs path-level scoping, use the <a href='edit_file.cgi?f=modsec_mode'>detection-only mode</a> ".
		"toggle (host-level, proven to work) or <a href='edit_file.cgi?f=modsec_exclusions'>path exclusions</a> (full disable) instead.</i>");
	}
print &ui_table_row("File integrity monitoring - watched paths", "<a href='edit_file.cgi?f=fim_paths'>Edit /etc/openxs/fim_paths &raquo;</a> ".
	"<i>one file or directory per line, e.g. /etc/passwd or your framework's core folder - hashed and checked for drift ".
	"(Dashboard's 'Baseline now' / 'Check now', or automatically with the daily scheduled scan).</i>");
print &ui_table_row("Watch paths (for the watch daemon)",
	&ui_textbox("watch_paths", $cfg{'WATCH_PATHS'}, 60, 0, 0, "autocomplete='off'") .
	" <i>comma-separated directories to monitor continuously. Blank = every account's web root ".
	"(Accounts directory/subpath above), same as accounts-mode scanning. ".
	"Restart the watch daemon (Dashboard) after changing this.</i>");
print &ui_table_row("Watch daemon rate limit",
	"ignore a file for " . &ui_textbox("watch_rate_cooldown", $cfg{'WATCH_RATE_COOLDOWN'}, 5) .
	"s if it's scanned more than " . &ui_textbox("watch_rate_count", $cfg{'WATCH_RATE_COUNT'}, 5) .
	" times within " . &ui_textbox("watch_rate_window", $cfg{'WATCH_RATE_WINDOW'}, 5) .
	"s <i>(cxs's --Wrateignore - stops a constantly-rewritten file, e.g. a log, from being rescanned on every single write)</i>");
if ($cfg{'OPENXS_SRC'} ne '' && -d "$cfg{'OPENXS_SRC'}/.git") {
	print &ui_table_row("Self-update (OpenXS's own code - daemon, Webmin module, tools)",
		&ui_checkbox("auto_update", "1",
			"Automatically pull and apply updates weekly, instead of checking manually from the dashboard",
			$cfg{'AUTO_UPDATE'} eq '1'));
	}
print &ui_table_row("Watch daemon memory limit",
	&ui_textbox("watchd_max_rss_mb", $cfg{'WATCHD_MAX_RSS_MB'}, 8) .
	"MB <i>safety backstop - if watchd's own memory ever exceeds this (a runaway custom rule, a future bug, " .
	"anything), it exits on its own and systemd restarts it, instead of growing unchecked until the kernel's " .
	"OOM killer picks some unrelated process instead. Normal usage is a few tens of MB.</i>");
print &ui_table_row("Scheduled scan memory limit",
	&ui_textbox("vmrss_max_mb", $cfg{'VMRSS_MAX_MB'}, 8) .
	"MB <i>the scan aborts (rather than getting OOM-killed) if its own memory passes this - mainly driven by " .
	"how many files it has to track for the end-of-run ClamAV pass. A site with tens of millions of files " .
	"(or that can't exclude large non-web-facing directories via the ignore file) may need this raised; " .
	"check the server's free RAM first.</i>");
print &ui_table_end();
print &ui_submit("Save", "save");
print &ui_form_end();

# Components/integrations - installs, updates, on/off toggles. Moved
# here from the dashboard (2026-10-24, explicit request): the front
# page should read as "what's running right now" (daemons, scans,
# quarantine, logs), not get cluttered with one-time setup actions -
# and a component someone deliberately turned off (mod_security, say)
# shouldn't keep surfacing itself there every time they look.
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

my $pmf_ok = &openxs_pmf_installed();
my $modsec_ok = &openxs_modsecurity_installed();
my $modsec_hook_ok = &openxs_modsecurity_hook_installed();
my $csf_ok = &openxs_csf_present();
my $csf_hook_ok = &openxs_csf_hook_installed();
my $clamav_ok = &openxs_clamav_installed();
my $clamav_running = &openxs_clamav_running();

print &ui_subheading("Components");
print &ui_table_start(undef, undef, 1);

print &ui_table_row("Detection engine (php-malware-finder)",
	&row_value(&status_cell($pmf_ok, "Installed (" . &openxs_pmf_commit() . ")", "Not installed"),
		$pmf_ok ? &mini_form("update.cgi",
			&ui_textbox("ruleset_ref", "", 20) . " <i>(blank = latest from our fork; or a specific commit/tag)</i><br>" .
			&ui_submit("Update now", "update"))
		        : "<i>installed as part of the base image</i>"));

my %cfg_for_src = &openxs_read_config();
my $openxs_src = $cfg_for_src{'OPENXS_SRC'};
if ($openxs_src ne '' && -d "$openxs_src/.git") {
	my $cur_version = `cd $openxs_src && git describe --tags 2>/dev/null`;
	chomp($cur_version);
	if ($cur_version eq '') {
		# No tags reachable (e.g. a fetch that didn't bring any over) -
		# fall back to just the hash rather than showing nothing.
		$cur_version = `cd $openxs_src && git rev-parse --short HEAD 2>/dev/null`;
		chomp($cur_version);
		}
	print &ui_table_row("OpenXS itself (daemon, Webmin module, tools)",
		&row_value("Installed (" . &html_escape($cur_version) . ")",
			&mini_form("self_update.cgi", &ui_submit("Check for updates", "check"))));
	}

my $clamav_apparmor_issue = $clamav_ok && &openxs_clamav_apparmor_issue();
print &ui_table_row("ClamAV (virus scanning, 2nd detector)",
	&row_value(($clamav_ok ? &status_cell($clamav_running, "Installed, running", "Installed, not running")
	                      : "<i style='color:#888'>Not installed - ran without it (optional, degrades gracefully)</i>") .
		($clamav_apparmor_issue ? "<br><span style='font-size:12px;color:#b38f00'>&#9888; AppArmor is denying ".
			"some file lookups (<code>dmesg | grep 'clamd.*disconnected path'</code>) - add ".
			"<code>flags=(attach_disconnected)</code> to <code>/etc/apparmor.d/usr.sbin.clamd</code> ".
			"and reload with <code>apparmor_parser -r</code>.</span>" : ""),
		&mini_form("install_clamav.cgi",
			&ui_submit($clamav_ok ? "Re-apply recommended config" : "Install", "install"))));

my $maldet_ok = &openxs_maldet_installed();
print &ui_table_row("maldet (Linux Malware Detect, 3rd detector)",
	&row_value($maldet_ok ? &status_cell(1, "Installed - own MD5/HEX/YARA signature set", "")
	                      : "<i style='color:#888'>Not installed - ran without it (optional, degrades gracefully)</i>",
		&mini_form("install_maldet.cgi",
			&ui_submit($maldet_ok ? "Re-apply recommended config" : "Install", "install"))));

my $modsec_active = &openxs_modsecurity_active();
my $modsec_overrides = &openxs_modsec_mode_overrides_summary();
print &ui_table_row("mod_security (real-time upload blocking)",
	&row_value(&status_cell($modsec_ok && $modsec_hook_ok && $modsec_active,
			$modsec_ok && $modsec_hook_ok ? "Installed and hooked up" : "Not installed",
			$modsec_ok && $modsec_hook_ok && !$modsec_active ? "Installed but disabled (module not loaded)" : "Not installed") .
		($modsec_overrides ne '' ? "<br><span style='font-size:12px;color:#8a5a1f'>Per-host override: " .
			&html_escape($modsec_overrides) . " (<a href='edit_file.cgi?f=modsec_mode'>edit &raquo;</a>)</span>" : ""),
		($modsec_ok && $modsec_hook_ok)
			# "View recent blocks" stays available either way - disabling
			# the module stops it recording NEW blocks, but the history
			# already on disk (cache + DB) is still worth being able to
			# see, not hidden away along with the toggle.
			? "<a href='modsec_log.cgi'>View recent blocks &raquo;</a> " .
				($modsec_active
					? &mini_form("disable_modsecurity.cgi", &ui_submit("Disable", "disable", 0,
						"onclick=\"return confirm('Disable mod_security entirely on this server? ".
						"(reversible - Install re-enables it)')\""))
					: "<i style='color:#888;font-size:12px'>(showing history from before it was disabled)</i> " .
						&mini_form("install_modsecurity.cgi", &ui_submit("Re-enable", "install")))
			: &mini_form("install_modsecurity.cgi", &ui_submit("Install", "install"))));

if ($csf_ok && &openxs_csf_old()) {
	my $v = `csf -v 2>/dev/null`;
	chomp($v);
	print &ui_table_row("CSF version",
		&row_value("<b style='color:#b30000'>Old, pre-GPLv3 release (" . &html_escape($v) . ") - upstream license/download infra is offline</b>",
			&mini_form("upgrade_csf.cgi", &ui_submit("Upgrade to open-source v15.00", "upgrade"))));
	}

print &ui_table_row("CSF firewall auto-block hook",
	&row_value($csf_ok ? &status_cell($csf_hook_ok, "Hooked up", "CSF found, hook not installed")
	                    : "<i style='color:#888'>CSF not found on this server</i>",
		($csf_ok && !$csf_hook_ok) ? &mini_form("install_csf_hook.cgi", &ui_submit("Install", "install")) : "")
	. ($csf_ok && -d "/usr/share/webmin/csf" ? "<div style='margin-top:4px'><a href='../csf/'>Open CSF Firewall module &raquo;</a></div>" : ""));

my $status_widgets_ok = -e "/etc/webmin/status/services/openxs-watchd.serv";
if (-d "/etc/webmin/status") {
	print &ui_table_row("Servers Status dashboard widget",
		&row_value(&status_cell($status_widgets_ok, "Added - watchd/scand show on Webmin's main status page", "Not added"),
			$status_widgets_ok ? "" : &mini_form("install_status_widgets.cgi", &ui_submit("Add", "install"))));
	}

if ($csf_ok) {
	my $active_feeds = `grep -c '^[A-Z]' /etc/csf/csf.blocklists 2>/dev/null`;
	chomp($active_feeds);
	print &ui_table_row("IP reputation (CSF BLOCKLIST feeds)",
		&row_value("<b>" . ($active_feeds || 0) . "</b> feed(s) active - native CSF feature, not tied to any license",
			"<a href='edit_file.cgi?f=csf_blocklists'>Edit csf.blocklists &raquo;</a>"));
	}

print &ui_table_end();

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
