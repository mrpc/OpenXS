#!/usr/bin/perl
# settings.cgi
# OpenXS configuration - split out from the dashboard so status/health
# and "how it behaves" don't get mixed on the same page.

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
if (-d '/etc/modsecurity') {
	print &ui_table_row("mod_security path exclusions", "<a href='edit_file.cgi?f=modsec_exclusions'>Edit /etc/openxs/modsec_exclusions &raquo;</a> ".
		"<i>one path prefix per line (e.g. /admin) - fully disables ModSecurity/CRS for matching requests. ".
		"For a real false positive on a first-party endpoint (analytics beacon, already-authenticated admin area), not a general bypass.</i>");
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
print &ui_table_end();
print &ui_submit("Save", "save");
print &ui_form_end();

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
