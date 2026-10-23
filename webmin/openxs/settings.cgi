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
print &ui_table_end();
print &ui_submit("Save", "save");
print &ui_form_end();

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
