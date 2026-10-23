#!/usr/bin/perl
# index.cgi
# OpenXS dashboard: component status, daemon control, manual scan.
# Configuration lives on its own page - see settings.cgi.

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
	                      : "<i style='color:#888'>Not installed - ran without it (optional, degrades gracefully)</i>",
		&mini_form("install_clamav.cgi",
			&ui_submit($clamav_ok ? "Re-apply recommended config" : "Install", "install"))));

my $maldet_ok = &openxs_maldet_installed();
print &ui_table_row("maldet (Linux Malware Detect, 3rd detector)",
	&row_value($maldet_ok ? &status_cell(1, "Installed - own MD5/HEX/YARA signature set", "")
	                      : "<i style='color:#888'>Not installed - ran without it (optional, degrades gracefully)</i>",
		&mini_form("install_maldet.cgi",
			&ui_submit($maldet_ok ? "Re-apply recommended config" : "Install", "install"))));

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

my $full_status = &openxs_full_status();
if ($full_status) {
	my $ls = $full_status->{'last_scan'};
	my $ls_text = $ls && $ls->{'ran'} ? &html_escape($ls->{'summary'}) . " <i>(" . &make_date($ls->{'at'}, 1) . ")</i>"
	                                  : "<i style='color:#888'>Never ran yet</i>";
	print &ui_table_row("Last scheduled/manual scan", &row_value($ls_text, ""));
	print &ui_table_row("Quarantined files",
		&row_value($full_status->{'quarantine_count'}, "<a href='reports.cgi?view=quarantine'>View quarantine &raquo;</a>"));
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
	"' instead (ignores 'Directory to scan' above) - see <a href='settings.cgi'>Settings</a> to change the accounts directory.", 0));
print &ui_table_end();
print &ui_submit("Scan now", "scan");
print &ui_form_end();

print &ui_subheading("Support");
print "<p><a href='support.cgi'>Install Information</a> <i>(diagnostic dump, for troubleshooting)</i></p>\n";

print &ui_subheading("Danger zone");
print &ui_form_start("disable_ui.cgi", "post");
print "<p>" . &ui_submit("Disable this UI completely", "disable") .
	" <i>Cannot be undone from the UI itself - remove <code>$ui_disabled_file</code> on the server to re-enable.</i></p>\n";
print &ui_form_end();

print "<p style='text-align:center;color:#888;margin-top:2em'>&copy; 2026 OpenXS - ".
	"<a href='https://github.com/mrpc/OpenXS' target='_blank'>github.com/mrpc/OpenXS</a></p>\n";

&ui_print_footer("/", "Webmin index page");
