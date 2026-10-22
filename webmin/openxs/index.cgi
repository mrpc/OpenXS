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

print &ui_subheading("Components");
print &ui_table_start(undef, undef, 3);

print &ui_table_row("Detection engine (php-malware-finder)",
	&status_cell($pmf_ok, "Installed (" . &openxs_pmf_commit() . ")", "Not installed"),
	$pmf_ok ? &mini_form("update.cgi", &ui_submit("Update now", "update"))
	        : "<i>installed as part of the base image</i>");

print &ui_table_row("Scan daemon (openxs-scand)",
	$pid ? &status_cell(1, "Running (pid $pid)", "") : &status_cell(0, "", "Not running"),
	&mini_form("daemon.cgi",
		&ui_submit("Start", "start") . &ui_submit("Stop", "stop") . &ui_submit("Restart", "restart")));

print &ui_table_row("mod_security (real-time upload blocking)",
	&status_cell($modsec_ok && $modsec_hook_ok, "Installed and hooked up", "Not installed"),
	($modsec_ok && $modsec_hook_ok) ? ""
	  : &mini_form("install_modsecurity.cgi", &ui_submit("Install", "install")));

print &ui_table_row("CSF firewall auto-block hook",
	$csf_ok ? &status_cell($csf_hook_ok, "Hooked up", "CSF found, hook not installed")
	        : "<i style='color:#888'>CSF not found on this server</i>",
	($csf_ok && !$csf_hook_ok) ? &mini_form("install_csf_hook.cgi", &ui_submit("Install", "install")) : "");

print &ui_table_end();

print &ui_subheading("Daemon log (last 30 lines)");
my @log = -e $daemon_log ? `tail -30 $daemon_log 2>/dev/null` : ();
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:300px;overflow:auto'>";
print @log ? join("", map { &html_escape($_) } @log) : "(no log yet)";
print "</pre>";

print "<p><a href='reports.cgi'>View scan history &raquo;</a></p>\n";

print &ui_subheading("Run a manual scan");
print &ui_form_start("scan.cgi", "post");
print &ui_table_start(undef, undef, 2);
print &ui_table_row("Directory to scan", &ui_textbox("path", "/var/www", 50));
print &ui_table_end();
print &ui_submit("Scan now", "scan");
print &ui_form_end();

print &ui_subheading("Settings");
my %cfg = &openxs_read_config();
print &ui_form_start("config.cgi", "post");
print &ui_table_start(undef, undef, 2);
print &ui_table_row("Alert e-mail address", &ui_textbox("email", $cfg{'EMAIL'}, 40));
print &ui_table_row("Directory scanned by the daily cron job", &ui_textbox("scan_path", $cfg{'SCAN_PATH'}, 40));
print &ui_table_end();
print &ui_submit("Save", "save");
print &ui_form_end();

&ui_print_footer("/", "Webmin index page");
