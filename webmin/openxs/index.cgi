#!/usr/bin/perl
# index.cgi
# OpenXS status/control page

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $pid = &openxs_daemon_pid();
my $has_socket = &openxs_socket_exists();

print &ui_subheading("Scan daemon");
print &ui_table_start(undef, undef, 2);
if ($pid) {
	print &ui_table_row("Status", "<b style='color:green'>Running</b> (pid $pid)");
	} else {
	print &ui_table_row("Status", "<b style='color:red'>Not running</b>");
	}
print &ui_table_row("Socket", $has_socket ? "<code>$socket_path</code> (present)"
					  : "<i>missing</i>");
print &ui_table_row("Ruleset", "<code>$ruleset</code>");
print &ui_table_end();

print &ui_form_start("daemon.cgi", "post");
print &ui_submit("Start", "start");
print &ui_submit("Stop", "stop");
print &ui_submit("Restart", "restart");
print &ui_form_end();

print &ui_subheading("Daemon log (last 30 lines)");
my @log = -e $daemon_log ? `tail -30 $daemon_log 2>/dev/null` : ();
print "<pre style='background:#f4f4f4;padding:8px;max-height:300px;overflow:auto'>";
print @log ? join("", map { &html_escape($_) } @log) : "(no log yet)";
print "</pre>";

print &ui_subheading("Run a manual scan");
print &ui_form_start("scan.cgi", "post");
print &ui_table_start(undef, undef, 2);
print &ui_table_row("Directory to scan", &ui_textbox("path", "/var/www", 50));
print &ui_table_end();
print &ui_submit("Scan now", "scan");
print &ui_form_end();

&ui_print_footer("/", "Webmin index page");
