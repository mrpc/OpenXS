#!/usr/bin/perl
# support.cgi
# cxs's "--test" / "Install Information" equivalent: a single diagnostic
# dump useful for troubleshooting, without having to SSH in and run a
# dozen separate commands.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my @info;
push(@info, "=== OpenXS ===");
push(@info, "Detection engine: " . (&openxs_pmf_installed() ? "installed (" . &openxs_pmf_commit() . ")" : "NOT installed"));
push(@info, "Scan daemon: " . (&openxs_daemon_pid() ? "running (pid " . &openxs_daemon_pid() . ")" : "not running"));
push(@info, "Daemon socket: " . (&openxs_socket_exists() ? "present ($socket_path)" : "missing"));
push(@info, "mod_security: " . (&openxs_modsecurity_installed() ? "installed" : "not installed") .
	", hook: " . (&openxs_modsecurity_hook_installed() ? "installed" : "not installed"));
push(@info, "CSF: " . (&openxs_csf_present() ? "present" : "not present") .
	", auto-block hook: " . (&openxs_csf_hook_installed() ? "installed" : "not installed"));
push(@info, "ClamAV: " . (&openxs_clamav_installed() ? "installed" : "not installed") .
	", running: " . (&openxs_clamav_running() ? "yes" : "no"));
push(@info, "");
push(@info, "=== Config (/etc/openxs/openxs.conf) ===");
my %cfg = &openxs_read_config();
foreach my $k (sort keys %cfg) {
	push(@info, "$k=$cfg{$k}");
	}
push(@info, "");
push(@info, "=== Cron ===");
push(@info, -e '/etc/cron.d/openxs-scan' ? `cat /etc/cron.d/openxs-scan 2>&1` : "(no scheduled scan - disabled)");
push(@info, "=== Recent scans ===");
push(@info, `python3 -c "
import sqlite3, datetime
try:
    conn = sqlite3.connect('/var/lib/openxs/openxs.db')
    for row in conn.execute('select id, started_at, path, files_scanned, hits from scans order by id desc limit 10'):
        print(row[0], datetime.datetime.fromtimestamp(row[1]), row[2], row[3], row[4])
except Exception as e:
    print('(no scan history yet:', e, ')')
" 2>&1`);
push(@info, "=== Versions ===");
push(@info, "python3: " . `python3 --version 2>&1`);
push(@info, "yara: " . `python3 -c 'import yara; print(yara.__version__)' 2>&1`);
push(@info, "clamdscan: " . `clamdscan --version 2>&1`);

print &ui_subheading("Install Information");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:500px;overflow:auto'>";
print &html_escape(join("\n", @info));
print "</pre>";

print "<p><a href='index.cgi'>&laquo; Back</a></p>\n";
&ui_print_footer("/", "Webmin index page");
