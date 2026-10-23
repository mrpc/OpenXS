#!/usr/bin/perl
# daemon.cgi
# Start / stop / restart the OpenXS daemons: the scan daemon (which=scand,
# default) used by the mod_security upload hook, or the watch daemon
# (which=watchd) that monitors whole directories via inotify.

require './openxs-lib.pl';
&ReadParse();

my $which = $in{'which'} || 'scand';
my $label = $which eq 'watchd' ? 'Watch daemon' : 'Scan daemon';
my ($script, $log, $pid) = $which eq 'watchd'
	? ($watchd_script, $watchd_log, &openxs_watchd_pid())
	: ($daemon_script, $daemon_log, &openxs_daemon_pid());

if (defined($in{'stop'}) || defined($in{'restart'})) {
	if ($pid) {
		# Negative PID = whole process group. setsid made $pid its own
		# group leader, so this also kills child processes (e.g. the
		# watch daemon's inotifywait) instead of orphaning them.
		system("kill -- -$pid 2>/dev/null; kill $pid 2>/dev/null");
		sleep(1);
		if (defined($in{'stop'})) {
			my $still_there = $which eq 'watchd' ? &openxs_watchd_pid() : &openxs_daemon_pid();
			if ($still_there) {
				&openxs_result_page("$label did not stop (pid $still_there).", 1);
				}
			}
		}
	elsif (!defined($in{'start'}) && !defined($in{'restart'})) {
		&openxs_result_page("$label was not running.", 1);
		}
	}

if (defined($in{'start'}) || defined($in{'restart'})) {
	my $still_running = $which eq 'watchd' ? &openxs_watchd_pid() : &openxs_daemon_pid();
	if (!$still_running) {
		if ($which eq 'watchd') {
			my %cfg = &openxs_read_config();
			if (($cfg{'WATCH_PATHS'} || '') eq '') {
				# Empty WATCH_PATHS falls back to every account's web root
				# (see openxs-watchd.py) - only block starting if that
				# fallback also has nothing to watch.
				my $accounts_dir = $cfg{'ACCOUNTS_DIR'} || '/home';
				my $subpath = $cfg{'ACCOUNTS_SUBPATH'};
				my @accounts = $subpath ne '' ? glob("$accounts_dir/*/$subpath") : glob("$accounts_dir/*");
				if (!grep { -d $_ } @accounts) {
					&openxs_result_page(
						"No 'Watch paths' set, and no accounts found under $accounts_dir - " .
						"set one of these in Settings before starting the watch daemon.", 1);
					}
				}
			}
		# setsid detaches into a new session/process group so the
		# daemon survives past this CGI request's own lifetime.
		system("setsid python3 $script >> $log 2>&1 < /dev/null &");
		sleep(1);
		my $now_running = $which eq 'watchd' ? &openxs_watchd_pid() : &openxs_daemon_pid();
		if (!$now_running) {
			&openxs_result_page(
				"$label did not start.", 1, undef, undef, &openxs_tail($log));
			}
		if ($which eq 'watchd' && &openxs_maldet_monitor_active()) {
			&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
			print $openxs_nav;
			print "<div style='background:#eaf6ec;color:#2e7d32;border:1px solid #2e7d32;border-radius:4px;".
				"padding:12px;font-weight:bold;margin:12px 0'>Watch daemon started.</div>\n";
			print "<div style='background:#fff8e1;color:#8a6500;border:1px solid #e6c200;border-radius:4px;".
				"padding:12px;margin:12px 0'>maldet's own <code>--monitor</code> daemon is also running on ".
				"this server - both now watch the same directories independently (double inotify watches, ".
				"double work per file change). OpenXS's watchd already gets 100% of maldet's detection value ".
				"via its own integration, so maldet's separate monitor is redundant here.<br>" .
				&ui_form_start("disable_maldet_monitor.cgi", "post") . &ui_submit("Disable maldet's monitor", "go") . &ui_form_end() .
				"</div>\n";
			print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
			&ui_print_footer("/", "Webmin index page");
			exit;
			}
		}
	}

&openxs_result_page("$label updated.", 0);
