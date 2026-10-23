#!/usr/bin/perl
# daemon.cgi
# Start / stop / restart the OpenXS daemons: the scan daemon (which=scand,
# default) used by the mod_security upload hook, or the watch daemon
# (which=watchd) that monitors whole directories via inotify. Both are
# managed entirely through their systemd units (enable+start / disable+
# stop) - one source of truth for "is it running" AND "will it survive a
# reboot". A previous version started them as a raw setsid process
# instead: running state and the unit's enabled/disabled state could then
# silently drift apart - found for real when a watchd started this way
# kept running fine, but systemctl still showed its unit disabled, so it
# would have silently not come back after the next reboot.

require './openxs-lib.pl';
&ReadParse();

my $which = $in{'which'} || 'scand';
my $label = $which eq 'watchd' ? 'Watch daemon' : 'Scan daemon';
my $unit = $which eq 'watchd' ? 'openxs-watchd' : 'openxs-scand';
my $log = $which eq 'watchd' ? $watchd_log : $daemon_log;

sub unit_active
{
my $out = `systemctl is-active $unit 2>/dev/null`;
chomp($out);
return $out eq 'active';
}

if (defined($in{'stop'}) || defined($in{'restart'})) {
	if (&unit_active()) {
		system('systemctl', 'disable', '--now', $unit);
		if (defined($in{'stop'}) && &unit_active()) {
			&openxs_result_page("$label did not stop.", 1);
			}
		}
	elsif (!defined($in{'start'}) && !defined($in{'restart'})) {
		&openxs_result_page("$label was not running.", 1);
		}
	}

if (defined($in{'start'}) || defined($in{'restart'})) {
	if (!&unit_active()) {
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
		system('systemctl', 'enable', '--now', $unit);
		sleep(1);
		if (!&unit_active()) {
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
