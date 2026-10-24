#!/usr/bin/perl
# index.cgi
# OpenXS dashboard: what's running right now (daemons, scans, quarantine,
# FIM, version checks), a manual scan trigger, and links to logs - the
# day-to-day view. Component installs/updates/on-off toggles (detection
# engine, ClamAV, maldet, mod_security, CSF) live on settings.cgi instead,
# so a component someone deliberately turned off doesn't keep surfacing
# itself here every time they look.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $pid = &openxs_daemon_pid();
my $watchd_pid = &openxs_watchd_pid();
my $scan_pid = &openxs_scan_pid();
my %cfg_early = &openxs_read_config();

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

print "<div style='display:flex;gap:16px;margin:16px 0;flex-wrap:wrap'>" .
	&openxs_resource_widget("scand", "Scan daemon", $pid, 1024) .
	&openxs_resource_widget("watchd", "Watch daemon", $watchd_pid, $cfg_early{'WATCHD_MAX_RSS_MB'}) .
	&openxs_resource_widget("scan", "Manual/scheduled scan", $scan_pid, $cfg_early{'VMRSS_MAX_MB'}, "scanlog") .
	"</div>";

# Auto-refresh the widget numbers every few seconds without a full page
# reload (Webmin's authentic theme has a known, separate quirk where any
# real page refresh drops back to the dashboard - this polls quietly in
# the background instead, same origin, no auth prompt).
print <<'JSEOF';
<script>
(function() {
	function paint(key, d) {
		var w = document.getElementById('widget-' + key);
		if (!w) return;
		if (!d || !d.pid) {
			w.style.background = '#f5f5f5'; w.style.borderColor = '#ddd';
			var rss = document.getElementById('rss-' + key);
			if (rss) rss.outerHTML = "<div style='font-size:22px;color:#888'>Not running</div>";
			return;
			}
		var limit = parseFloat(w.getAttribute('data-limit-mb')) || 0;
		var pct = limit ? (d.rss_mb / limit * 100) : 0;
		var color = pct >= 90 ? '#b30000' : (pct >= 50 ? '#b38f00' : '#2e7d32');
		w.style.background = '#fff'; w.style.borderColor = color;
		var pidEl = document.getElementById('pid-' + key);
		if (pidEl) pidEl.textContent = d.pid;
		var rssEl = document.getElementById('rss-' + key);
		if (rssEl) rssEl.innerHTML = d.rss_mb + "<span style='font-size:16px'>MB</span>";
		if (rssEl) rssEl.style.color = color;
		var cpuEl = document.getElementById('cpu-' + key);
		if (cpuEl) cpuEl.innerHTML = d.cpu + "<span style='font-size:14px'>%</span>";
		}
	function paintScanProgress(scan, progress) {
		var extra = document.getElementById('extra-scan');
		if (!extra) return;
		if (!scan || !scan.pid) { extra.textContent = ''; return; }
		var mins = Math.floor(scan.etimes / 60), secs = scan.etimes % 60;
		var msg = 'running ' + mins + 'm ' + secs + 's';
		if (progress) {
			msg += ' - stage ' + progress.stage_num + '/' + progress.stage_count + ' (' + progress.stage + ')';
			if (progress.pct !== undefined) msg += ': ~' + progress.pct + '% (' + progress.done + '/' + progress.total + ')';
			}
		extra.textContent = msg;
		}
	function tick() {
		fetch('daemon_stats.cgi', {credentials: 'same-origin'})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				paint('scand', d.scand); paint('watchd', d.watchd); paint('scan', d.scan);
				paintScanProgress(d.scan, d.scan_progress);
				})
			.catch(function() {});
		}
	tick();
	setInterval(tick, 4000);
	})();
</script>
JSEOF

print &ui_subheading("Status");
print &ui_table_start(undef, undef, 1);

print &ui_table_row("Scan daemon (openxs-scand, shared YARA engine - powers the upload hook + watch daemon)",
	&row_value($pid ? &status_cell(1, "Running (pid $pid)" . &openxs_proc_stats($pid), "") : &status_cell(0, "", "Not running"),
		&mini_form("daemon.cgi",
			&ui_hidden("which", "scand") .
			&ui_submit("Start", "start") . &ui_submit("Stop", "stop") . &ui_submit("Restart", "restart"))));

print &ui_table_row("Watch daemon (openxs-watchd, account-wide inotify monitor) <i>early/evolving</i>",
	&row_value($watchd_pid ? &status_cell(1, "Running (pid $watchd_pid)" . &openxs_proc_stats($watchd_pid), "")
	           : (($cfg_early{'WATCH_PATHS'} || '') eq '' ? "<i style='color:#888'>Not running - set 'Watch paths' below first</i>"
	                                                       : &status_cell(0, "", "Not running")),
		&mini_form("daemon.cgi",
			&ui_hidden("which", "watchd") .
			&ui_submit("Start", "start") . &ui_submit("Stop", "stop") . &ui_submit("Restart", "restart"))));

my $full_status = &openxs_full_status();
if ($full_status) {
	my $ls = $full_status->{'last_scan'};
	my $ls_text = $ls && $ls->{'ran'} ? &html_escape($ls->{'summary'}) . " <i>(" . &make_date($ls->{'at'}, 1) . ")</i>"
	                                  : "<i style='color:#888'>Never ran yet</i>";
	print &ui_table_row("Last scheduled/manual scan", &row_value($ls_text, ""));
	print &ui_table_row("Quarantined files",
		&row_value($full_status->{'quarantine_count'}, "<a href='reports.cgi?view=quarantine'>View quarantine &raquo;</a>"));

	my $fi = $full_status->{'fim'};
	my $fi_text = !$fi->{'baselined'} ? "<i style='color:#888'>No baseline yet - add paths in Settings, then run 'Baseline now' below</i>"
	            : $fi->{'summary'} ? &html_escape($fi->{'summary'}) . ($fi->{'checked_at'} ? " <i>(" . &make_date($fi->{'checked_at'}, 1) . ")</i>" : "")
	            : "<i style='color:#888'>Baselined, not checked yet (runs with the next scheduled scan)</i>";
	print &ui_table_row("File integrity monitoring",
		&row_value($fi_text,
			&mini_form("fim.cgi", &ui_hidden("action", "baseline") . &ui_submit("Baseline now", "go")) .
			($fi->{'baselined'} ? &mini_form("fim.cgi", &ui_hidden("action", "check") . &ui_submit("Check now", "go")) : "")));

	# version_scan.py/apt_security_check.py both make live network calls
	# (Packagist/WordPress.org/apt-get update) - too slow for an on-demand
	# dashboard button (a full composer check across many sites can take
	# minutes), so these are summary-only here: last result from the
	# daily scheduled scan, same as the whitelist drift check.
	my $vs = $full_status->{'version_scan'};
	my $vs_text = !$vs->{'ran'} ? "<i style='color:#888'>Runs with the next scheduled scan</i>"
	            : &html_escape($vs->{'summary'}) . " <i>(" . &make_date($vs->{'at'}, 1) . ")</i>";
	print &ui_table_row("WordPress / composer package versions", &row_value($vs_text, ""));

	my $aps = $full_status->{'apt_security'};
	my $aps_text = !$aps->{'ran'} ? "<i style='color:#888'>Runs with the next scheduled scan</i>"
	             : &html_escape($aps->{'summary'}) . " <i>(" . &make_date($aps->{'at'}, 1) . ")</i>";
	print &ui_table_row("Pending apt security updates", &row_value($aps_text, ""));

	my $mb = $full_status->{'mailbox_scan'};
	my $mb_text = !$mb->{'ran'} ? "<i style='color:#888'>Off by default - enable in Settings (cxs's 'virusscan')</i>"
	            : &html_escape($mb->{'summary'}) . " <i>(" . &make_date($mb->{'at'}, 1) . ")</i>";
	print &ui_table_row("Mailbox virus scan", &row_value($mb_text, "<a href='settings.cgi'>Settings &raquo;</a>"));
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
print &ui_table_row("Directory to scan", &ui_textbox("path", $cfg{'SCAN_PATH'} || '/var/www', 50));
print &ui_table_row("...or every account", &ui_checkbox("accounts", "1",
	"Scan all accounts under '" . &html_escape($cfg{'ACCOUNTS_DIR'}) . "/*/" . &html_escape($cfg{'ACCOUNTS_SUBPATH'}) .
	"' instead (ignores 'Directory to scan' above) - see <a href='settings.cgi'>Settings</a> to change the accounts directory.",
	$cfg{'SCAN_MODE'} eq 'accounts'));
print &ui_table_end();
print &ui_submit("Scan now", "scan");
print &ui_form_end();

print &ui_subheading("Support");
print "<p><a href='support.cgi'>Install Information</a> <i>(diagnostic dump, for troubleshooting)</i></p>\n";
print "<p><a href='false_positive_export.cgi'>Export false positive reports</a> <i>(every \"Mark false positive\" click, ".
	"as Markdown - paste into a GitHub issue to help improve detection rules)</i></p>\n";

print &ui_subheading("Danger zone");
print &ui_form_start("disable_ui.cgi", "post");
print "<p>" . &ui_submit("Disable this UI completely", "disable") .
	" <i>Cannot be undone from the UI itself - remove <code>$ui_disabled_file</code> on the server to re-enable.</i></p>\n";
print &ui_form_end();

print "<p style='text-align:center;color:#888;margin-top:2em'>&copy; 2026 OpenXS - ".
	"<a href='https://github.com/mrpc/OpenXS' target='_blank'>github.com/mrpc/OpenXS</a></p>\n";

&ui_print_footer("/", "Webmin index page");
