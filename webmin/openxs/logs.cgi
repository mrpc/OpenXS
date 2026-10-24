#!/usr/bin/perl
# logs.cgi
# All OpenXS log files in one place, instead of "check the log on the server".

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;

my %logs = (
	"scand" => ["Scan daemon (openxs-scand)", $daemon_log],
	"watchd" => ["Watch daemon (openxs-watchd)", $watchd_log],
	"cron" => ["Scheduled scan (cron)", "$pmf_dir/cron.log"],
	"scanlog" => ["Scheduled scan - scanner's own stderr", "$pmf_dir/scan.log"],
	"quarantine" => ["Quarantine actions", "/var/log/openxs-quarantine.log"],
	"fim" => ["File integrity - last check", "$pmf_dir/fim_results.txt"],
);

my $only = $in{'only'};

if ($only ne '' && $logs{$only}) {
	# Single-log view, with its own independent "show more" control -
	# no more ambiguity about which log a "show more lines" link applied to.
	my $n = $in{'lines'};
	$n =~ s/[^0-9]//g;
	$n = 200 if ($n eq '' || $n < 1);

	my ($title, $file) = @{$logs{$only}};
	print &ui_subheading("$title <small>(<code>$file</code>)</small> ".
		"<button id='live-pause' type='button' class='btn btn-default' style='font-size:12px;padding:1px 8px;margin-left:8px'>Pause</button> ".
		"<span id='live-indicator' style='font-size:12px;color:#888'>(live)</span>");
	if ($only eq 'scanlog') {
		# This is pmf_scan.py's own stderr - the one log where a
		# completion percentage actually means something.
		print "<div id='scan-progress-bar-wrap' style='display:none;margin-bottom:8px'>".
			"<div id='scan-overall-bar-wrap' style='display:none;margin-bottom:4px'>".
			"<div style='background:#ddd;border-radius:4px;height:10px;overflow:hidden'>".
			"<div id='scan-overall-bar' style='background:#6b8fc2;height:100%;width:0%;transition:width 1s'></div></div>".
			"<div id='scan-overall-label' style='font-size:11px;color:#888;margin-top:1px'></div></div>".
			"<div style='background:#ddd;border-radius:4px;height:18px;overflow:hidden'>".
			"<div id='scan-progress-bar' style='background:#2e7d32;height:100%;width:0%;transition:width 1s'></div></div>".
			"<div id='scan-progress-label' style='font-size:12px;color:#666;margin-top:2px'></div></div>\n";
		}
	print "<pre id='live-tail' style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:600px;overflow:auto'>".
		&html_escape(&openxs_tail($file, $n))."</pre>\n";
	print "<p><a href='logs.cgi?only=$only&lines=" . ($n * 5) . "'>Show more lines (last $n shown)</a></p>\n";
	print "<p><a href='logs.cgi'>&laquo; Back to all logs</a></p>\n";
	print <<JSEOF;
<script>
(function() {
	var pre = document.getElementById('live-tail');
	var indicator = document.getElementById('live-indicator');
	var pauseBtn = document.getElementById('live-pause');
	var progressWrap = document.getElementById('scan-progress-bar-wrap');
	var progressBar = document.getElementById('scan-progress-bar');
	var progressLabel = document.getElementById('scan-progress-label');
	var overallWrap = document.getElementById('scan-overall-bar-wrap');
	var overallBar = document.getElementById('scan-overall-bar');
	var overallLabel = document.getElementById('scan-overall-label');
	var timer = null;
	var paused = false;
	function tickProgress() {
		if (!progressWrap) return;
		fetch('daemon_stats.cgi', {credentials: 'same-origin'})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				if (!d.scan || !d.scan.pid || !d.scan_progress) { progressWrap.style.display = 'none'; return; }
				var p = d.scan_progress;
				progressWrap.style.display = '';
				// No per-file pct for clamav/maldet/fs - without this, the
				// bar fell back to 0% on every one of them, looking
				// identical (empty) whether in stage 1 or stage 4. Treat
				// each stage as an equal slice of the whole bar instead,
				// so it visibly fills up as stages pass even without
				// intra-stage granularity.
				var stagePct = ((p.stage_num - 1) + (p.pct !== undefined ? p.pct / 100 : 0.5)) / p.stage_count * 100;
				progressBar.style.width = stagePct + '%';
				progressLabel.textContent = 'Stage ' + p.stage_num + '/' + p.stage_count + ' (' + p.stage + ')' +
					(p.pct !== undefined ? ': ~' + p.pct + '% done (' + p.done + ' of ' + p.total + ' files)' : '');
				if (p.overall_pct_from_history !== undefined) {
					overallWrap.style.display = '';
					var hp = Math.min(99, p.overall_pct_from_history);
					overallBar.style.width = hp + '%';
					overallLabel.textContent = 'Overall (vs past full scans): ~' + hp + '%';
					} else {
					overallWrap.style.display = 'none';
					}
				})
			.catch(function() {});
		}
	function tick() {
		fetch('tail_text.cgi?file=$only&lines=$n', {credentials: 'same-origin'})
			.then(function(r) { return r.text(); })
			.then(function(t) {
				pre.textContent = t;
				pre.scrollTop = pre.scrollHeight;
				indicator.textContent = '(live - updated ' + new Date().toLocaleTimeString() + ')';
				})
			.catch(function() { indicator.textContent = '(live - last update failed)'; });
		tickProgress();
		}
	function start() { timer = setInterval(tick, 4000); }
	function stop() { clearInterval(timer); timer = null; }
	pauseBtn.addEventListener('click', function() {
		paused = !paused;
		if (paused) { stop(); pauseBtn.textContent = 'Resume'; indicator.textContent = '(paused)'; }
		else { start(); pauseBtn.textContent = 'Pause'; tick(); }
		});
	tick();
	start();
	})();
</script>
JSEOF
	}
else {
	my $preview_lines = 10;
	foreach my $key (sort keys %logs) {
		my ($title, $file) = @{$logs{$key}};
		print &ui_subheading("$title <small>(<code>$file</code>)</small>");
		print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:300px;overflow:auto'>".
			&html_escape(&openxs_tail($file, $preview_lines))."</pre>\n";
		print "<p><a href='logs.cgi?only=$key'>View full log &raquo;</a></p>\n";
		}

	if (-d '/etc/modsecurity') {
		my $cache_age = &openxs_modsec_cache_age();
		my $age_note = defined($cache_age) ? "updated " . int($cache_age / 60) . "m ago" : "live (no cache yet)";
		print &ui_subheading("mod_security blocks <small>(across every Apache error log on this server - $age_note)</small>");
		my @rows = &openxs_modsec_rows();
		if (!@rows) {
			print "<p>(no blocks found)</p>\n";
			}
		else {
			my $n = $in{'lines'};
			$n =~ s/[^0-9]//g;
			$n = 100 if ($n eq '' || $n < 1);
			my $last = $#rows > $n - 1 ? $n - 1 : $#rows;
			my $excluded_rules = &openxs_modsec_excluded_rule_ids();
			my $excluded_path_prefixes = &openxs_modsec_excluded_path_prefixes();
			print &ui_columns_start(["Count", "Host", "Path", "Rule", "Quick exclude"]);
			foreach my $r (@rows[0 .. $last]) {
				print &ui_columns_row([$r->{'count'}, &html_escape($r->{'host'}), &html_escape($r->{'uri'}),
					&openxs_modsec_rule_link($r->{'rule_id'}),
					&openxs_modsec_quick_exclude_links($r->{'rule_id'}, $r->{'uri'}, $excluded_rules, $excluded_path_prefixes)]);
				}
			print &ui_columns_end();
			print "<p><a href='logs.cgi?lines=" . ($n * 5) . "'>Show more mod_security rows (last $n shown)</a></p>\n";
			}
		print "<p><a href='modsec_log.cgi'>Full view with grouping notes &raquo;</a></p>\n";
		}
	}

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
