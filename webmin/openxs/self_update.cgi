#!/usr/bin/perl
# self_update.cgi
# Updates OpenXS's own codebase (daemon, Webmin module, tools/ scripts) -
# not the php-malware-finder ruleset, that's update.cgi. action=check just
# compares commits; action=apply does 'git pull' + re-runs install.sh
# (the same idempotent upgrade path a human running it by hand would use).

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my %cfg = &openxs_read_config();
my $src = $cfg{'OPENXS_SRC'};

if ($src eq '' || !-d "$src/.git") {
	print &ui_alert_box("OPENXS_SRC is not set or isn't a git clone (" . &html_escape($src || '(blank)') .
		") - self-update isn't available on this install (it may predate this feature, or was installed " .
		"from a tarball rather than git clone). Re-running install.sh from a git clone sets this.", 'warn');
	}
elsif ($in{'action'} eq 'apply') {
	print &ui_subheading("Updating OpenXS...");
	print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:500px;overflow:auto'>";
	my $out = `cd $src && git pull -q origin main 2>&1 && bash install.sh 2>&1`;
	print &html_escape($out);
	print "</pre>";
	}
else {
	my $out = `python3 $src/tools/openxs_selfupdate.py $src 2>&1`;
	my ($cur, $latest, $behind) = ($out =~ /current=(\S+) latest=(\S+) behind=(\d+)/);
	if (!defined($cur)) {
		print &ui_alert_box("Could not check for updates (network issue, or git access to GitHub is blocked from this server). Raw output:<br><pre>" . &html_escape($out) . "</pre>", 'warn');
		}
	elsif ($behind == 0) {
		print &ui_alert_box("Up to date (commit $cur).", 'info');
		}
	else {
		print &ui_alert_box("$behind commit(s) behind - current: $cur, latest: $latest.", 'warn');
		print &ui_form_start("self_update.cgi", "post");
		print &ui_hidden("action", "apply");
		print &ui_submit("Update now", "update");
		print &ui_form_end();
		}
	}

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
