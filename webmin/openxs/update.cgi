#!/usr/bin/perl
# update.cgi
# Pull the latest php-malware-finder ruleset, reapply our IsWhitelisted fix
# (idempotent), and reload the running daemon without dropping its socket.

require './openxs-lib.pl';
&ReadParse();

if (-d $pmf_dir) {
	system("cd $pmf_dir && git pull >/dev/null 2>&1");
	# Idempotent: only add the fix if it's not already there
	my $has_fix = `grep -c 'Misc or' $pmf_dir/whitelist.yar 2>/dev/null`;
	chomp($has_fix);
	if (!$has_fix) {
		system("sed -i 's/^        Misc\$/        Misc or\\n        Custom/' $pmf_dir/whitelist.yar");
		}
	my $pid = &openxs_daemon_pid();
	system("kill -HUP $pid") if ($pid);
	}

&redirect("index.cgi");
