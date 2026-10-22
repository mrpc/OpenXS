#!/usr/bin/perl
# update.cgi
# Update the php-malware-finder ruleset: either to our fork's latest commit
# (default, blank ref), or to a specific commit/tag/branch if given -
# reapplies our IsWhitelisted fix (idempotent), and reloads the running
# daemon without dropping its socket.

require './openxs-lib.pl';
&ReadParse();

my $ref = $in{'ruleset_ref'};
$ref =~ s/[^a-zA-Z0-9_.\-\/]//g;  # commit SHAs, tags and branch names only

if (!-d $pmf_dir) {
	&openxs_redirect_with_message("index.cgi", "$pmf_dir does not exist - detection engine not installed.", 1);
	}

my $before = &openxs_pmf_commit();
my $rc;
if ($ref ne "") {
	system("cd $pmf_dir && git fetch -q origin " . quotemeta($ref) . " 2>&1");
	$rc = system("cd $pmf_dir && git checkout -q FETCH_HEAD 2>&1") >> 8;
	}
else {
	$rc = system("cd $pmf_dir && git pull -q >/dev/null 2>&1") >> 8;
	}

if ($rc != 0) {
	&openxs_redirect_with_message("index.cgi",
		"Update failed (git exited $rc) - ruleset left at $before. Check network/git access on the server.", 1);
	}

# Idempotent: only add the fix if it's not already there
my $has_fix = `grep -c 'Misc or' $pmf_dir/whitelist.yar 2>/dev/null`;
chomp($has_fix);
if (!$has_fix) {
	system("sed -i 's/^        Misc\$/        Misc or\\n        Custom/' $pmf_dir/whitelist.yar");
	}
my $pid = &openxs_daemon_pid();
system("kill -HUP $pid") if ($pid);

my $after = &openxs_pmf_commit();
&openxs_redirect_with_message("index.cgi", "Ruleset updated: $before -> $after.", 0);
