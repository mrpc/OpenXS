#!/usr/bin/perl
# config.cgi
# Save settings (currently: alert e-mail address)

require './openxs-lib.pl';
&ReadParse();

# Strip newlines defensively - the config file is plain KEY=value lines,
# an embedded newline would let one form field inject a second bogus line.
sub one_line { my ($s) = @_; $s =~ s/[\r\n]//g; return $s; }

my %cfg = &openxs_read_config();
$cfg{'EMAIL'} = &one_line($in{'alert_addr'}) if (defined($in{'alert_addr'}) && $in{'alert_addr'} ne "");
$cfg{'SCAN_PATH'} = &one_line($in{'scan_path'}) if (defined($in{'scan_path'}) && $in{'scan_path'} ne "");
$cfg{'QUARANTINE_ENABLED'} = (defined($in{'quarantine_enabled'}) && $in{'quarantine_enabled'} eq '1') ? '1' : '0';
$cfg{'FAST_PHP_ONLY'} = (defined($in{'fast_php_only'}) && $in{'fast_php_only'} eq '1') ? '1' : '0';
$cfg{'QUIET'} = (defined($in{'quiet'}) && $in{'quiet'} eq '1') ? '1' : '0';
$cfg{'CHANGED_HOURS'} = &one_line($in{'changed_hours'}) if (defined($in{'changed_hours'}));
$cfg{'CHANGED_HOURS'} =~ s/[^0-9]//g if ($cfg{'CHANGED_HOURS'} ne '');
$cfg{'THROTTLE_LOAD'} = &one_line($in{'throttle_load'}) if (defined($in{'throttle_load'}));
$cfg{'THROTTLE_LOAD'} =~ s/[^0-9.]//g if ($cfg{'THROTTLE_LOAD'} ne '');
my @qcats;
push(@qcats, 'virus') if (defined($in{'qcat_virus'}) && $in{'qcat_virus'} eq '1');
push(@qcats, 'yara_exploit') if (defined($in{'qcat_yara_exploit'}) && $in{'qcat_yara_exploit'} eq '1');
push(@qcats, 'yara_heuristic') if (defined($in{'qcat_yara_heuristic'}) && $in{'qcat_yara_heuristic'} eq '1');
push(@qcats, 'maldet') if (defined($in{'qcat_maldet'}) && $in{'qcat_maldet'} eq '1');
push(@qcats, 'fs') if (defined($in{'qcat_fs'}) && $in{'qcat_fs'} eq '1');
$cfg{'QUARANTINE_CATEGORIES'} = join(',', @qcats);
$cfg{'WATCH_PATHS'} = &one_line($in{'watch_paths'}) if (defined($in{'watch_paths'}));
$cfg{'WATCH_EXCLUDE'} = &one_line($in{'watch_exclude'}) if (defined($in{'watch_exclude'}));
foreach my $k ('watch_rate_count', 'watch_rate_window', 'watch_rate_cooldown', 'watch_max_dirs') {
	if (defined($in{$k}) && $in{$k} ne "") {
		my $v = $in{$k};
		$v =~ s/[^0-9]//g;
		$cfg{uc($k)} = $v if ($v ne "");
		}
	}
$cfg{'SCAN_MODE'} = $in{'scan_mode'} eq 'accounts' ? 'accounts' : 'path';
$cfg{'ACCOUNTS_DIR'} = &one_line($in{'accounts_dir'}) if (defined($in{'accounts_dir'}) && $in{'accounts_dir'} ne "");
$cfg{'ACCOUNTS_SUBPATH'} = &one_line($in{'accounts_subpath'}) if (defined($in{'accounts_subpath'}));
if (defined($in{'watchd_max_rss_mb'}) && $in{'watchd_max_rss_mb'} ne "") {
	my $v = $in{'watchd_max_rss_mb'};
	$v =~ s/[^0-9]//g;
	$cfg{'WATCHD_MAX_RSS_MB'} = $v if ($v ne "");
	}
if (defined($in{'vmrss_max_mb'}) && $in{'vmrss_max_mb'} ne "") {
	my $v = $in{'vmrss_max_mb'};
	$v =~ s/[^0-9]//g;
	$cfg{'VMRSS_MAX_MB'} = $v if ($v ne "");
	}
if (defined($in{'yara_paranoia_level'}) && $in{'yara_paranoia_level'} =~ /^[123]$/) {
	$cfg{'YARA_PARANOIA_LEVEL'} = $in{'yara_paranoia_level'};
	}
foreach my $k ('composer_trust_min_age_days', 'composer_trust_min_downloads',
               'composer_trust_l2_min_age_days', 'composer_trust_l2_min_downloads') {
	if (defined($in{$k}) && $in{$k} ne "") {
		my $v = $in{$k};
		$v =~ s/[^0-9]//g;
		$cfg{uc($k)} = $v if ($v ne "");
		}
	}
$cfg{'VERSION_SCAN_ENABLED'} = (defined($in{'version_scan_enabled'}) && $in{'version_scan_enabled'} eq '1') ? '1' : '0';
$cfg{'DB_SCAN_ENABLED'} = (defined($in{'db_scan_enabled'}) && $in{'db_scan_enabled'} eq '1') ? '1' : '0';
$cfg{'APT_SECURITY_ENABLED'} = (defined($in{'apt_security_enabled'}) && $in{'apt_security_enabled'} eq '1') ? '1' : '0';
$cfg{'SCAN_MAILBOXES'} = (defined($in{'scan_mailboxes'}) && $in{'scan_mailboxes'} eq '1') ? '1' : '0';
$cfg{'MAILBOX_RECENT_HOURS'} = &one_line($in{'mailbox_recent_hours'}) if (defined($in{'mailbox_recent_hours'}));
$cfg{'MAILBOX_RECENT_HOURS'} =~ s/[^0-9]//g if ($cfg{'MAILBOX_RECENT_HOURS'} ne '');
if (defined($in{'csf_autoban_enabled'}) && $in{'csf_autoban_enabled'} eq '1' && !&openxs_remoteip_active()) {
	# The one hard guard this feature needs: a CSF ban is only ever
	# applied to an attribution IP that's already confirmed NOT a
	# Cloudflare edge address (csf_autoban.py's own safety net), but
	# without mod_remoteip active, every single site behind Cloudflare
	# on this server would simply never attribute anything (the
	# candidate IP in the access log IS Cloudflare's edge IP) - so the
	# feature would silently never do anything useful there, giving a
	# false sense that it's protecting those sites. Refuse to even
	# save the setting until that's fixed, rather than silently no-op.
	&openxs_result_page(
		"Not saved: mod_remoteip isn't active on this server yet. Enabling CSF auto-ban without it means any ".
		"site behind Cloudflare would never get a useful IP to ban (the watch daemon would only ever see ".
		"Cloudflare's own edge IP, which csf_autoban.py already refuses to ban) - install mod_remoteip in ".
		"Settings first, then come back and enable this.", 1, "Back to Settings", "settings.cgi");
	}
$cfg{'CSF_AUTOBAN_ENABLED'} = (defined($in{'csf_autoban_enabled'}) && $in{'csf_autoban_enabled'} eq '1') ? '1' : '0';
$cfg{'CSF_AUTOBAN_TTL'} = &one_line($in{'csf_autoban_ttl'}) if (defined($in{'csf_autoban_ttl'}) && $in{'csf_autoban_ttl'} ne '');

if (defined($in{'modsec_body_limit_ceiling'})) {
	my $v = $in{'modsec_body_limit_ceiling'};
	$v =~ s/[^0-9]//g;
	if ($v ne $cfg{'MODSEC_BODY_LIMIT_CEILING'}) {
		$cfg{'MODSEC_BODY_LIMIT_CEILING'} = $v;
		&openxs_write_config(%cfg);  # modsec_body_limit.py reads the ceiling from this file
		&openxs_apply_modsec_body_limit() if (&openxs_modsecurity_installed());
		}
	}

if ($cfg{'OPENXS_SRC'} ne '' && -d "$cfg{'OPENXS_SRC'}/.git") {
	$cfg{'AUTO_UPDATE'} = (defined($in{'auto_update'}) && $in{'auto_update'} eq '1') ? '1' : '0';
	my $cron_file = '/etc/cron.d/openxs-selfupdate';
	if ($cfg{'AUTO_UPDATE'} eq '1') {
		open(my $fh, '>', $cron_file);
		print $fh "# Weekly OpenXS self-update, enabled from the Webmin Settings page.\n";
		print $fh "17 3 * * 0 root cd $cfg{'OPENXS_SRC'} && git pull -q origin main && bash install.sh >> /var/log/openxs-selfupdate.log 2>&1\n";
		close($fh);
		}
	else {
		unlink($cron_file);
		}
	}
&openxs_write_config(%cfg);

if (defined($in{'schedule'}) && $in{'schedule'} ne "") {
	if (&openxs_write_schedule(&one_line($in{'schedule'}))) {
		$cfg{'SCHEDULE'} = &one_line($in{'schedule'});
		&openxs_write_config(%cfg);
		}
	else {
		&openxs_result_page(
			"Settings saved, but the schedule '" . $in{'schedule'} .
			"' is not valid cron syntax (5 space-separated fields) - schedule left unchanged.", 1);
		}
	}
elsif (defined($in{'schedule'})) {
	# Disable the scheduled scan entirely, cxs's --Wstop/--Wstart
	# equivalent for the cron-based scan (rather than just "no change",
	# which a blank field would otherwise mean).
	unlink('/etc/cron.d/openxs-scan');
	$cfg{'SCHEDULE'} = '';
	&openxs_write_config(%cfg);
	}

&openxs_result_page("Settings saved.", 0);
