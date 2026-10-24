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
foreach my $k ('watch_rate_count', 'watch_rate_window', 'watch_rate_cooldown') {
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
$cfg{'VERSION_SCAN_ENABLED'} = (defined($in{'version_scan_enabled'}) && $in{'version_scan_enabled'} eq '1') ? '1' : '0';
$cfg{'APT_SECURITY_ENABLED'} = (defined($in{'apt_security_enabled'}) && $in{'apt_security_enabled'} eq '1') ? '1' : '0';
$cfg{'SCAN_MAILBOXES'} = (defined($in{'scan_mailboxes'}) && $in{'scan_mailboxes'} eq '1') ? '1' : '0';
$cfg{'MAILBOX_RECENT_HOURS'} = &one_line($in{'mailbox_recent_hours'}) if (defined($in{'mailbox_recent_hours'}));
$cfg{'MAILBOX_RECENT_HOURS'} =~ s/[^0-9]//g if ($cfg{'MAILBOX_RECENT_HOURS'} ne '');
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
