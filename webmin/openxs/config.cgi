#!/usr/bin/perl
# config.cgi
# Save settings (currently: alert e-mail address)

require './openxs-lib.pl';
&ReadParse();

# Strip newlines defensively - the config file is plain KEY=value lines,
# an embedded newline would let one form field inject a second bogus line.
sub one_line { my ($s) = @_; $s =~ s/[\r\n]//g; return $s; }

my %cfg = &openxs_read_config();
$cfg{'EMAIL'} = &one_line($in{'email'}) if (defined($in{'email'}) && $in{'email'} ne "");
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
push(@qcats, 'yara') if (defined($in{'qcat_yara'}) && $in{'qcat_yara'} eq '1');
push(@qcats, 'fs') if (defined($in{'qcat_fs'}) && $in{'qcat_fs'} eq '1');
$cfg{'QUARANTINE_CATEGORIES'} = join(',', @qcats);
&openxs_write_config(%cfg);

if (defined($in{'schedule'}) && $in{'schedule'} ne "" && &openxs_write_schedule(&one_line($in{'schedule'}))) {
	$cfg{'SCHEDULE'} = &one_line($in{'schedule'});
	&openxs_write_config(%cfg);
	}

&redirect("index.cgi");
