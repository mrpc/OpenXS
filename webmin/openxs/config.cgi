#!/usr/bin/perl
# config.cgi
# Save settings (currently: alert e-mail address)

require './openxs-lib.pl';
&ReadParse();

my %cfg = &openxs_read_config();
$cfg{'EMAIL'} = $in{'email'} if (defined($in{'email'}) && $in{'email'} ne "");
$cfg{'SCAN_PATH'} = $in{'scan_path'} if (defined($in{'scan_path'}) && $in{'scan_path'} ne "");
$cfg{'QUARANTINE_ENABLED'} = (defined($in{'quarantine_enabled'}) && $in{'quarantine_enabled'} eq '1') ? '1' : '0';
&openxs_write_config(%cfg);

&redirect("index.cgi");
