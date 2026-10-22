#!/usr/bin/perl
# daemon.cgi
# Start / stop / restart the OpenXS scan daemon

require './openxs-lib.pl';
&ReadParse();

my $pid = &openxs_daemon_pid();

if (defined($in{'stop'}) || defined($in{'restart'})) {
	if ($pid) {
		system("kill $pid");
		sleep(1);
		}
	}

if (defined($in{'start'}) || defined($in{'restart'})) {
	if (!&openxs_daemon_pid()) {
		system("nohup python3 $daemon_script >> $daemon_log 2>&1 &");
		sleep(1);
		}
	}

&redirect("index.cgi");
