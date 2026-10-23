#!/usr/bin/perl
# disable_maldet_monitor.cgi
# Stops and disables maldet's own --monitor daemon (maldet.service) -
# offered specifically when starting openxs-watchd on a server where
# both would otherwise run two independent inotify watches over the
# same directories. OpenXS's own watchd still gets 100% of maldet's
# detection value via maldet_scan() in pmf_scan.py - this only removes
# the redundant second watcher, never maldet's signatures themselves.

require './openxs-lib.pl';
&ReadParse();

my $out = `systemctl stop maldet 2>&1; systemctl disable maldet 2>&1`;
my $still_active = &openxs_maldet_monitor_active();

&openxs_result_page(
	$still_active ? "Could not fully disable maldet's monitor - see details below." : "maldet's own monitor stopped and disabled.",
	$still_active, "Back to dashboard", "index.cgi", $out);
