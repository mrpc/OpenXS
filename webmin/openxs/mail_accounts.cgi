#!/usr/bin/perl
# mail_accounts.cgi
# SMTP/SASL account activity and blocks, from sasl_watch.py: blocked
# accounts (unblock / temporary unblock), the last 24h of authenticated
# sending per account (with a manual Block), the login names most
# targeted by failed AUTH, and milter health. Reads the report the
# collector cron writes every 5 minutes - never parses mail.log itself.

use JSON::PP;
require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;

my %cfg = &openxs_read_config();
my $report_file = '/var/lib/openxs/sasl_watch_report.json';
my $r = {};
if (open(my $fh, '<', $report_file)) {
	local $/;
	$r = eval { decode_json(<$fh>) } || {};
	close($fh);
	}
sub fmt_ts { my ($t) = @_; return $t ? &make_date(int($t)) : ''; }
sub mx_h { return &html_escape($_[0]); }

print &ui_subheading("Mail accounts");
my $mode = $cfg{'SASL_WATCH_AUTOBLOCK'} eq '1'
	? "<b style='color:#2e7d32'>auto-block ON</b>" : "<b>alert only</b> (auto-block off)";
print "<p>$mode - alert when an account logs in from more than <b>" . &mx_h($cfg{'SASL_WATCH_MAX_IPS'}) .
	"</b> IPs in 24h, sends more than <b>" . &mx_h($cfg{'SASL_WATCH_MAX_MSGS_PER_HOUR'}) .
	"</b> messages in an hour, or more than <b>" . &mx_h($cfg{'SASL_WATCH_MAX_BOUNCE_PCT'}) .
	"%</b> of its mail bounces. IPs of <code>" . &mx_h($cfg{'SASL_WATCH_EXEMPT_HOSTS'}) . "</code> don't count. " .
	"<a href='settings.cgi'>Change in Settings</a>.<br>" .
	($r->{'generated'} ? "Data as of " . &fmt_ts($r->{'generated'}) . " (refreshed every 5 minutes)."
	                   : "<b>No data yet</b> - the collector cron writes it every 5 minutes.") . "</p>\n";

# Milters
my @milters = grep { $_ ne '' } split(/[\s,]+/, `postconf -h smtpd_milters 2>/dev/null`);
my %dead = %{$r->{'milters'} || {}};
if (%dead) {
	foreach my $m (sort keys %dead) {
		print "<div style='background:#fdecea;color:#b30000;border:1px solid #b30000;border-radius:4px;padding:8px;margin:6px 0'>" .
			"Milter <b>" . &mx_h($m) . "</b> refused connections (last at " . &fmt_ts($dead{$m}) . ") - " .
			"whatever it enforces (rate limits, greylisting, DKIM) is not applied while it's down.</div>\n";
		}
	}
print "<p>Milters (smtpd_milters): " . (@milters ? join(", ", map { "<code>" . &mx_h($_) . "</code>" } @milters) : "none") .
	(%dead ? "" : " - none refused a connection in the last hour.") . "</p>\n";

# Forwarded spam rejected as unauthenticated (Gmail 550 5.7.26 on orig_to= lines)
my $fwd = $r->{'fwd_unauth_rejected'} || {};
if ($fwd->{'count'}) {
	my $top = join(", ", map { "<code>" . &mx_h($_->[0]) . "</code> (" . int($_->[1]) . ")" } @{$fwd->{'top'} || []});
	my $fix = &foreign_available("virtualmin-authfwd")
		? "Set it up per mailbox in <a href='../virtualmin-authfwd/index.cgi'>Authenticated forwarding</a>."
		: $authfwd_repo_url
		? "<a href='" . &mx_h($authfwd_repo_url) . "' target='_blank'>virtualmin-authfwd</a> forwards only DKIM-pass or local mail and stops this."
		: "Forward only authenticated (DKIM-pass) mail, or stop forwarding those mailboxes.";
	print "<div style='background:#fff4e5;border:1px solid #e0a800;border-radius:4px;padding:8px;margin:6px 0'>" .
		"<b>Forwarded spam is being rejected as unauthenticated</b>: <b>" . int($fwd->{'count'}) .
		"</b> in 24h (550 5.7.26), which hurts this server's IP reputation. Forwarding mailboxes: $top. $fix</div>\n";
	}

# Blocked accounts
my @blocked;
if (open(my $fh, '-|', 'python3', "$pmf_dir/sasl_watch.py", 'list')) {
	while (<$fh>) { chomp; push(@blocked, [split(/\t/, $_, 4)]); }
	close($fh);
	}
my %is_blocked = map { $_->[0] => 1 } grep { $_->[2] eq '' } @blocked;
print &ui_subheading("Blocked accounts (" . scalar(@blocked) . ")");
if (@blocked) {
	print "<p><i>Listed in " . &mx_h($cfg{'SASL_WATCH_MAP'}) . " (check_sasl_access) - they can still log in and read mail, " .
		"but can't send. Change the password before unblocking: whoever stole it can usually change it too.</i></p>\n";
	print &ui_columns_start(["Account", "Blocked since", "Temporarily unblocked until", "Reason", ""]);
	foreach my $b (@blocked) {
		my ($u, $since, $until, $reason) = @$b;
		print &ui_columns_row([&mx_h($u), &mx_h($since), &mx_h($until), &mx_h($reason),
			&ui_form_start("sasl_action.cgi", "post") . &ui_hidden("user", $u) .
			&ui_submit("Unblock") . " or for " . &ui_textbox("hours", "", 3) . " hours " .
			&ui_submit("Unblock temporarily", "temp") . &ui_form_end()]);
		}
	print &ui_columns_end();
	}
else {
	print "<p>None.</p>\n";
	}

# Activity
my $accts = $r->{'accounts'} || {};
my $last_alert = $r->{'last_alert'} || {};
my @order = sort { $accts->{$b}{'ips'} <=> $accts->{$a}{'ips'} || $accts->{$b}{'msgs'} <=> $accts->{$a}{'msgs'} } keys %$accts;
print &ui_subheading("Authenticated sending, last 24h (" . scalar(@order) . " accounts)");
if (@order) {
	print &ui_columns_start(["Account", "Login names", "Messages 24h", "Last hour", "Distinct IPs",
		"Top IPs (messages)", "Delivered / bounced", "Last message", "Last alert", ""]);
	foreach my $u (@order) {
		my $a = $accts->{$u};
		my $flag = @{$a->{'reasons'} || []};
		my $style = $flag ? "color:#b30000;font-weight:bold" : "";
		my $ips = join("<br>", map { &mx_h($_->[0]) . " (" . $_->[1] . ")" } @{$a->{'top_ips'} || []});
		my $total = $a->{'sent'} + $a->{'bounced'};
		my $bounce = $total ? sprintf(" (%.0f%%)", 100 * $a->{'bounced'} / $total) : "";
		my $action = $is_blocked{$u} ? "<i>blocked</i>"
			: &ui_form_start("sasl_action.cgi", "post") . &ui_hidden("user", $u) . &ui_hidden("block", 1) .
			  &ui_submit("Block") . &ui_form_end();
		print &ui_columns_row([
			"<span style='$style'>" . &mx_h($u) . "</span>" .
				($flag ? "<br><small style='color:#b30000'>" . join("<br>", map { &mx_h($_) } @{$a->{'reasons'}}) . "</small>" : ""),
			join("<br>", map { &mx_h($_) } @{$a->{'names'} || []}),
			$a->{'msgs'} . ($a->{'exempt_msgs'} ? " <small>(" . $a->{'exempt_msgs'} . " via exempt hosts)</small>" : ""),
			$a->{'msgs_1h'},
			$a->{'ips'},
			$ips,
			"$a->{'sent'} / $a->{'bounced'}$bounce",
			&fmt_ts($a->{'last_seen'}),
			&fmt_ts($last_alert->{$u}),
			$action]);
		}
	print &ui_columns_end();
	}
else {
	print "<p>No authenticated (SASL) sending in the last 24h.</p>\n";
	}

# Failed logins - credential stuffing shows up here as real login names
# tried from many IPs.
my $failed = $r->{'failed'} || {};
my @fail_order = (sort { $failed->{$b}{'count'} <=> $failed->{$a}{'count'} } keys %$failed)[0..19];
@fail_order = grep { defined } @fail_order;
print &ui_subheading("Most targeted login names - failed AUTH, last 24h");
if (@fail_order) {
	print "<p><i>Real account names tried from many different IPs usually mean a leaked password list " .
		"(credential stuffing), not blind guessing - worth checking those accounts' passwords. " .
		"lfd/CSF blocks the IPs; this shows which accounts they aim at.</i></p>\n";
	print &ui_columns_start(["Login name", "Failed attempts", "Distinct IPs"]);
	foreach my $n (@fail_order) {
		print &ui_columns_row([&mx_h($n), $failed->{$n}{'count'}, $failed->{$n}{'ips'}]);
		}
	print &ui_columns_end();
	}
else {
	print "<p>None (or Postfix doesn't log the username on failed AUTH).</p>\n";
	}

&ui_print_footer("/", "Webmin index page");
