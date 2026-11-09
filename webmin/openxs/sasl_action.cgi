#!/usr/bin/perl
# sasl_action.cgi
# Block an account by hand, or unblock it - for good, or for N hours
# (blocked again after that) - through sasl_watch.py.

require './openxs-lib.pl';
&ReadParse();

my $user = $in{'user'};
my $hours = $in{'temp'} ? $in{'hours'} : 0;
$hours =~ s/[^0-9.]//g;
if ($user !~ /^[A-Za-z0-9._\@+-]+$/) {
	&openxs_result_page("Invalid account name.", 1, "Back to Mail accounts", "mail_accounts.cgi");
	}
if ($in{'temp'} && !($hours > 0)) {
	&openxs_result_page("Give the number of hours for a temporary unblock.", 1, "Back to Mail accounts", "mail_accounts.cgi");
	}
my @args = $in{'block'} ? ('block', $user) : ('unblock', $user, '--hours', $hours || 0);

# List-form open: no shell, the account name is never interpreted.
my $out = '';
if (open(my $fh, '-|', 'python3', "$pmf_dir/sasl_watch.py", @args)) {
	local $/;
	$out = <$fh>;
	close($fh);
	}
&openxs_result_page($out || "sasl_watch.py failed", $? ? 1 : 0, "Back to Mail accounts", "mail_accounts.cgi");
