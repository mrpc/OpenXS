#!/usr/bin/perl
# scan.cgi
# Run a manual scan - either a single directory, or (accounts=1) every
# account under Settings' "Accounts directory" (cxs's --allusers/--www).

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my %cfg = &openxs_read_config();
my $accounts_mode = defined($in{'accounts'}) && $in{'accounts'} eq '1';

my @targets;
my $label;
my $fs_scan_root;
if ($accounts_mode) {
	my $accounts_dir = $cfg{'ACCOUNTS_DIR'} || '/home';
	my $subpath = $cfg{'ACCOUNTS_SUBPATH'};
	@targets = $subpath ne '' ? glob("$accounts_dir/*/$subpath")
	                          : glob("$accounts_dir/*");
	@targets = grep { -d $_ } @targets;
	$label = "$accounts_dir (accounts mode" . ($subpath ne '' ? ", */$subpath" : "") . ")";
	$fs_scan_root = $accounts_dir;
	}
else {
	my $path = $in{'path'};
	$path =~ s/[^a-zA-Z0-9\/_.\-]//g;  # strip anything that isn't a plain path character
	@targets = ($path) if ($path && -d $path);
	$label = $path;
	$fs_scan_root = $path;
	}

print &ui_subheading("Scan results for <code>" . &html_escape($label) . "</code>");

if (!@targets) {
	print "<p style='color:red'>" . ($accounts_mode ? "No account directories found." : "Not a valid directory.") . "</p>\n";
	}
else {
	my $filelist = "/tmp/openxs-webmin-scan-$$.txt";
	open(my $fh, '>', $filelist);
	# Scans every file by default (not just *.php) - a disguised-extension
	# webshell would otherwise never reach either engine. FAST_PHP_ONLY=1
	# trades that off for speed on very large directories.
	my $name_filter = ($cfg{'FAST_PHP_ONLY'} || '0') eq '1' ? "-name '*.php'" : "";
	foreach my $target (@targets) {
		my $cmd = "find " . quotemeta($target) . " -type f $name_filter 2>/dev/null";
		print $fh `$cmd`;
		}
	close($fh);

	$ENV{'OPENXS_SCAN_LABEL'} = $fs_scan_root;
	$ENV{'OPENXS_QUARANTINE_ENABLED'} = ($cfg{'QUARANTINE_ENABLED'} || '0') eq '1' ? '1' : '0';
	$ENV{'OPENXS_CHANGED_HOURS'} = $cfg{'CHANGED_HOURS'} || '';
	$ENV{'OPENXS_THROTTLE_LOAD'} = $cfg{'THROTTLE_LOAD'} || '';
	$ENV{'OPENXS_QUIET'} = ($cfg{'QUIET'} || '0') eq '1' ? '1' : '0';
	$ENV{'OPENXS_QUARANTINE_CATEGORIES'} = $cfg{'QUARANTINE_CATEGORIES'} || 'virus,yara_exploit,maldet';
	$ENV{'OPENXS_FAST_PHP_ONLY'} = ($cfg{'FAST_PHP_ONLY'} || '0') eq '1' ? '1' : '0';
	$ENV{'OPENXS_YARA_PARANOIA_LEVEL'} = $cfg{'YARA_PARANOIA_LEVEL'} || '1';
	$ENV{'OPENXS_COMPOSER_TRUST_MIN_AGE_DAYS'} = $cfg{'COMPOSER_TRUST_MIN_AGE_DAYS'} || '90';
	$ENV{'OPENXS_COMPOSER_TRUST_MIN_DOWNLOADS'} = $cfg{'COMPOSER_TRUST_MIN_DOWNLOADS'} || '1000';
	$ENV{'OPENXS_COMPOSER_TRUST_L2_MIN_AGE_DAYS'} = $cfg{'COMPOSER_TRUST_L2_MIN_AGE_DAYS'} || '180';
	$ENV{'OPENXS_COMPOSER_TRUST_L2_MIN_DOWNLOADS'} = $cfg{'COMPOSER_TRUST_L2_MIN_DOWNLOADS'} || '50000';
	my $out = `python3 /opt/php-malware-finder/pmf_scan.py scan $ruleset $filelist 2>&1`;
	unlink($filelist);
	print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";
	print $out ne "" ? &html_escape($out) : "(no output)";
	print "</pre>";
	}

print "<p><a href='index.cgi'>&laquo; Back</a></p>\n";
&ui_print_footer("/", "Webmin index page");
