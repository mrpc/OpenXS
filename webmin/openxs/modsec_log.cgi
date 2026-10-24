#!/usr/bin/perl
# modsec_log.cgi
# Summary of recent ModSecurity blocks across every Apache error log on
# the box (shared + per-Virtualmin-domain), grouped by host/uri/rule -
# see tools/openxs_modsec_log.py for why it's grouped this way.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");
print $openxs_nav;

my $cache_age = &openxs_modsec_cache_age();
my $age_note = defined($cache_age) ? "updated " . int($cache_age / 60) . "m ago" : "live (no cache yet)";
print &ui_subheading("mod_security blocks - grouped by host/path/rule <small>($age_note)</small>");
if (!&openxs_modsecurity_active()) {
	print "<p style='color:#8a5a1f'><b>mod_security is currently disabled</b> on this server - this is ".
		"historical data from before it was disabled, it won't gain new entries until it's re-enabled.</p>\n";
	}
print "<p>A repeated block on the SAME host+path is worth a closer look - either a real false " .
	"positive (exclude it in <a href='settings.cgi'>Settings</a>), or an underlying issue " .
	"ModSecurity is correctly catching (this is how a real information-leak bug on a live site " .
	"was found and fixed this way). Scattered one-off hits across many different paths are " .
	"usually just attack-scanner noise being correctly blocked. Click a rule number to see what " .
	"it actually checks for.</p>\n";

my @rows = &openxs_modsec_rows();

if (!@rows) {
	print "<p>(no ModSecurity blocks found in any log on this server)</p>\n";
	}
else {
	my $excluded_rules = &openxs_modsec_excluded_rule_ids();
	my $excluded_path_prefixes = &openxs_modsec_excluded_path_prefixes();
	print &ui_columns_start(["Count", "Host", "Path", "Rule", "First seen", "Last seen", "Quick exclude"]);
	foreach my $r (@rows) {
		print &ui_columns_row([
			$r->{'count'}, &html_escape($r->{'host'}), &html_escape($r->{'uri'}),
			&openxs_modsec_rule_link($r->{'rule_id'}),
			&html_escape($r->{'first'}), &html_escape($r->{'last'}),
			&openxs_modsec_quick_exclude_links($r->{'rule_id'}, $r->{'uri'}, $excluded_rules, $excluded_path_prefixes),
			]);
		}
	print &ui_columns_end();
	}

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
