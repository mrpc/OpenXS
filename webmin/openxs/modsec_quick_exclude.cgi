#!/usr/bin/perl
# modsec_quick_exclude.cgi
# One-click exclude from a mod_security blocks row - appends a line to
# the appropriate config file (deduped, not already present), then
# regenerates and reloads, same as a manual edit via Settings would.
# "rule" excludes one rule ID across ARGS generally (the broadest
# reasonable starting point without inspecting the audit log for the
# exact variable - refine to a narrower variable or add a path scope
# later via Settings if this turns out too broad for that rule). "path"
# fully disables ModSecurity for that exact path (same as an entry in
# Settings' path exclusions).

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $action = $in{'action'};
my $file = $action eq 'path' ? '/etc/openxs/modsec_exclusions'
         : $action eq 'rule' ? '/etc/openxs/modsec_rule_exclusions'
         : undef;
my $line = $action eq 'path' ? $in{'uri'}
         : $action eq 'rule' ? ($in{'rule_id'} . " ARGS")
         : undef;

if (!$file || $line eq '') {
	print "<p style='color:red'>Missing or invalid action.</p>\n";
	}
else {
	my @existing = -e $file ? @{ &read_file_lines($file, 1) } : ();
	if (grep { $_ eq $line } @existing) {
		print "<p>Already excluded: <code>" . &html_escape($line) . "</code></p>\n";
		}
	else {
		open(my $fh, '>>', $file) || print "<p style='color:red'>Could not write $file: $!</p>\n";
		if (fileno($fh)) {
			print $fh "$line\n";
			close($fh);
			my $script = $action eq 'path' ? 'openxs_modsec_exclusions.py' : 'openxs_modsec_rule_exclusions.py';
			my $out = `python3 $pmf_dir/$script 2>&1`;
			system("apache2ctl -t 2>/dev/null && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null)");
			print "<p style='color:green'>Added <code>" . &html_escape($line) . "</code> to " . &html_escape($file) .
				", regenerated the Apache config, and reloaded.</p>\n";
			print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" . &html_escape($out) . "</pre>";
			if ($action eq 'rule') {
				print "<p><i>This excludes the rule across ARGS generally - edit <a href='edit_file.cgi?f=modsec_rule_exclusions'>".
					"$file</a> directly to narrow it to one specific variable or path once you've confirmed the exact match ".
					"from the request's audit log entry.</i></p>\n";
				}
			}
		}
	}

print "<p><a href='modsec_log.cgi'>&laquo; Back to mod_security blocks</a></p>\n";
&ui_print_footer("/", "Webmin index page");
