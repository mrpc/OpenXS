#!/usr/bin/perl
# edit_file.cgi
# Generic small text-file editor, restricted to the %editable_files
# allow-list in openxs-lib.pl (ignore/rules/path_settings/csf.blocklists) -
# never an arbitrary path from the request.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

my $key = $in{'f'};
my $path = $editable_files{$key};

my %modsec_regen = (
	'modsec_exclusions' => ['openxs_modsec_exclusions.py', '/etc/modsecurity/openxs-exclusions.conf'],
	'modsec_mode' => ['openxs_modsec_mode.py', '/etc/modsecurity/openxs-mode.conf'],
	'modsec_rule_exclusions' => ['openxs_modsec_rule_exclusions.py', '/etc/modsecurity/after-crs/openxs-rule-exclusions.conf'],
	);

sub regenerate_modsec
{
my ($key) = @_;
return if (!$modsec_regen{$key});
my ($script, $generated) = @{$modsec_regen{$key}};
my $out = `python3 $pmf_dir/$script 2>&1`;
system("apache2ctl -t 2>/dev/null && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null)");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" . &html_escape($out) . "</pre>";
print "<p style='color:green'>Regenerated " . &html_escape($generated) . " and reloaded Apache.</p>\n";
}

if (!$path) {
	print "<p style='color:red'>Unknown file.</p>\n";
	}
else {
	# The server-wide mode toggle (modsec_mode's bare '*' hostname) gets
	# its own small form above the per-host text editor - typing '* off'
	# by hand works too, but a dropdown is harder to typo into silently
	# doing nothing (an unrecognized mode is just skipped by the parser).
	if ($key eq 'modsec_mode' && defined($in{'global_mode'})) {
		my @lines = -e $path ? @{ &read_file_lines($path, 1) } : ();
		@lines = grep { !/^\s*\*\s+/ } @lines;  # drop any existing '*' line(s)
		push(@lines, "* $in{'global_mode'}") if ($in{'global_mode'} ne 'on');  # 'on' is the implicit default - no line needed
		open(my $fh, '>', $path) || print "<p style='color:red'>Could not write $path: $!</p>\n";
		if (fileno($fh)) {
			print $fh join("\n", @lines) . (@lines ? "\n" : "");
			close($fh);
			print "<p style='color:green'>Server-wide mode set to '$in{'global_mode'}'.</p>\n";
			&regenerate_modsec($key);
			}
		}
	my @save_errors;
	if (defined($in{'content'}) && !defined($in{'global_mode'})) {
		my $content = $in{'content'};
		$content =~ s/\r\n/\n/g;
		my @submitted_lines = split(/\n/, $content, -1);
		@submitted_lines = () if (@submitted_lines == 1 && $submitted_lines[0] eq '');
		@save_errors = $editable_file_validators{$key} ? $editable_file_validators{$key}->(\@submitted_lines) : ();
		if (@save_errors) {
			print "<p style='color:red'><b>Not saved - fix these first:</b></p>\n<ul>";
			print "<li>" . &html_escape($_) . "</li>\n" foreach (@save_errors);
			print "</ul>\n";
			}
		else {
			open(my $fh, '>', $path) || print "<p style='color:red'>Could not write $path: $!</p>\n";
			if (fileno($fh)) {
				print $fh $content;
				close($fh);
				print "<p style='color:green'>Saved $path.</p>\n";
				&regenerate_modsec($key);
				}
			}
		}

	# Show the submitted (unsaved) text back on a validation failure -
	# re-reading the file here would silently discard what was just
	# typed, undoing the whole point of catching the mistake first.
	my @lines;
	if (@save_errors) {
		@lines = split(/\n/, $in{'content'}, -1);
		}
	else {
		@lines = -e $path ? @{ &read_file_lines($path, 1) } : ();
		}

	print &ui_subheading("Edit <code>" . &html_escape($path) . "</code>");
	if ($editable_file_help{$key}) {
		print "<div style='background:#f0f7ff;border:1px solid #c3d6ea;border-radius:4px;padding:8px;margin-bottom:10px'>".
			"<b>Format:</b> " . $editable_file_help{$key} . "</div>\n";
		}

	if ($key eq 'modsec_mode') {
		my %current;
		foreach my $l (@lines) {
			my $t = $l; $t =~ s/^\s+|\s+$//g;
			next if ($t eq '' || $t =~ /^#/);
			my ($h, $m) = split(/\s+/, $t);
			$current{$h} = $m if (defined($m));
			}
		my $current_global = $current{'*'} || 'on';
		print &ui_form_start("edit_file.cgi", "post");
		print &ui_hidden("f", $key);
		print "<b>Server-wide default:</b> " .
			&ui_select("global_mode", $current_global, [["on", "On"], ["detection", "Detection only"], ["off", "Off"]]) . " " .
			&ui_submit("Set", "set_global") . "<br>\n";
		print &ui_form_end();
		print "<p>Per-host overrides (below) take priority over the server-wide default above.</p>\n";
		}

	print &ui_form_start("edit_file.cgi", "post");
	print &ui_hidden("f", $key);
	print "<textarea name='content' rows='20' cols='100' style='font-family:monospace'>" .
		&html_escape(join("\n", @lines)) . "</textarea><br>\n";
	print &ui_submit("Save", "save");
	print &ui_form_end();
	}

print "<p><a href='index.cgi'>&laquo; Back</a></p>\n";
&ui_print_footer("/", "Webmin index page");
