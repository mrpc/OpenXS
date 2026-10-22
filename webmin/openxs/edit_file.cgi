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

if (!$path) {
	print "<p style='color:red'>Unknown file.</p>\n";
	}
else {
	if (defined($in{'content'})) {
		my $content = $in{'content'};
		$content =~ s/\r\n/\n/g;
		open(my $fh, '>', $path) || print "<p style='color:red'>Could not write $path: $!</p>\n";
		if (fileno($fh)) {
			print $fh $content;
			close($fh);
			print "<p style='color:green'>Saved $path.</p>\n";
			}
		}
	my @lines = -e $path ? &read_file_lines($path, 1) : ();
	print &ui_subheading("Edit <code>" . &html_escape($path) . "</code>");
	print &ui_form_start("edit_file.cgi", "post");
	print &ui_hidden("f", $key);
	print "<textarea name='content' rows='20' cols='100' style='font-family:monospace'>" .
		&html_escape(join("\n", @lines)) . "</textarea><br>\n";
	print &ui_submit("Save", "save");
	print &ui_form_end();
	}

print "<p><a href='index.cgi'>&laquo; Back</a></p>\n";
&ui_print_footer("/", "Webmin index page");
