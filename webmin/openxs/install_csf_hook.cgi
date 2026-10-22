#!/usr/bin/perl
# install_csf_hook.cgi
# Wires up CSF's documented regex.custom.pm extension point so lfd picks up
# our mod_security block messages and auto-blocks the offending IP, using
# CSF's existing LF_CUSTOMTRIGGER mechanism. Does not touch lfd.pl itself,
# and inserts without clobbering any custom rules already in the file.

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print &ui_subheading("Installing CSF firewall hook...");
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px;max-height:400px;overflow:auto'>";

if (!&openxs_csf_present()) {
	print "CSF was not found on this server - nothing to do.\n";
	}
else {
	my $apache_log = -e "/var/log/apache2/error.log" ? "/var/log/apache2/error.log"
							   : "/var/log/httpd/error_log";

	# Point CUSTOM1_LOG at Apache's error log (where mod_security logs blocks)
	my $conf = &read_file_lines('/etc/csf/csf.conf', 1);
	for (my $i = 0; $i < @$conf; $i++) {
		if ($conf->[$i] =~ /^CUSTOM1_LOG\s*=/) {
			$conf->[$i] = "CUSTOM1_LOG = \"$apache_log\"";
			}
		}
	&flush_file_lines('/etc/csf/csf.conf');
	print "Set CUSTOM1_LOG = \"$apache_log\" in csf.conf\n";

	# Insert our regex into regex.custom.pm, right after the marker comment,
	# unless it's already there (idempotent).
	my $already = `grep -c openxs $csf_regex 2>/dev/null`;
	chomp($already);
	if ($already) {
		print "regex.custom.pm already has the OpenXS rule, skipping.\n";
		}
	else {
		my $content = &read_file_contents($csf_regex);
		my $marker = "# Do not edit before this point";
		my $rule = "\n\tif ((\$globlogs{CUSTOM1_LOG}{\$lgfile}) and (\$line =~ ".
			"/\\[client (\\S+?)(?::\\d+)?\\] \\[client \\S+\\] ModSecurity: Access denied.*".
			"rejected by the approver script \"\\/opt\\/php-malware-finder\\/inspectfile\\.sh\"/)) {\n".
			"\t\treturn (\"openxs-scan blocked malicious upload from\",\$1,\"openxs\",\"1\",\"80,443\",\"1\",\"0\");\n".
			"\t}\n";
		my $idx = index($content, $marker);
		if ($idx >= 0) {
			$idx += length($marker);
			$content = substr($content, 0, $idx) . $rule . substr($content, $idx);
			&write_file_contents($csf_regex, $content);
			print "Inserted OpenXS rule into $csf_regex\n";
			}
		else {
			print "Could not find the expected marker in $csf_regex - not modified.\n";
			}
		}

	my $out = `perl -c $csf_regex 2>&1`;
	print &html_escape($out);
	$out = `csf -r 2>&1`;
	print &html_escape($out);
	}

print "</pre>";
print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");

sub read_file_contents
{
my ($f) = @_;
local $/;
open(my $fh, '<', $f) || return "";
my $c = <$fh>;
close($fh);
return $c;
}

sub write_file_contents
{
my ($f, $c) = @_;
open(my $fh, '>', $f) || return 0;
print $fh $c;
close($fh);
return 1;
}
