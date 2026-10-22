#!/usr/bin/perl
# documentation.cgi
# Reference documentation - cxs's "Documentation" button equivalent
# (reference.txt/install.txt rolled into one page here, since this is
# much smaller in scope so far).

require './openxs-lib.pl';
&ReadParse();
&ui_print_header(undef, 'OpenXS Exploit Scanner', "");

print $openxs_nav;

print &ui_subheading("Overview");
print "<p>OpenXS detects malicious PHP (webshells, obfuscated code) and other compromise ".
      "indicators across three independent layers:</p><ul>".
      "<li><b>Real-time upload blocking</b>: a mod_security <code>\@inspectFile</code> hook checks every ".
      "HTTP file upload before it's accepted, via the scan daemon's socket.</li>".
      "<li><b>Watch daemon</b> (<i>early/evolving</i>): watches whole directories for any file change ".
      "- not just HTTP uploads - via inotify.</li>".
      "<li><b>Scheduled/manual scans</b>: a daily cron job and the dashboard's 'Scan now' button, ".
      "covering everything under the scan path regardless of when it last changed.</li></ul>".
      "<p>All three go through the same detectors: YARA (php-malware-finder + our own rules), ClamAV, ".
      "filesystem-level checks (SUID files, world-writable directories, symlinks, core dumps, stray ".
      "binaries), and whatever you add to the custom rule file.</p>";

print &ui_subheading("Architecture: the two daemons");
print "<p><b>openxs-scand</b> compiles the full ruleset (php.yar + whitelist.yar + ".
      "<code>tools/openxs-rules/*.yar</code>) once and serves match requests over a Unix socket ".
      "(<code>/run/openxs/scan.sock</code>) - this is the only process holding the compiled ruleset in ".
      "memory. It's used directly by the mod_security hook, and queried by <b>openxs-watchd</b> (which ".
      "has no ruleset of its own - it's purely an inotify-driven discovery mechanism that asks scand ".
      "'what matches on this file', then runs custom rules/ClamAV/quarantine itself). Updating the ".
      "ruleset ('Update now' on the dashboard) sends scand a SIGHUP reload - both daemons pick it up, ".
      "since watchd always asks the live scand rather than holding a stale copy.</p>";

print &ui_subheading("Configuration file - /etc/openxs/openxs.conf");
print "<p>Plain <code>KEY=value</code> lines, one per line. Editable from the dashboard's Settings form, ".
      "or by hand:</p>";
print "<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>".
"EMAIL=root\@localhost              # alert e-mail address
SCAN_MODE=path                     # 'path' (single directory) or 'accounts' (every hosting account)
SCAN_PATH=/var/www                 # directory for the scheduled/manual scan, used when SCAN_MODE=path
ACCOUNTS_DIR=/home                 # one subdirectory per account, used when SCAN_MODE=accounts
ACCOUNTS_SUBPATH=public_html       # web root per account; blank = whole account home dir
SCHEDULE=17 2 * * *                # cron syntax; blank = scheduled scan disabled
QUARANTINE_ENABLED=0               # move flagged files to quarantine
QUARANTINE_CATEGORIES=virus,yara   # which categories to quarantine: virus, yara, fs
FAST_PHP_ONLY=0                    # 1 = only scan *.php (faster, misses disguised payloads)
CHANGED_HOURS=                     # blank = no time filter; N = only files changed in the last N hours
THROTTLE_LOAD=                     # blank = disabled; pause scanning if load average exceeds this
QUIET=0                            # suppress the scan summary line (for cron)
WATCH_PATHS=                       # comma-separated dirs for the watch daemon; blank = daemon stays off
</pre>";

print &ui_subheading("Ignore file - /etc/openxs/ignore");
print "<p>One entry per line, applied to every detector (YARA, ClamAV, filesystem checks):</p>".
"<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" .
"/some/path/or/substring     # skip anything whose path contains this
md5:&lt;hash&gt;                   # skip one exact file by content (survives renames)
sha256:&lt;hash&gt;
# lines starting with # are comments
</pre>";

print &ui_subheading("Custom rule file - /etc/openxs/rules");
print "<p>Extra checks beyond the built-in ruleset, applied to every scanned file's content:</p>".
"<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" .
"eval\\s*\\(base64_decode     # a regex (Python re syntax) to flag if found
md5:&lt;hash&gt;                   # flag an exact known-exploit file by content hash
sha256:&lt;hash&gt;
</pre>";

print &ui_subheading("Per-path settings - /etc/openxs/path_settings");
print "<p>Different settings for a specific directory, overriding the global ones above. One per line: ".
      "<code>&lt;path-prefix&gt; key=value,key=value</code> - the longest matching prefix wins. Supported ".
      "keys: <code>fast_php_only</code>, <code>quarantine_enabled</code>, <code>quarantine_categories</code>.</p>".
"<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" .
"/home/bigsite/uploads fast_php_only=1
/home/bigsite/backups quarantine_enabled=0
</pre>";

print &ui_subheading("Quarantine");
print "<p>Opt-in (<code>QUARANTINE_ENABLED</code>), applies to manual/scheduled/watch-daemon scans only ".
      "- the real-time upload hook already blocks the request outright, there's nothing left to move. ".
      "Quarantined files are chmod 0000'd and moved to <code>/var/lib/openxs/quarantine/</code>; restore ".
      "and permanent delete are both available from the Quarantine view. By default only the <code>virus</code> ".
      "and <code>yara</code> categories are quarantined (not <code>fs</code> - filesystem indicators like ".
      "SUID files or symlinks are much more likely to be a legitimate part of the server).</p>";

print &ui_subheading("Command-line tools (tools/)");
print "<ul>".
"<li><code>pmf_scan.py scan &lt;php.yar&gt; &lt;filelist.txt&gt;</code> - the core scanner, used by the ".
"cron job and the manual scan button.</li>".
"<li><code>fs_scan.py &lt;directory&gt;</code> - filesystem-level checks standalone.</li>".
"<li><code>pmf_decode.py &lt;file&gt; [max_depth]</code> - manually unwrap base64/rot13/gzinflate/".
"gzuncompress/gzdecode calls in a suspicious file, for inspecting obfuscated PHP by hand.</li>".
"<li><code>openxs-scand.py</code> / <code>openxs-watchd.py</code> - the two daemons, see Architecture above.</li>".
"</ul>";

print &ui_subheading("More");
print "<p>Full source, issues and the public README: <a href='https://github.com/mrpc/OpenXS' target='_blank'>".
      "github.com/mrpc/OpenXS</a>.</p>";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
