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
      "maldet (Linux Malware Detect - its own independently-maintained MD5/HEX/YARA signature set; ".
      "report-only here, its own auto-quarantine is disabled for scans OpenXS triggers), ".
      "filesystem-level checks (SUID files, world-writable directories, symlinks, core dumps, stray ".
      "binaries), and whatever you add to the custom rule file. Two further, independent checks run alongside ".
      "these: <b>file integrity monitoring</b> (not malware detection, but drift detection for files you've ".
      "explicitly said matter) and <b>mailbox virus scanning</b> (opt-in, cxs's separate virusscan feature) - ".
      "see below.</p>";

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
QUARANTINE_CATEGORIES=virus,yara,maldet   # which categories to quarantine: virus, yara, maldet, fs
FAST_PHP_ONLY=0                    # 1 = only scan *.php (faster, misses disguised payloads)
CHANGED_HOURS=                     # blank = no time filter; N = only files changed in the last N hours
THROTTLE_LOAD=                     # blank = disabled; pause scanning if load average exceeds this
QUIET=0                            # suppress the scan summary line (for cron)
WATCH_PATHS=                       # comma-separated dirs for the watch daemon; blank = every account's web root
WATCH_RATE_COUNT=5                 # watch daemon: ignore a file after this many scans...
WATCH_RATE_WINDOW=10                # ...within this many seconds...
WATCH_RATE_COOLDOWN=60              # ...for this many seconds (cxs's --Wrateignore)
SCAN_MAILBOXES=0                    # scan every account's Maildir for viruses (ClamAV only)
MAILBOX_RECENT_HOURS=               # blank = scan all mail every time; N = only mail from the last N hours
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

print &ui_subheading("Version checks (initial sversionscan-equivalent)");
print "<p>Two independent, read-only checks run with the daily scheduled scan (not on the mod_security/watch-daemon ".
      "real-time paths - both make live network calls):</p><ul>".
      "<li><b>WordPress core</b> (<code>version_scan.py</code>): finds every <code>wp-includes/version.php</code> ".
      "under the scan path, compares against WordPress.org's own latest-version API. The only CMS type actually ".
      "found installed across our fleet so far - a generic vulnerable-plugin-version scanner is a much bigger, ".
      "still-unsolved problem (needs a CVE/vulnerability database we don't have).</li>".
      "<li><b>Composer packages</b> (same script): reads every <code>composer.lock</code> found and checks each ".
      "installed package's version against <a href='https://packagist.org' target='_blank'>Packagist</a> - no ".
      "built-in knowledge of any specific package needed (our own framework included - it just asks Packagist ".
      "the same as any dependency). A small SQLite cache (<code>/var/lib/openxs/package_versions.db</code>, ".
      "1-week TTL) means the same package appearing in many sites' composer.lock isn't re-queried every time.</li>".
      "<li><b>Pending apt security updates</b> (<code>apt_security_check.py</code>): <code>apt-get -s dist-upgrade</code> ".
      "(simulate only, never installs anything), filtered to packages whose origin includes a security repo - ".
      "portable across Debian and Ubuntu, unlike Ubuntu-only tools like update-notifier's apt-check.</li></ul>";

print &ui_subheading("Mailbox virus scanning (SCAN_MAILBOXES)");
print "<p>cxs had two separate scans: <code>exploitscan</code> (YARA, web content - what the rest of OpenXS ".
      "replicates) and <code>virusscan</code> (ClamAV, mail). This is the latter, still opt-in (off by default) ".
      "since not every server even has Maildir-format mail under its accounts directory, and some already scan ".
      "mail at delivery time via amavisd-new or clamav-milter - the Settings page checks for and notes this, but ".
      "never assumes it: confirmed on our own largest mail-handling server that neither was actually running ".
      "despite Postfix having two other milters configured (greylisting, DKIM) that look superficially similar.</p>".
      "<p>ClamAV only, not the full YARA ruleset - email attachments aren't PHP webshells. Finds every ".
      "<code>Maildir</code> directory under the accounts directory (handles both a flat <code>/home/&lt;user&gt;/".
      "Maildir</code> and a Virtualmin sub-server's nested <code>/home/&lt;user&gt;/homes/&lt;domain&gt;/".
      "Maildir</code>), scans every message under any <code>cur</code>/<code>new</code>/<code>tmp</code> folder - ".
      "including IMAP subfolders like <code>.Spam</code>, which have their own.</p>";

print &ui_subheading("File integrity monitoring - /etc/openxs/fim_paths");
print "<p>A different, broader check than the whitelist drift check above: hashes (SHA-256 - never content, so ".
      "even a file like /etc/shadow is safe to include) a configured list of files/directories you consider ".
      "important, and flags any that no longer match their last recorded baseline. Report-only: accepting a ".
      "legitimate change is a deliberate 'Baseline now' (Dashboard), same philosophy as whitelist re-validation. ".
      "One file/directory per line - pre-seeded on install (<code>tools/fim_paths.default</code>) with a ".
      "reasoned default list, editable freely (a path that doesn't exist on this server is silently skipped):</p>".
"<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" .
"/etc/passwd, /etc/shadow, /etc/group, /etc/sudoers   # core identity - should only
/etc/ssh/sshd_config, /etc/crontab, /etc/cron.d       # change via a deliberate admin action
/etc/csf/csf.conf, /etc/csf/csf.allow                 # compromised root often self-whitelists here first
/etc/openxs/*, /opt/php-malware-finder/whitelist.yar  # OpenXS's own config/rules - tampering could
/etc/systemd/system/openxs-*.service                  # blind or disable the scanner itself
</pre>".
"<p>Baselined automatically once on install. Runs with the daily scheduled scan from then on. ".
"<code>tools/openxs_fim.py baseline</code> / <code>tools/openxs_fim.py check</code> from the CLI, or ".
"'Baseline now' / 'Check now' on the Dashboard.</p>";

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
"<li><code>install_maldet.sh</code> / <code>install_clamav.sh</code> - install each if missing and apply its ".
"recommended config either way; same buttons as the dashboard's \"Install\"/\"Re-apply recommended config\".</li>".
"</ul>";

print &ui_subheading("MCP interface (for an AI agent, e.g. Claude Code)");
print "<p>A small, read-only MCP server (<code>tools/openxs_mcp_server.py</code>) exposes the same ".
      "information as this dashboard - daemon/detector status, last scan summary, log tails, the ".
      "quarantine list, whitelist drift - as structured tool calls instead of SSH + grep. It only ".
      "answers questions; it never changes anything (no quarantine restore/delete, no triggering a scan - ".
      "those stay one click away on this dashboard). Runs over stdio via SSH, no public exposure, no ".
      "auth of its own beyond whatever the SSH key already allows - add this to a <code>.mcp.json</code> ".
      "on the machine you run the agent from:</p>".
"<pre style='background:#1e1e1e;color:#e8e8e8;padding:8px'>" .
"{
  \"mcpServers\": {
    \"openxs\": {
      \"command\": \"ssh\",
      \"args\": [\"&lt;your-ssh-alias&gt;\", \"python3\", \"/opt/php-malware-finder/openxs_mcp_server.py\"]
    }
  }
}
</pre>";

print &ui_subheading("More");
print "<p>Full source, issues and the public README: <a href='https://github.com/mrpc/OpenXS' target='_blank'>".
      "github.com/mrpc/OpenXS</a>.</p>";

print "<p><a href='index.cgi'>&laquo; Back to dashboard</a></p>\n";
&ui_print_footer("/", "Webmin index page");
