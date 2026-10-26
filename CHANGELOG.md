# Changelog

All notable changes to OpenXS are documented here, grouped per release
by what kind of change it is. Versions link to their GitHub comparison;
the current unreleased state lives at the top until the next tag.

Categories used: **Signatures** (new/updated detection rules, checksum
bundles, version-detection for a platform), **Fixed** (bug fixes),
**Added** (new features), **Changed** (behavior changes to an existing
feature's logic), **UX** (dashboard/Settings layout, live-progress UI,
anything about how the admin interacts with OpenXS rather than what it
detects/does), **Security** (CVE-specific protections). Only include
categories a release actually touched - don't pad with empty headings.

When tagging a release: move `[Unreleased]`'s entries under a new
`## [vX.Y.Z] - YYYY-MM-DD` heading (keep `[Unreleased]` itself, now
empty, at the top for the next round), then tag and create the GitHub
Release from that section's text.

## [Unreleased]

### Fixed
- `install_modsecurity.sh` hardcoded ModSecurity's `SecRequestBodyLimit`/
  `SecRequestBodyNoFilesLimit` to its own stock recommended defaults
  (12.5MB/128KB) - raising a site's own PHP `upload_max_filesize`/
  `post_max_size` past that point kept failing uploads with no obvious
  cause, since ModSecurity's cap sat nowhere an admin configuring PHP
  limits would think to check. New `tools/modsec_body_limit.py` derives
  both from this server's own actual PHP configuration instead: every
  web-facing php.ini (fpm/apache2/cgi, every installed version) AND
  every FPM pool's own `php_value[...]`/`php_admin_value[...]`
  overrides, which win over their version's php.ini for that one site -
  confirmed live (2026-10-26) that at least one Virtualmin-managed pool
  on prodserver overrides its php.ini's default by two orders of magnitude
  (2048M). Never goes below ModSecurity's own stock defaults even when
  no PHP config is found.
- `NonPrintableChars` (php-malware-finder's own vendored rule) matches
  "function"/"return"/"base64_decode" followed within 256 characters by
  3+ consecutive bytes outside printable ASCII - a single em dash,
  curly quote, or any other non-ASCII character in a PHPDoc comment
  encodes as exactly that in UTF-8 (an em dash is 3 bytes, all outside
  ASCII), right next to two of the most common words in any PHP file.
  Found live across two unrelated servers' 2-day scan history
  (2026-10-26): every one of 521 (prodserver) and 507 (newserver.anotherserver)
  distinct flagged files was valid UTF-8 end-to-end - essentially the
  entire false-positive volume of this rule on both. New
  `is_valid_utf8_file()` suppresses just this rule (not
  ObfuscatedPhp/DangerousPhp/etc., whose own trigger patterns don't
  share this mechanism) when the whole file decodes as valid UTF-8 - a
  genuinely obfuscated/binary-packed payload essentially never happens
  to decode as valid UTF-8 across its entire length, so this doesn't
  trade away real detection. Deliberately NOT fixed by loosening the
  vendored rule's own byte-range regex - YARA can only match byte
  ranges, not verify a valid multi-byte UTF-8 *sequence*, so doing that
  there would also start ignoring genuinely binary/obfuscated content
  that happens to use the same byte ranges without being valid UTF-8 -
  weaker than real UTF-8 decoding, not just differently located.

## [v0.2.0] - 2026-10-25

### Signatures
- Drupal 7: detect installs, flag as unsupported (Drupal 7 is end of
  life), suppress false positives on unmodified core files via a
  self-built checksums bundle (drupal.org has no official per-file
  checksums API).
- WordPress: suppress false positives on unmodified core files via
  wordpress.org's official per-version checksums (bundled, weekly
  auto-refresh).
- Revive Adserver: detect installs, flag outdated ones.
- Any wordpress.org-hosted plugin (not a hand-picked few): suppress
  false positives on its own unmodified, officially-released code via
  `wp_plugin_checksums.py` - downloads.wordpress.org's own per-version
  zip (the same URL WordPress's own "install this version" uses),
  cached to disk per (slug, version) on first use rather than a
  pre-built bundle (too many plugins/versions to commit, unlike
  WordPress core itself). Covers most of the real false-positive
  volume found live 2026-10-24 (Wordfence, Jetpack, Yoast SEO and
  others were all wordpress.org-hosted, confirmed end-to-end against
  real flagged files) - a commercial/non-wp.org plugin (e.g. RevSlider)
  isn't covered and needs its own fix.
- A wordpress.org plugin's own TRANSLATION files (`wp_plugin_lang_checksums.py`):
  a plugin's own release zip never contains these at all (confirmed by
  hand) - they're versioned completely separately via
  api.wordpress.org/translations/plugins/1.0/ and land in one shared
  directory (`wp-content/languages/plugins/<slug>-<locale>.l10n.php`,
  every plugin's translations together, not nested under the plugin's
  own folder), which is why `wp_plugin_checksums.py` alone never
  covered these. Non-ASCII translated text (Greek, etc.) trips the
  generic NonPrintableChars/DodgyStrings heuristics just as easily as
  obfuscated code does, found live 2026-10-24 recurring across many
  unrelated accounts. Partial coverage by nature, not a bug - WordPress
  translations get revised independently of the plugin version (unlike
  code, which never changes once released), so a site's local file can
  legitimately be an earlier-but-still-official revision than whatever
  the API currently serves.
- Roundcube Webmail and phpMyAdmin: suppress false positives on
  unmodified core files via self-built checksums bundles (same shape as
  Revive - neither project publishes an official per-file checksums
  API, so these are computed from each project's own official release
  archive). Found live 2026-10-24 on our own infra (prodserver's webmail
  and DB-admin installs) - phpMyAdmin legitimately runs arbitrary SQL/
  code by design, and Roundcube bundles minified/obfuscated-looking
  vendored JS, both real false-positive sources.
- Vendored [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)'s
  webshell ruleset into our php-malware-finder fork (upstream
  php-malware-finder itself has had no activity since 2022).
- `default_rules` (shipped custom-rule bundle, same relationship to
  `/etc/openxs/rules` as `default_ignore` has to `/etc/openxs/ignore`):
  a regex for the "self-doubled MD5" password-gated backdoor
  (`md5($x.md5($x))==(hash)`, then an eval/base64_decode/file_put_contents/
  SSRF-relay payload) - found live 2026-10-24, a multi-site compromise
  where 5 of 68 planted files used a plain hash literal with an SSRF-
  relay payload that none of the existing heuristics' dangerous-sink
  keywords happened to match, evading detection entirely. This targets
  the one structural element every variant shares, regardless of payload.

### Security
- PHP2Shell (CVE-2026-109618/109619): ModSecurity rules blocking the
  main attack vectors, installed only on servers where at least one
  PHP version isn't already protected (minimizes false-positive
  surface where the vulnerability can't even be triggered).

### Fixed
- `pmf_scan.py` no longer crashes the whole scan on a file whose path
  has a raw non-UTF8 byte, or one that can't be passed through to
  yara's C extension.
- `install.sh`'s "already cloned, update in place" path for the
  php-malware-finder fork was silently leaving the real files stale
  while a new vendored ruleset appeared in an unused directory -
  fixed, and the pinned commit now uses a full SHA (a short one isn't
  always resolvable via `git fetch`).
- Split the single `yara` quarantine category into `yara_exploit`
  (high-confidence fingerprint matches, still auto-quarantined by
  default) and `yara_heuristic` (generic patterns, now opt-in only) -
  the root fix for a stale-whitelist false-positive storm auto-
  quarantining real site files.
- Genuinely binary file content (detected via a NUL byte in the first
  chunk, same heuristic `git`/`grep -I` use) now skips only the YARA
  text-heuristic ruleset instead of false-positiving on it (found live:
  `.git/index` and pack files flagging as `ObfuscatedPhp`/`NonPrintableChars`
  purely because a `<?` byte sequence appeared by chance in binary
  data) - ClamAV and custom rules still scan the file regardless, and
  nothing is path-excluded (a `.git` directory can still host a real
  exploit).

### Added
- "Resolved" filter on the Findings page (All / Unresolved only /
  Resolved only) - "resolved" means actually acted on (quarantined/
  deleted, or has an active permission fix). Lets an admin hide what's
  already been dealt with and see only what's left, instead of
  re-scanning the same already-handled findings mentally on every
  visit - a real need after fixing thousands of world-writable-
  directory findings by hand in one sitting.
- "Fix permissions" button on a "world-writable directory" finding
  (strips just the world-write bit) - found live 2026-10-24 that one
  account alone had its entire upload tree at 0777 with no technical
  reason under php-fpm's own per-account pools (the pool already owns
  the files; the world-write bit adds nothing a legitimate process
  needs). A directory can't be quarantined the way a file can
  (quarantining would take the whole site down), so this is its
  equivalent one-click remediation, reversible the same way
  quarantine's own Restore button is.
- `VMRSS_MAX_MB` as a real Settings-page option instead of a silent
  hardcoded scan memory ceiling.
- Weekly GitHub Action keeping the WordPress checksums bundle current
  with new releases automatically.
- `version_scan.py`: WordPress plugin/theme outdated-version checks
  (wordpress.org's plugin/theme info API) and Joomla core version
  detection/EOL-branch flagging (1.x/2.x/3.x) - closes the real gap
  that most shared-hosting WordPress exposure is an outdated plugin,
  not an outdated core or a Composer-managed dependency.
- `openxs_collector.py`: one periodic cron entry for lightweight
  bookkeeping jobs (mod_security block-count history, the blocks-view
  cache) instead of a separate `/etc/cron.d` file per feature.
- mod_security detection-only mode (`/etc/openxs/modsec_mode`, one
  `<hostname> <mode>` per line, plus a server-wide on/detection/off
  dropdown surfaced directly on Settings) and precise rule exclusions
  (`/etc/openxs/modsec_rule_exclusions`, one `<rule id> <variable>` per
  line via `SecRuleUpdateTargetById`, server-wide only - confirmed by
  hand that neither `LocationMatch`, `<If>`, `ctl:ruleRemoveById` nor a
  mod_rewrite env var scopes it to one path on this stack) - a
  confirmed false positive gets a surgical fix (one rule, one variable)
  instead of `openxs_modsec_exclusions.py`'s blunter "disable
  everything for this path", found live on a real incident (CRS 930120
  false-positiving on Google OAuth's `scope` parameter).
- `mod_remoteip`, installable from Settings: resolves the real visitor
  IP behind Cloudflare (`CF-Connecting-IP`, trusted against Cloudflare's
  own published ranges) instead of every Cloudflare-fronted site's logs
  and IP-based decisions seeing only Cloudflare's own edge IPs.
- CSF auto-ban (opt-in, Settings): the watch daemon temporarily bans
  (`csf -td`, reversible) an uploader's IP on a high-confidence
  yara_exploit/virus/maldet finding, but only when exactly one client
  made a POST/PUT to that account's domain in the preceding seconds -
  zero or multiple candidates just log a line, never guess. Refuses to
  even save as enabled until `mod_remoteip` is active, and refuses to
  ban an IP that's actually Cloudflare's own edge range.
- `MIGRATION.md`: step-by-step cxs migration guide (comparison table +
  the actual `migrate_from_cxs.py` subcommands in order), not just the
  README's "why" explanation.
- Revive Adserver core-file checksum suppression (`revive_core_checksums.py`,
  bundled against every tagged GitHub release) - its delivery scripts
  (`www/delivery/*.php`) are legitimately minified/obfuscated-looking by
  design, a real false-positive source found in production
  (`ObfuscatedPhp`/`DodgyPhp` on `cl.php`, `ajs.php`, `al.php`, etc.),
  same fix shape as WordPress/Drupal core.
- "Mark false positive" on findings (adds the file to `/etc/openxs/ignore`
  automatically) and on mod_security blocks (same effect as its existing
  quick-exclude buttons) - both also write to a new
  `false_positive_reports` table for later review/aggregation.
- Format-hint text and a per-file validator for every Settings text-file
  editor (`edit_file.cgi`) - a malformed line that the real parser would
  otherwise silently skip is now rejected at save time instead.
- `default_ignore`: a shipped (not locally-editable) false-positive list
  for common third-party software (Adminer, PHPUnit's eval-stdin test
  utility, Loco Translate, Simple Lightbox, GOTMLS) - unlike
  `/etc/openxs/ignore` (local, per-server), this updates on every
  install via `git pull`, so a false positive found on one install's
  copy of a common package is suppressed on every other install too,
  not just the one it was found
  on.

### Changed
- `pmf_scan.py`'s per-file platform-checksum checks (WordPress,
  Drupal, ...) unified into one shared registry/directory-walk instead
  of one independent walk per platform - adding a future platform no
  longer means a second full traversal per flagged file.
- A file whose path can't be encoded as UTF-8 (a non-UTF8 filename,
  e.g. Greek text from an older encoding) is now actually scanned via
  its raw bytes instead of being skipped and merely logged - the
  earlier "fix" only stopped the crash, it never scanned those files.
- mod_security's "grouped by host/path/rule" view reads from a 5-minute
  cron-refreshed cache instead of re-grepping every Apache error log on
  the box on every page view.

### UX
- Every per-row action button on the Findings page and Scan history
  (Quarantine/Restore/Delete, Fix/Restore permissions) silently
  submitted to the wrong backend ("Invalid request." from
  bulk_action.cgi, not whichever script the button actually meant to
  hit) - findings.cgi/reports.cgi wrap the whole table in one outer
  `<form>` for the "Quarantine selected/Restore/Delete" bulk checkboxes,
  and every per-row button was ALSO its own nested `<form>` - invalid
  HTML, so the browser's own parser recovery collapsed every nested one
  into that single outer form. Root-caused by reproducing the exact
  failure in a real headless browser against a synced local copy of
  the module (not guesswork from code reading alone) - the user's own
  click only ever reached bulk_action.cgi, never the per-row script at
  all. Fixed with HTML5's `form="<id>"` button attribute (an
  out-of-line, non-nested `<form>` per row, referenced by id) instead
  of nesting - Authentic theme's own `ui_submit()` override already
  has built-in support for exactly this attribute.
- Dashboard: live scan-completion percentage, stage indicator (all 4
  scan stages - YARA, ClamAV, maldet, filesystem checks), a per-stage
  progress bar plus a second, history-based overall-progress bar (the
  scan's elapsed time against the average duration of recent full
  scans) in the live scanlog view, all fed by `pmf_scan.py`'s own
  progress file. Resource widgets (scan daemon/watch daemon/manual
  scan) now link through to their own live log view.
- Settings page: a "Components" section holds every component's own
  install/update/on-off toggle (detection engine, ClamAV, maldet,
  mod_security, CSF, mod_remoteip, the Servers Status widget, IP
  reputation feeds) - the dashboard itself now only shows what's
  actually running right now (daemons, last scan, quarantine count,
  FIM, pending updates) plus day-to-day actions and log links, instead
  of mixing in every one-time setup/toggle control.
- mod_security's two "off" controls (the lightweight rule-engine mode
  dropdown vs. `Disable` actually unloading Apache's module) merged
  into one Settings row with the relationship between them spelled
  out, instead of sitting in separate, unrelated-looking rows.
- `settings.cgi`: a newly-added row (server-wide mod_security mode) had
  its own `<form>` nested inside the still-open main Settings form -
  invalid HTML, which made the browser collapse every row after it
  into one unstructured line of buttons.
- An unchanged file already flagged by a generic heuristic (a legitimate
  third-party plugin that just looks obfuscated) got re-alerted on
  every single scheduled scan forever - findings were never deduplicated
  across scans at all. `openxs_db.new_finding_ids()` now tracks whether
  an exact (path, rule, size) finding has shown up in any earlier scan;
  the email alert only counts heuristic/fs findings the first time
  they're seen, while serious ones (virus/yara_exploit/maldet) still
  alert every scan regardless - an unresolved real backdoor should keep
  nagging until it's actually quarantined, not go quiet just because
  it's been seen once. This doesn't reduce how much checksums/
  default_ignore need to cover (that only addresses specific known
  software) - it's the general fix for the fact that no amount of
  curation covers every possible legitimate script an account might
  install.
- The scheduled-scan email's subject and body lumped every category
  together into one flat "N genuine hit(s)" count/dump - a night with
  thousands of generic-heuristic hits (common, legitimate minified/
  obfuscated third-party code) buried the 1-2 real virus/exploit/maldet
  hits in a wall of noise, or made the subject line itself misleadingly
  alarming. `split_scan_results.py` now tiers scan_results.txt into
  serious/heuristic/fs before the email is built, and leads with
  serious. The Findings page also now shows a color-coded category
  badge on every row (not just as a tab filter), so "All" doesn't read
  as one undifferentiated wall either.
- The scan progress file was removed right after ClamAV finished,
  before maldet/fs_scan even started - the dashboard/live log showed
  nothing for the rest of the scan even on runs where those two stages
  were individually slower than YARA+ClamAV combined. Now tracks all 4
  stages (scan/clamav/maldet/fs), cleaned up only once at the very end.
- The scan progress bar fell back to 0% width on every stage without a
  per-file percentage (clamav/maldet/fs), looking identically empty
  whether 1/4 or fully done through the pipeline.
- "symlink" dominated the fs (filesystem-hygiene) findings (9897 of
  12526 on one server) with no way to tell a routine panel/OS
  convention from something actually worth a look - Virtualmin's own
  per-domain Apache log symlinks, the PHP-version-selector symlink, and
  (the biggest chunk) relative symlinks within the same account (e.g. a
  mimetype icon pack's "notavailable.png" fallback for filetypes
  without their own icon) are no longer flagged. A symlink pointing
  OUTSIDE its own account (another account's home directory, /etc/,
  anywhere unexpected) - the pattern that actually matters - still is,
  always checked by where it actually points, never by name alone.
  A cPanel-to-Virtualmin account migration's leftover theme symlink
  (var/cpanel/styled/current_style -> /usr/local/cpanel/...) is also
  no longer flagged - dangling by nature on a server with no cPanel
  install at all, so nothing can ever appear at that target for it to
  resolve to.
- The Findings page showed "File gone" (hiding the Quarantine/View
  actions) for a "symlink" finding whose symlink itself still existed
  but whose TARGET didn't (a dangling symlink) - os.path.exists()
  follows the link and checks the target, not the symlink file itself;
  switched to os.path.lexists(), found live via the cPanel-migration-
  leftover symlinks above.
- The Findings page briefly showed "No findings recorded yet." for
  every real finding after the fix above shipped - its own fix
  comment's escaped quotes (`\"symlink\"`, `\"File gone\"`) satisfied
  Perl's own string parsing but landed unescaped in the shell command
  that runs the embedded Python, breaking its quoting mid-loop; Python
  then only received a truncated script, printed the total count
  (before the loop) and crashed silently on the rest - backticks only
  capture stdout, not stderr, so this had no visible error at all.
  Found live by reproducing against a copy of the real production
  database with a headless browser rather than trusting the backend
  query alone (which returned correct rows when run directly - the bug
  was purely in how the CGI assembled its own shell command). Fixed by
  rewording the comment without embedded quote characters; same trap
  any future comment inside one of these backtick-wrapped Python
  blocks needs to avoid.
- `quarantine_file()`/`restore_file()` had the same exists()-vs-
  symlink gap as the display bug above, plus a sharper one: chmod()
  follows a symlink, so quarantining one whose target DOES exist
  somewhere would have locked down that unrelated target file, not the
  symlink being acted on. Switched both to os.path.lexists() and skip
  the chmod step for a symlink entirely (nothing of its own to lock
  down). The "Quarantine now" button is now labeled "Remove symlink"
  for symlink findings specifically - "Quarantine" implies a
  neutralized threat, the wrong framing for what's usually just a
  stale or unexpected path (asked after the cPanel-leftover symlinks
  above surfaced this as a real, if rare, user-facing action).

## [v0.1.2] - 2026-10-24

### Fixed
- `pmf_scan.py` skips files whose path can't be passed to yara instead
  of crashing the whole scan.
- `openxs_tail()` rewritten as pure Perl instead of forking `tail(1)` -
  fixed intermittent truncated log output under system load.

### Added
- mod_security: per-day chart/column on the Stats page (persisted via
  cron, since live log parsing alone loses history to log rotation),
  clickable rule-ID links, a dedicated "recent blocks" page, and
  path-exclusion support (Settings page) for known false positives.

### Changed
- `logs.cgi`: per-file "View full log" page instead of one shared,
  ambiguous "show more lines" link.

## [v0.1.1] - 2026-10-24

### Fixed
- Manual scan form now reflects the actually-configured scan mode
  instead of hardcoding `/var/www`.

### Changed
- Scheduled scan defaults to "accounts" mode automatically when
  Virtualmin is detected.

## [v0.1.0] - 2026-10-24

First tagged release.
