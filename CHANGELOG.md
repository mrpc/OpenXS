# Changelog

All notable changes to OpenXS are documented here, grouped per release
by what kind of change it is. Versions link to their GitHub comparison;
the current unreleased state lives at the top until the next tag.

Categories used: **Signatures** (new/updated detection rules, checksum
bundles, version-detection for a platform), **Fixed** (bug fixes),
**Added** (new features), **Changed** (behavior/UX changes to an
existing feature), **Security** (CVE-specific protections). Only
include categories a release actually touched - don't pad with empty
headings.

When tagging a release: move `[Unreleased]`'s entries under a new
`## [vX.Y.Z] - YYYY-MM-DD` heading (keep `[Unreleased]` itself, now
empty, at the top for the next round), then tag and create the GitHub
Release from that section's text.

## [Unreleased]

### Signatures
- Drupal 7: detect installs, flag as unsupported (Drupal 7 is end of
  life), suppress false positives on unmodified core files via a
  self-built checksums bundle (drupal.org has no official per-file
  checksums API).
- WordPress: suppress false positives on unmodified core files via
  wordpress.org's official per-version checksums (bundled, weekly
  auto-refresh).
- Revive Adserver: detect installs, flag outdated ones.
- Vendored [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)'s
  webshell ruleset into our php-malware-finder fork (upstream
  php-malware-finder itself has had no activity since 2022).

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

### Added
- `VMRSS_MAX_MB` as a real Settings-page option instead of a silent
  hardcoded scan memory ceiling.
- Weekly GitHub Action keeping the WordPress checksums bundle current
  with new releases automatically.
- Dashboard: live scan-completion percentage, stage indicator
  (scanning vs ClamAV post-processing), and a progress bar in the live
  scanlog view, all fed by `pmf_scan.py`'s own progress file. Resource
  widgets (scan daemon/watch daemon/manual scan) now link through to
  their own live log view.
- `version_scan.py`: WordPress plugin/theme outdated-version checks
  (wordpress.org's plugin/theme info API) and Joomla core version
  detection/EOL-branch flagging (1.x/2.x/3.x) - closes the real gap
  that most shared-hosting WordPress exposure is an outdated plugin,
  not an outdated core or a Composer-managed dependency.
- `openxs_collector.py`: one periodic cron entry for lightweight
  bookkeeping jobs (mod_security block-count history, the blocks-view
  cache) instead of a separate `/etc/cron.d` file per feature.
- mod_security detection-only mode (`/etc/openxs/modsec_mode`, one
  `<hostname> <mode>` per line) and precise rule exclusions
  (`/etc/openxs/modsec_rule_exclusions`, one `<rule id> <variable>
  [path]` per line via `SecRuleUpdateTargetById`) - a confirmed false
  positive gets a surgical fix (one rule, one variable) instead of
  `openxs_modsec_exclusions.py`'s blunter "disable everything for this
  path", found live on a real incident (CRS 930120 false-positiving on
  Google OAuth's `scope` parameter).
- `MIGRATION.md`: step-by-step cxs migration guide (comparison table +
  the actual `migrate_from_cxs.py` subcommands in order), not just the
  README's "why" explanation.
- "Mark false positive" on findings (adds the file to `/etc/openxs/ignore`
  automatically) and on mod_security blocks (same effect as its existing
  quick-exclude buttons) - both also write to a new
  `false_positive_reports` table for later review/aggregation.
- Format-hint text and a per-file validator for every Settings text-file
  editor (`edit_file.cgi`) - a malformed line that the real parser would
  otherwise silently skip is now rejected at save time instead.

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
