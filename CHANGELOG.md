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

### Changed
- `pmf_scan.py`'s per-file platform-checksum checks (WordPress,
  Drupal, ...) unified into one shared registry/directory-walk instead
  of one independent walk per platform - adding a future platform no
  longer means a second full traversal per flagged file.

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
