# OpenXS

[![CI](https://github.com/mrpc/OpenXS/actions/workflows/ci.yml/badge.svg)](https://github.com/mrpc/OpenXS/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrpc/OpenXS/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrpc/OpenXS/actions/workflows/codeql.yml)

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release, and
[MIGRATION.md](MIGRATION.md) for a step-by-step guide to moving from cxs.

An open-source exploit/malware scanner and firewall-integration layer for
Linux web hosting servers — built as a drop-in replacement for
[cxs (ConfigServer eXploit Scanner)](https://configserver.com/), which was
discontinued along with the rest of Way to the Web Ltd. on 2025-08-31.

## Why

cxs combined three things: heuristic exploit scanning, ClamAV-backed virus
scanning, and a CSF firewall hook that auto-blocks IPs behind malicious
uploads. It was proprietary, obfuscated, and is now unmaintained with its
license-check infrastructure offline. CSF itself — the firewall most of
these servers also depend on — was open-sourced under GPLv3 in its final
release (v15.00) before the company shut down, but the official repo is
gone and the cPanel fork that followed dropped support for anything that
isn't cPanel/WHM.

OpenXS rebuilds cxs's role entirely from actively-maintained, open
components, with nothing vendored or reverse-engineered from the original
product.

## What it does

- **Exploit detection**: [php-malware-finder](https://github.com/mrpc/php-malware-finder)
  (YARA, LGPL-3.0) — detects obfuscated PHP, webshells, and known exploit
  patterns. Upstream (nbs-system) has had no activity since 2022, so
  OpenXS pins and extends this fork instead.
- **Virus scanning**: ClamAV, as a second detector alongside YARA.
- **Known-exploit database (maldet)**: [Linux Malware Detect](https://github.com/rfxn/linux-malware-detect)
  as a third, independent detector (its own MD5/HEX/YARA signature set) -
  optional, one-click installer from the dashboard, report-only (its own
  auto-quarantine is disabled for scans OpenXS triggers).
- **Version checks**: WordPress core (against WordPress.org's own API) and
  Composer packages (against Packagist - no built-in knowledge of any
  specific package needed) for outdated versions, plus pending apt
  security updates - an initial, narrower `sversionscan` equivalent.
- **File integrity monitoring**: SHA-256 baseline of a configured list of
  important files (configs, this scanner's own whitelist/rules), reports
  drift against it - pre-seeded with a reasoned default list on install.
- **Mailbox virus scanning**: opt-in ClamAV scan of every account's
  Maildir - cxs's separate `virusscan` feature, which had no equivalent
  before this.
- **Real-time upload blocking**: a mod_security `@inspectFile` hook runs
  both detectors on every file upload, before it's ever accepted by the
  web app.
- **Firewall auto-block**: a CSF `regex.custom.pm` integration watches for
  blocked uploads and bans the source IP, using CSF's own documented
  custom-trigger mechanism (no changes to `lfd` itself).
- **Scheduled + on-demand scanning**: a daily cron job plus a manual
  "scan this directory" action.
- **Quarantine**: optional, opt-in — moves flagged files out of the
  webroot on scan (not on the real-time hook, which already blocks the
  request), with restore/delete from the UI.
- **Scan history**: a small local SQLite database, so results survive
  past the next scan - including per-scan duration (broken down by
  detector) and system load, for answering "is it optimized", not just
  "is it working".
- **Statistics**: daily aggregate counters (scans, hits, quarantined,
  avg. duration - mirrors cxs's own daily counter tables) with a simple
  chart, no external JS/CDN required.
- **Migration from cxs**: `tools/migrate_from_cxs.py` reads an existing
  cxs install's settings, custom ignore/exploit rules, quarantine, and
  historical scan logs, and imports what it can into OpenXS - reporting
  clearly (never silently) anything it can't translate - plus
  `disable-cxs` to retire cxs entirely (every cron entry, its Watch
  daemon) once OpenXS covers what it did. Dry-run by default throughout,
  `install.sh` previews and asks before applying anything.
- **MCP server**: a minimal, read-only MCP server
  (`tools/openxs_mcp_server.py`) exposes status/logs/findings as
  structured tool calls instead of SSH + grep - meant to run over SSH
  stdio from an operator's own machine, no public exposure.
- **Webmin module**: dashboard (per-component install status, with
  one-click installers for ClamAV/maldet/mod_security/the CSF hook),
  daemon control, settings (its own page, separate from the dashboard),
  scan history, statistics, and quarantine management.

### A known limitation of Composer/Packagist checksum suppression

WordPress/Drupal/Revive/Roundcube/phpMyAdmin core and any wordpress.org
plugin all go through those projects' own reviewed release directories,
so a checksum match there is a strong signal. Packagist is different:
it does no review of what gets published under a package name - it's a
pure auto-index of whatever a package's own GitHub repo publishes as a
release, so a checksum match there only verifies *"this matches what
Packagist/GitHub say is official"* - not *"this is safe"*. If that
channel itself is compromised (a maintainer's account taken over, a
malicious release published under a legitimate name), the malicious
code matches the checksum too.

Mitigated (not eliminated) by `composer_trust.py`: a package also needs
to be trusted - via `tools/composer_trusted_packages` (common ecosystem
prefixes, auto-trusted) or Packagist's own age/downloads reputation
stats (configurable thresholds) - before a checksum match suppresses
anything for it. `OPENXS_YARA_PARANOIA_LEVEL` controls how strict that
bar is, up to disabling Composer-checksum suppression entirely at
level 3 - see its docstring.

What still applies regardless of any of this: ClamAV and OpenXS's own
custom MD5/SHA256/regex rules run on every file no matter what the
checksum/trust check says - a known-bad signature or hash still gets
caught. What doesn't: a brand-new supply-chain payload with no existing
signature, published through an otherwise-trusted package, has no other
layer here to catch it. Known, accepted tradeoff, not a bug.

## Architecture

A small Python daemon (`openxs-scand`) keeps the compiled YARA ruleset in
memory and answers scan requests over a Unix socket, so uploads aren't
paying the cost of recompiling the ruleset on every request. Everything
else — the cron script, the manual scan button, the mod_security hook —
is a thin client around that engine plus ClamAV.

```
upload ──> mod_security (@inspectFile) ──> openxs-scand (YARA) ──┬─> clean: pass
                                                                   └─> malware: 403 + CSF ban
```

## Installing

**On a real Debian/Ubuntu server:**

```sh
git clone https://github.com/mrpc/OpenXS.git
cd OpenXS
sudo ./install.sh
```

Installs the detection engine, the scan daemon (systemd service), ClamAV,
the cron job, and the Webmin module (if Webmin is present). mod_security
and the CSF firewall hook are **not** installed automatically — enable
them later from the Webmin dashboard once you're ready for real-time
upload blocking.

**Sandbox (Docker)**, for trying it out or development:

```sh
docker build -t openxs .
docker run -d --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -p 18080:80 -p 18443:443 -p 10000:10000 openxs
```

Gives you a self-contained environment with Apache + mod_security + CSF +
Webmin + the full OpenXS stack, built fresh from source on every build
(nothing vendored).

## Configuration

Settings live in `/etc/openxs/openxs.conf`:

```
EMAIL=you@example.com
SCAN_PATH=/var/www
QUARANTINE_ENABLED=0
```

Editable from the Webmin dashboard, or by hand.

## Testing

```sh
pip install pytest
pytest tests/
```

Unit tests for the pure logic (ignore/path-override parsing, archive
scanning, the filesystem checks, the decode utility) - no YARA ruleset,
ClamAV, or Docker sandbox required. They're not a substitute for actually
exercising the Webmin dashboard and the mod_security/CSF integration by
hand, which has no automated coverage yet.

## Status

This is an early-stage project. What's implemented is listed above and has
been tested end-to-end (including on a vanilla, from-scratch install), but
it has **not yet been deployed to a real production server**. `install.sh`
has only been tested on Debian 12 (bookworm); it explicitly refuses to run
on non-apt systems rather than failing halfway through.

Still on the roadmap, deliberately incremental rather than all-at-once:

- Full `sversionscan` coverage — WordPress core and Composer packages are
  covered; the other ~200 CMSs/plugins (and any vulnerable-version
  database beyond "what's the latest release") cxs covered are not.
- Support for hosting control panels beyond Webmin/Virtualmin (our own
  fleet's panel, and all of OpenXS's UI/accounts-mode assumptions so
  far) — CyberPanel, HestiaCP, CloudPanel. Each has its own account
  layout and plugin/module system; needs its own investigation per
  panel before any code.
- Testing `install.sh` against more environments: other Debian/Ubuntu
  releases, RHEL/CentOS-family systems (would need a yum/dnf code path),
  and against the actual CSF version (v14.24, pre-GPLv3) still running on
  most of our own servers — the CSF-hook installer has only been verified
  against the v15.00 GPLv3 release so far.
- WordPress database-content scanning: a real 2+ year compromise on
  mrpc.pramnos.net (found 2026-10-25) lived entirely in `wp_posts` as a
  published "WPCode"/Insert Headers and Footers snippet — a full
  remote-control backdoor (cookie-gated admin-user creation, C2-proxied
  content injection for logged-out visitors) that never touched the
  filesystem at all, so no amount of YARA/ClamAV/maldet coverage could
  ever have caught it; OpenXS only scans files on disk. Needs a
  DB-aware check (any WordPress install found during a scan, look at
  its own `wp_posts`/`wp_options` for published WPCode/IHAF/similar
  header-footer-injection snippets, flag suspicious ones the same way
  a file-based finding is flagged) — a structurally new category of
  check, not an extension of the existing file-scanning path.

## Credits

- [php-malware-finder](https://github.com/nbs-system/php-malware-finder)
  (nbs-system, LGPL-3.0) — the original detection ruleset this builds
  on; see our [fork](https://github.com/mrpc/php-malware-finder), which
  OpenXS actually pins and extends.
- [signature-base](https://github.com/Neo23x0/signature-base) (Florian
  Roth/Nextron Systems and contributors, Detection Rule License 1.1) —
  the webshell detection rules vendored into our php-malware-finder
  fork, since it's still actively maintained where upstream
  php-malware-finder isn't.
- [CSF](https://github.com/centminmod/configserver-scripts) (Jonathan
  Michaelson, GPLv3) — the firewall OpenXS integrates with.
- [Webmin](https://github.com/webmin/webmin) — the management UI framework.

OpenXS builds against [its own forks](https://github.com/mrpc) of the first
two, pinned to a specific reviewed commit rather than upstream HEAD — the
forks auto-sync with upstream daily, but OpenXS only moves to a new commit
deliberately. Pass `--build-arg PMF_COMMIT=master`/`CSF_COMMIT=main` (or
the equivalent `install.sh`/Webmin options) to track the fork's latest
instead.

## License

MIT (see [LICENSE](LICENSE)) for OpenXS's own code. php-malware-finder and
CSF are fetched at install/build time under their own licenses (LGPL-3.0
and GPLv3 respectively) and are not redistributed as part of this repo.
