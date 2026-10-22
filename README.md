# OpenXS

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

- **Exploit detection**: [php-malware-finder](https://github.com/nbs-system/php-malware-finder)
  (YARA, LGPL-3.0) — detects obfuscated PHP, webshells, and known exploit
  patterns.
- **Virus scanning**: ClamAV, as a second detector alongside YARA.
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
  past the next scan.
- **Webmin module**: dashboard (per-component install status, with
  one-click installers for mod_security/the CSF hook), daemon control,
  settings (alert e-mail, scan path, quarantine toggle), scan history,
  and quarantine management.

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

## Status

This is an early-stage project. What's implemented is listed above and has
been tested end-to-end (including on a vanilla, from-scratch install), but
it has **not yet been deployed to a real production server**. `install.sh`
has only been tested on Debian 12 (bookworm); it explicitly refuses to run
on non-apt systems rather than failing halfway through.

Still on the roadmap, deliberately incremental rather than all-at-once:

- `sversionscan` equivalent — detecting outdated/vulnerable versions of
  installed CMSs and plugins (cxs covered 700+ applications; this needs
  its own data model and isn't a quick addition).
- Per-category detection strictness (cxs let you choose exactly which
  heuristics trigger a report vs. a quarantine action).
- Server-level security audit (missing security updates, known
  vulnerable packages).
- Testing `install.sh` against more environments: other Debian/Ubuntu
  releases, RHEL/CentOS-family systems (would need a yum/dnf code path),
  and against the actual CSF version (v14.24, pre-GPLv3) still running on
  most of our own servers — the CSF-hook installer has only been verified
  against the v15.00 GPLv3 release so far.

## Credits

- [php-malware-finder](https://github.com/nbs-system/php-malware-finder)
  (nbs-system, LGPL-3.0) — the detection ruleset this builds on.
- [CSF](https://github.com/centminmod/configserver-scripts) (Jonathan
  Michaelson, GPLv3) — the firewall OpenXS integrates with.
- [Webmin](https://github.com/webmin/webmin) — the management UI framework.

## License

MIT (see [LICENSE](LICENSE)) for OpenXS's own code. php-malware-finder and
CSF are fetched at install/build time under their own licenses (LGPL-3.0
and GPLv3 respectively) and are not redistributed as part of this repo.
