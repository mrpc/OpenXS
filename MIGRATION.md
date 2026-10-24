# Migrating from cxs

This is the "how", not the "why" (see [README.md](README.md) for why OpenXS
exists). It assumes an existing cxs install on a Virtualmin/Webmin server.

## Feature comparison

| cxs feature | OpenXS equivalent | Notes |
|---|---|---|
| `exploitscan` (heuristic PHP scanning) | php-malware-finder (YARA) | OpenXS splits hits into `yara_exploit` (high-confidence) vs `yara_heuristic` (generic patterns, opt-in quarantine) - cxs didn't distinguish these, which is what caused a false-positive incident on the old model |
| `virusscan` (ClamAV) | ClamAV, same engine | Same detector, same install |
| Mailbox virus scanning | `tools/mailbox_scan.py` | cxs had this too; opt-in here as well |
| `sversionscan` (outdated-software detection) | WordPress core + Drupal core + Composer packages + pending apt security updates | **Narrower**: cxs covered many more CMS platforms generically against a vulnerable-version database; OpenXS currently checks WordPress/Drupal core versions and Composer/apt, not arbitrary plugin-level CVEs. Known gap, tracked, not silently dropped. |
| Command Wizard "Other Options" (ignore file, change-time filter, throttle, quiet mode, `*.php`-only) | `tools/fs_scan.py` + scan options, `/etc/openxs/ignore` | Covered |
| Command Wizard "Other Options": Bayesian probability scoring, max-resources-per-directory limit, multi-threaded scanning | *(not implemented)* | Known gap - described here rather than silently dropped |
| CSF `LF_CXS` auto-block on malicious upload | `regex.custom.pm` CSF hook | Reproduced end-to-end, uses CSF's own documented custom-trigger mechanism |
| mod_security `@inspectFile` real-time upload block | Same mechanism | Covered |
| cxs's own `cxs.db` (scan history/stats) | SQLite-backed scan history (`tools/openxs_db.py`) | Covered, plus per-detector duration and system load |
| Web panel | Webmin module (dashboard, settings, quarantine, statistics) | Covered |
| File/permission compromise indicators (SUID, world-writable dirs, stray binaries, etc.) | `tools/fs_scan.py` | Covered, separate from YARA/ClamAV content scanning |

Checksum-based false-positive suppression (verifying a flagged WordPress/Drupal
core file against the official release byte-for-byte) and per-CVE
version-gated ModSecurity rules are new capabilities cxs never had.

## Migration steps

Run everything as root. `tools/migrate_from_cxs.py` is dry-run by default for
every subcommand - it only prints what it *would* do until you add `--apply`.
Review the dry-run output of each step before applying it.

1. **Install OpenXS alongside cxs** (don't touch cxs yet):
   ```
   bash install.sh
   ```
2. **Translate settings** (cxs's cron invocation flags → `openxs.conf`):
   ```
   python3 tools/migrate_from_cxs.py settings
   python3 tools/migrate_from_cxs.py settings --apply
   ```
3. **Translate custom rules** (`cxs.ignore`/`cxs.xtra` → OpenXS's `ignore`/`rules`):
   ```
   python3 tools/migrate_from_cxs.py rules
   python3 tools/migrate_from_cxs.py rules --apply
   ```
4. **Import the existing quarantine** so flagged files already moved aside by
   cxs show up in OpenXS's own quarantine UI:
   ```
   python3 tools/migrate_from_cxs.py quarantine
   python3 tools/migrate_from_cxs.py quarantine --apply
   ```
5. **Import historical scan logs** (`cxs.db` → OpenXS's scan history, so
   dashboards/trends don't start from zero):
   ```
   python3 tools/migrate_from_cxs.py logs
   python3 tools/migrate_from_cxs.py logs --apply
   ```
6. **Run OpenXS for real for a few days** (scheduled scan, real-time hook)
   alongside cxs, and compare results, before retiring cxs.
7. **Disable cxs's own `exploitscan`** first (keeps cxs's other features, like
   its CSF hook, running as a safety net while you confirm OpenXS's own CSF
   hook works):
   ```
   python3 tools/migrate_from_cxs.py disable-exploitscan --apply
   ```
8. **Once confident, retire cxs entirely** (every cxs cron entry, its Watch
   daemon):
   ```
   python3 tools/migrate_from_cxs.py disable-cxs --apply
   ```

Every `--apply` step above is independent - stop at any point and keep
running cxs and OpenXS side by side for as long as you want before continuing.

## What to double-check after migrating

- Re-read the "Narrower" row above: if you relied on cxs's `sversionscan` for
  plugin-level CVE coverage beyond WordPress/Drupal/Composer core versions,
  that gap doesn't close automatically - review what it was actually catching
  on your sites.
- Anything `migrate_from_cxs.py` printed under "item(s) need your attention"
  at any step - it reports what it can't translate instead of silently
  dropping it.
