# CSF firewall integration — proof of concept (2026-10-22)

Reproduces the `LF_CXS` auto-block behavior of the now-discontinued cxs
(ConfigServer eXploit Scanner), using only open-source components. Verified
end-to-end in a Docker sandbox (Debian + Apache + mod_security2 + CSF v15.00
GPLv3 + the php-malware-finder YARA ruleset).

## How it works
1. **mod_security** (`modsecurity-openxs.conf`) uses `@inspectFile` on
   `FILES_TMPNAMES` — it runs our own script on every file upload.
2. **inspectfile.sh** (`../tools/inspectfile.sh`) runs the php-malware-finder
   YARA ruleset against the file. **Protocol gotcha**: mod_security's
   `@inspectFile` does NOT read the exit code — it reads one line from
   stdout: `"1"` = approve/clean, `"0 <reason>"` = reject/malware (the
   opposite of the usual Unix exit-code convention; took a while to find).
3. When mod_security denies the request, it logs a specific line to Apache's
   error log (`... rejected by the approver script
   "/opt/php-malware-finder/inspectfile.sh": ...`).
4. **CSF's `regex.custom.pm`** (via `CUSTOM1_LOG`, see
   `csf.conf.snippet.txt`) watches that log with our own regex and calls
   CSF's existing, documented `LF_CUSTOMTRIGGER` mechanism — **no changes to
   lfd.pl itself**, a fully supported, official extension point.

## Test result
- Uploading a malicious PHP file (obfuscated eval/system, disguised as
  `.jpg`) → 403 → IP automatically blocked in `csf.deny` within ~10 seconds.
- Uploading a clean file → 200, no action taken.

## Requirements on a real server (not yet applied to production)
- `mod_security2` installed (not present on most of our fleet yet — see the
  ops notes repo for the cost/benefit discussion).
- `SecUploadKeepFiles On` + `SecUploadDir` configured (off by default — the
  hook does nothing without this).
- `php.yar`/php-malware-finder already installed.
- CSF v15.00 (GPLv3 community release).

## Not done yet
- Testing against realistic upload traffic (false-positive rate on
  legitimate uploads: images, PDFs, etc. — `@inspectFile` runs on *every*
  upload, so CPU/latency cost needs measuring).
- Any production deployment decision.
