"""Keeps clamd able to check every upload mod_security hands it
(inspectfile.sh), applied by install_clamav.sh (and so by the Webmin
"Re-apply recommended config" button).

1. AppArmor: Apache runs with PrivateTmp, so an upload's temp file is a
   "disconnected path" to clamd's AppArmor profile. Found live 2026-11-08
   on a Debian 13 (AppArmor 4.1) server: plain `attach_disconnected` was
   loaded, yet every upload was still denied (~340/day) - without
   `attach_disconnected.path=/` the path gets no leading "/", so no
   `/tmp/**` rule can match it. inspectfile.sh then fell back to
   --stream for every single upload.
2. Size limits: clamd skips/errors on anything above MaxFileSize /
   MaxScanSize / StreamMaxLength (Debian's generated clamd.conf: 25M), so
   an upload PHP happily accepts could go unchecked. Raised to the same
   PHP-derived size ModSecurity's own body limit uses
   (modsec_body_limit.py) - never lowered, an admin's higher value stays.
"""
import os
import re
import shutil
import subprocess
import sys

import modsec_body_limit as mbl

PROFILE = "/etc/apparmor.d/usr.sbin.clamd"
CLAMD_CONF = "/etc/clamav/clamd.conf"

# ClamAV can't scan a file over 2GB at all ("technical design limitations",
# clamd.conf docs) - no point asking for more.
CLAMD_MAX = 2000 * 1024 ** 2
# ClamAV 1.x defaults, used as the floor when a directive is absent, so
# appending one never lowers what clamd would already allow.
CLAMD_DEFAULTS = {
    "MaxFileSize": 100 * 1024 ** 2,
    "StreamMaxLength": 100 * 1024 ** 2,
    "MaxScanSize": 400 * 1024 ** 2,
}

FLAGS = ("attach_disconnected", "attach_disconnected.path=/")
_HEADER_RE = re.compile(
    r"^(\s*(?:profile\s+\S+\s+)?/usr/sbin/clamd)(?:\s+flags=\(([^)]*)\))?(\s*\{)",
    re.MULTILINE,
)


def fix_profile(text):
    """The profile text with both FLAGS on the clamd header (other flags
    kept), or the text unchanged if already there / no header found."""
    def repl(m):
        flags = [f.strip() for f in (m.group(2) or "").split(",") if f.strip()]
        flags += [f for f in FLAGS if f not in flags]
        return f"{m.group(1)} flags=({', '.join(flags)}){m.group(3)}"
    return _HEADER_RE.sub(repl, text, count=1)


def target_size():
    """Largest upload ModSecurity lets through, as clamd should accept it."""
    return min(mbl.capped_recommended_limits()[0], CLAMD_MAX)


def fix_clamd_conf(text, target):
    """clamd.conf text with each size directive raised to at least target."""
    for name, default in CLAMD_DEFAULTS.items():
        line_re = re.compile(rf"^{name}\s+(\S+)\s*$", re.MULTILINE)
        m = line_re.search(text)
        if m:
            current = mbl.parse_php_size(m.group(1))
            if current == 0 or (current is not None and current >= target):
                continue  # 0 = unlimited; never lower an admin's value
            text = line_re.sub(f"{name} {target}", text, count=1)
        elif target > default:
            text = text.rstrip("\n") + f"\n{name} {target}\n"
    return text


def _rewrite(path, new_text):
    with open(path, encoding="utf-8") as f:
        old = f.read()
    if old == new_text:
        return False
    shutil.copy2(path, path + ".openxs-bak")
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
    return True


def apply_profile():
    if not os.path.exists(PROFILE) or not shutil.which("apparmor_parser"):
        return
    with open(PROFILE, encoding="utf-8") as f:
        new = fix_profile(f.read())
    if not _rewrite(PROFILE, new):
        print("==> clamd AppArmor profile: already OK")
        return
    if subprocess.run(["apparmor_parser", "-r", PROFILE]).returncode == 0:
        print("==> clamd AppArmor profile: added attach_disconnected.path=/, reloaded")
        return
    # Older AppArmor without attach_disconnected.path: put it back as it was.
    shutil.copy2(PROFILE + ".openxs-bak", PROFILE)
    subprocess.run(["apparmor_parser", "-r", PROFILE])
    print("==> clamd AppArmor profile: parser rejected the change, restored "
          "(inspectfile.sh falls back to --stream)", file=sys.stderr)


def apply_clamd_conf():
    if not os.path.exists(CLAMD_CONF):
        return
    target = target_size()
    with open(CLAMD_CONF, encoding="utf-8") as f:
        new = fix_clamd_conf(f.read(), target)
    # ponytail: Debian's dpkg-reconfigure clamav-daemon may rewrite these;
    # re-running install_clamav.sh puts them back.
    if not _rewrite(CLAMD_CONF, new):
        print(f"==> clamd size limits: already >= {target} bytes")
        return
    subprocess.run(["systemctl", "restart", "clamav-daemon"])
    print(f"==> clamd size limits: raised to {target} bytes, clamd restarted")


if __name__ == "__main__":
    apply_profile()
    apply_clamd_conf()
