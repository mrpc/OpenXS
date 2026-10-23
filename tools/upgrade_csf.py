#!/usr/bin/env python3
"""Upgrades an existing CSF install to the pinned open-source GPLv3
release (same fork+commit the Dockerfile uses for a fresh sandbox
install - see CSF_FORK/CSF_COMMIT there, bump both together on review).

CSF's own install.generic.sh only creates csf.conf/csf.allow/csf.deny/
csf.pignore/regex.custom.pm etc. if they don't already exist (confirmed
by reading it directly, not assumed) - an existing config, including
our own OpenXS hook rule in regex.custom.pm, survives this untouched.
Only the CSF scripts/binaries themselves get replaced. Still backs up
/etc/csf and /usr/local/csf first regardless, as cheap insurance before
touching anything that can affect firewall/SSH access.
"""
import os
import shutil
import subprocess
import tarfile
import tempfile

CSF_FORK = "https://github.com/mrpc/openxs-csf.git"
CSF_COMMIT = "4793f7c2e6f705eb4244a9fcd3f4cd202c726085"


def _run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def csf_version():
    rc, out = _run(["csf", "-v"])
    return out.strip() if rc == 0 else None


def is_old_csf(version_str):
    """True if this looks like the old pre-GPLv3 licensed line (< 15),
    not the open-source v15.00+ release. 'csf: v14.24 (generic)' etc."""
    if not version_str:
        return False
    import re
    m = re.search(r"v(\d+)\.(\d+)", version_str)
    return bool(m) and int(m.group(1)) < 15


def upgrade():
    if not os.path.exists("/etc/csf/csf.conf"):
        return False, "CSF isn't installed on this server - nothing to upgrade."

    before = csf_version()
    backup_dir = "/var/lib/openxs/csf-backup-" + subprocess.run(
        ["date", "+%Y%m%d%H%M%S"], capture_output=True, text=True).stdout.strip()
    os.makedirs(backup_dir, exist_ok=True)
    for d in ("/etc/csf", "/usr/local/csf"):
        if os.path.isdir(d):
            shutil.copytree(d, os.path.join(backup_dir, os.path.basename(d)), dirs_exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        rc, out = _run(["git", "init", "-q", tmp])
        if rc != 0:
            return False, f"git init failed:\n{out}"
        rc, out = _run(["git", "remote", "add", "origin", CSF_FORK], cwd=tmp)
        rc2, out2 = _run(["git", "fetch", "-q", "--depth", "1", "origin", CSF_COMMIT], cwd=tmp)
        rc3, out3 = _run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=tmp)
        if rc != 0 or rc2 != 0 or rc3 != 0:
            return False, f"Fetching the pinned fork failed:\n{out}{out2}{out3}"

        tgz = os.path.join(tmp, "csf.tgz")
        if not os.path.isfile(tgz):
            return False, f"csf.tgz not found in the fork at {CSF_COMMIT} - fork layout may have changed."
        with tarfile.open(tgz) as t:
            t.extractall(tmp)

        csf_dir = os.path.join(tmp, "csf")
        rc, out = _run(["sh", "install.sh"], cwd=csf_dir)
        if rc != 0:
            return False, f"install.sh failed (backup kept at {backup_dir}):\n{out}"

    # Per the fork's own migration guide: v15.00 disabled the actual
    # auto-update mechanism in code, but AUTO_UPDATES left on still tries
    # and fails with a cosmetic (but noisy, daily) error otherwise.
    with open("/etc/csf/csf.conf") as f:
        conf = f.read()
    import re
    conf, _ = re.subn(r'^AUTO_UPDATES\s*=.*$', 'AUTO_UPDATES = "0"', conf, flags=re.M)
    with open("/etc/csf/csf.conf", "w") as f:
        f.write(conf)

    after = csf_version()
    _run(["csf", "-r"])
    return True, f"{before} -> {after}\nBackup kept at {backup_dir}. AUTO_UPDATES disabled (upstream's own servers are gone)."


if __name__ == "__main__":
    import sys
    if "--apply" in sys.argv:
        ok, msg = upgrade()
        print(msg)
        sys.exit(0 if ok else 1)
    else:
        print(csf_version())
