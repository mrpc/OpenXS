"""Restores a finding's file to its official, upstream-pristine content -
the counterpart to the various is_unmodified_*_file() checksum checks,
which only ever SUPPRESS an existing finding when a file matches. This
is the explicit "put the official bytes back" action an admin triggers
by hand from the Webmin findings page for a file confirmed to be a
known, named core/package file whose content no longer matches what it
should (a real backdoor, or a legitimate local patch the admin decides
to discard either way).

Modeled after Wordfence's own restoreFile action
(wordfenceClass.php::ajax_restoreFile_callback(), GPLv3) - same
path-traversal defense in spirit, but backs the current content up via
the existing quarantine mechanism first instead of overwriting it
outright, since nothing here can independently verify the fetched
"pristine" content is itself safe to trust blindly (a network hiccup,
or a wrongly-detected version, could otherwise silently hand back the
wrong bytes with no way to undo it).

Composer packages, Drupal 7 core, WordPress core and wordpress.org-
hosted WordPress plugins are wired up. Revive/Roundcube/phpMyAdmin
(the other platforms pmf_scan.py's find_platform_root_for() already
recognizes) aren't yet - nobody's needed it for those so far, and each
would need its own fetch_file_content() added to its own checksums
module first (see wp_core_checksums.py's for the shape to follow)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import composer_package_checksums
import drupal_core_checksums
import pmf_scan
import wp_core_checksums
import wp_plugin_checksums

RESTORABLE_PLATFORMS = {
    "drupal7": drupal_core_checksums,
    "wordpress": wp_core_checksums,
}


def _fetch_pristine_content(file_path):
    """The official bytes this file should have, or None if we can't
    determine a known package/platform (or its version, or the content
    itself) for it at all."""
    found = pmf_scan.find_composer_package_root_for(file_path)
    if found:
        project_root, name, package_root = found
        entry = composer_package_checksums.lock_entry(os.path.join(project_root, "composer.lock"), name)
        if not entry:
            return None
        version, dist_url, _reference = entry
        if not version:
            return None
        rel = os.path.relpath(file_path, package_root)
        return composer_package_checksums.fetch_file_content(name, version, rel, dist_url=dist_url)

    # Checked before the generic platform branch below, same precedence
    # is_unmodified_wp_plugin_file() has over is_unmodified_core_file()
    # in pmf_scan.py - a plugin file sits under a WordPress install root
    # too, but needs the PLUGIN's own version/checksums, not core's.
    wp_plugin_found = pmf_scan.find_wp_plugin_root_for(file_path)
    if wp_plugin_found:
        wp_root, slug, plugin_root = wp_plugin_found
        import version_scan
        version = None
        for s, v in version_scan.find_wp_plugins(wp_root):
            if s == slug:
                version = v
                break
        if not version:
            return None
        rel = os.path.relpath(file_path, plugin_root)
        return wp_plugin_checksums.fetch_file_content(slug, version, rel)

    platform, root = pmf_scan.find_platform_root_for(file_path)
    if platform and platform["name"] in RESTORABLE_PLATFORMS:
        version = pmf_scan.detect_platform_version(platform, root)
        if not version:
            return None
        rel = os.path.relpath(file_path, root)
        return RESTORABLE_PLATFORMS[platform["name"]].fetch_file_content(version, rel)

    return None


def repair_file(finding_id):
    """(True, None) on success, (False, error_message) otherwise. Order
    matters: the pristine content is fetched and verified BEFORE
    anything on disk is touched, and the current file is only ever
    quarantined (backed up, not deleted) after that succeeds - never
    the other way around."""
    import openxs_db

    row = openxs_db.finding_by_id(finding_id)
    if not row:
        return False, "finding not found"
    file_path, _rule_name, quarantine_path, _size = row
    if quarantine_path:
        return False, "already quarantined - restore it first if you want to try a repair"
    if not os.path.isfile(file_path):
        return False, "file no longer exists"

    content = _fetch_pristine_content(file_path)
    if content is None:
        return False, "could not determine the official pristine content for this file"

    try:
        with open(file_path, "rb") as f:
            current_content = f.read()
    except OSError as e:
        return False, f"could not read the current file: {e}"
    if current_content == content:
        # Already byte-for-byte pristine - nothing to back up or
        # rewrite. Can happen if the YARA hit that created this finding
        # was itself a false positive is_unmodified_*_file() somehow
        # didn't already suppress (a different paranoia level, a stale
        # finding from before this exact version was bundled/cached,
        # ...) - no need to quarantine an unmodified file just because
        # someone clicked "repair" on it.
        return True, None

    # The account's own PHP-FPM pool runs as its own user, not root (this
    # whole daemon does) - quarantine_file() renames the original out of
    # the way, so the new file this writes needs the SAME owner/mode the
    # original had, or the site can't read its own file back afterwards.
    try:
        st = os.stat(file_path)
    except OSError as e:
        return False, f"could not stat the current file before replacing it: {e}"

    q_path = openxs_db.quarantine_file(finding_id)
    if not q_path:
        return False, "could not back up the current file before replacing it"

    try:
        with open(file_path, "wb") as f:
            f.write(content)
        os.chown(file_path, st.st_uid, st.st_gid)
        os.chmod(file_path, st.st_mode)
    except OSError as e:
        return False, (f"wrote the backup to {q_path} but could not write the restored "
                        f"file back to {file_path}: {e}")
    return True, None
