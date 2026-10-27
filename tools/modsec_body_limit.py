"""Derives ModSecurity's SecRequestBodyLimit/SecRequestBodyNoFilesLimit
from the server's own PHP configuration instead of a fixed number.

Why: found live 2026-10-25 - an admin raised a site's PHP upload limit
(upload_max_filesize/post_max_size) to allow a larger file, but
ModSecurity's own body-size cap (modsecurity.conf-recommended's
defaults: 13107200 bytes / 12.5MB) was still LOWER than the new PHP
limit, so uploads kept failing with no clue why - PHP's own limit
looked fine, the real ceiling was ModSecurity's, checked nowhere an
admin would normally look. A fixed replacement value (e.g. always
100MB) just moves the same class of bug to a different threshold the
next time someone raises a PHP limit past it - this derives the value
instead, so it tracks whatever PHP is actually configured to allow.

Only php.ini files for web-facing SAPIs matter here (fpm/apache2/cgi -
ModSecurity only ever inspects requests that pass through Apache/PHP-FPM).
cli/phpdbg's own limits are irrelevant to a web request body cap.

A global php.ini is only the DEFAULT, not the actual effective limit for
every site - confirmed live on prodserver (2026-10-26): a Virtualmin-managed
FPM pool had `php_admin_value[upload_max_filesize] = 2048M`, dwarfing
anything in that PHP version's own php.ini. Any FPM pool's own
php_value[...]/php_admin_value[...] override wins over its php.ini for
that one site, so pool.d/*.conf files have to be scanned too, or a
per-vhost-raised limit hits the exact same "ModSecurity caps it lower,
with no clue why" bug this module exists to prevent - just for one site
instead of the whole server.
"""
import glob
import os
import re

CONFIG_FILE = os.environ.get("OPENXS_CONFIG", "/etc/openxs/openxs.conf")

_SIZE_RE = re.compile(r"^\s*(\d+)\s*([KMG]?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}

# ModSecurity's own stock recommended defaults - never go BELOW these,
# even if no PHP limit is found (or all found ones are tiny) - that's
# ModSecurity's own considered floor, not ours to second-guess downward.
MODSEC_DEFAULT_REQUEST_BODY_LIMIT = 13107200
MODSEC_DEFAULT_REQUEST_BODY_NO_FILES_LIMIT = 131072

# HTTP multipart overhead (boundaries, per-part headers) sits on top of
# the raw file bytes PHP's own limit describes - a flat margin, not
# intended to be precise, just enough that a request landing exactly at
# PHP's own limit doesn't get rejected by ModSecurity's for being a few
# hundred bytes larger in its raw HTTP form.
MULTIPART_OVERHEAD_MARGIN = 2 * 1024 ** 2

_INI_GLOBS = [
    "/etc/php/*/fpm/php.ini",
    "/etc/php/*/apache2/php.ini",
    "/etc/php/*/cgi/php.ini",
]

_POOL_CONF_GLOB = "/etc/php/*/fpm/pool.d/*.conf"
_POOL_OVERRIDE_RE = re.compile(
    r"^\s*php_(?:admin_)?value\[(upload_max_filesize|post_max_size)\]\s*=\s*(.+?)\s*$",
    re.MULTILINE,
)


def parse_php_size(value):
    """'128M' -> 134217728, '2G' -> 2147483648, '100000' (bytes) -> 100000.
    Returns None if the value isn't a recognizable PHP ini size (this
    covers PHP's own "0" (unlimited) too, so a caller can choose how to
    treat it rather than let an unbounded site determine the limit)."""
    m = _SIZE_RE.match(value)
    if not m:
        return None
    number, unit = m.groups()
    return int(number) * _UNITS[unit.upper()]


def find_php_ini_files():
    files = []
    for pattern in _INI_GLOBS:
        files.extend(glob.glob(pattern))
    return sorted(files)


def _max_directive_value(ini_path, directive):
    try:
        with open(ini_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    m = re.search(rf"^\s*{directive}\s*=\s*(.+?)\s*$", text, re.MULTILINE)
    if not m:
        return None
    size = parse_php_size(m.group(1))
    # "0" means unlimited in PHP - that tells us nothing about what a
    # real request will actually look like, so it can't be used to size
    # a limit; skip it rather than let it collapse the result to 0.
    return size if size else None


def find_pool_conf_files():
    return sorted(glob.glob(_POOL_CONF_GLOB))


def _max_pool_override_value(pool_path):
    """The largest upload_max_filesize/post_max_size this one pool's own
    php_value[...]/php_admin_value[...] overrides to, or None if it
    doesn't override either (in which case its site falls back to its
    PHP version's own php.ini, already covered by find_php_ini_files())."""
    try:
        with open(pool_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    best = None
    for _directive, raw_value in _POOL_OVERRIDE_RE.findall(text):
        size = parse_php_size(raw_value)
        if size and (best is None or size > best):
            best = size
    return best


def max_configured_php_body_bytes():
    """The largest upload_max_filesize/post_max_size found across every
    web-facing php.ini AND every FPM pool's own override on this server,
    or None if none were found/parseable (e.g. no PHP installed, or every
    value was "0"/unlimited)."""
    best = None
    for ini_path in find_php_ini_files():
        for directive in ("upload_max_filesize", "post_max_size"):
            value = _max_directive_value(ini_path, directive)
            if value is not None and (best is None or value > best):
                best = value
    for pool_path in find_pool_conf_files():
        value = _max_pool_override_value(pool_path)
        if value is not None and (best is None or value > best):
            best = value
    return best


def recommended_limits():
    """(request_body_limit, request_body_no_files_limit) in bytes - both
    sized the same, since a PHP site can legitimately post a large
    non-file body too (e.g. a big base64-encoded field); ModSecurity's
    own stock defaults already treat the no-files case as the unusual,
    much-smaller one, this only raises both when PHP's own configured
    limit calls for it."""
    php_max = max_configured_php_body_bytes()
    if php_max is None:
        return (MODSEC_DEFAULT_REQUEST_BODY_LIMIT,
                MODSEC_DEFAULT_REQUEST_BODY_NO_FILES_LIMIT)
    target = php_max + MULTIPART_OVERHEAD_MARGIN
    return (
        max(target, MODSEC_DEFAULT_REQUEST_BODY_LIMIT),
        max(target, MODSEC_DEFAULT_REQUEST_BODY_NO_FILES_LIMIT),
    )


def body_limit_ceiling(path=None):
    """MODSEC_BODY_LIMIT_CEILING from openxs.conf, in bytes, or None if
    unset/blank/not a positive integer. An optional admin-set cap on top
    of recommended_limits()'s own PHP-derived value - e.g. to match a
    CDN/WAF's own per-request limit (Cloudflare Free/Pro: 100M), which
    raising a site's PHP limit further can never make ModSecurity need
    to allow past anyway."""
    path = path or CONFIG_FILE
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("MODSEC_BODY_LIMIT_CEILING="):
                    value = line.split("=", 1)[1].strip()
                    return int(value) if value.isdigit() and int(value) > 0 else None
    except OSError:
        pass
    return None


def capped_recommended_limits():
    """recommended_limits(), capped to body_limit_ceiling() when one is
    set - the actual values install_modsecurity.sh and the Webmin
    Settings page's "apply" action both write to modsecurity.conf."""
    body_limit, no_files_limit = recommended_limits()
    ceiling = body_limit_ceiling()
    if ceiling is not None:
        body_limit = min(body_limit, ceiling)
        no_files_limit = min(no_files_limit, ceiling)
    return body_limit, no_files_limit


if __name__ == "__main__":
    body_limit, no_files_limit = capped_recommended_limits()
    print(f"{body_limit}\t{no_files_limit}")
