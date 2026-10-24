"""Cloudflare's own published IP ranges (ips-v4/ips-v6) - shared between
install_mod_remoteip.sh (bash, its own copy) and anything in OpenXS that
makes a decision based on a "visitor IP" (e.g. an auto-ban).

is_cloudflare_ip() is the actual safety net for that second use: before
ever acting on an IP (banning it, say), check it isn't itself one of
Cloudflare's own edge addresses - if mod_remoteip isn't active, isn't
configured correctly for that specific vhost, or simply wasn't installed
yet on this server, the "visitor IP" we'd otherwise see is really just
the shared Cloudflare PoP that happened to proxy this one request, and
banning it would affect every other site Cloudflare also serves through
it, not the actual attacker. This check doesn't depend on whether
mod_remoteip is installed at all - it directly inspects the candidate IP
itself, so it still protects a server that was never set up with
install_mod_remoteip.sh."""
import ipaddress
import os
import urllib.request

IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
IPS_V6_URL = "https://www.cloudflare.com/ips-v6"
CACHE_FILE = os.environ.get("OPENXS_CLOUDFLARE_RANGES_CACHE", "/var/lib/openxs/cloudflare_ranges.txt")

# Last-known-good, 2026-10-24 - used when there's no cache yet and no
# outbound internet right now (same list install_mod_remoteip.sh bakes
# in for the same reason).
FALLBACK_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


def fetch_ranges(timeout=10):
    """Live from Cloudflare, None on any failure (caller falls back)."""
    try:
        ranges = []
        for url in (IPS_V4_URL, IPS_V6_URL):
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                ranges += [line.strip() for line in resp.read().decode().splitlines() if line.strip()]
        return ranges or None
    except Exception:
        return None


def get_ranges(refresh=False):
    """Cache-first (same spirit as the WordPress/Drupal/Revive checksum
    bundles - works offline), live-refresh on request, falling back to
    the baked-in list if neither is available."""
    if not refresh and os.path.isfile(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                cached = [line.strip() for line in f if line.strip()]
            if cached:
                return cached
        except OSError:
            pass
    live = fetch_ranges()
    if live:
        try:
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            with open(CACHE_FILE, "w") as f:
                f.write("\n".join(live) + "\n")
        except OSError:
            pass
        return live
    return FALLBACK_RANGES


def is_cloudflare_ip(ip, ranges=None):
    """True if ip falls inside any of Cloudflare's published ranges.
    Never raises on a malformed ip - treated as "not Cloudflare" rather
    than crashing whatever safety check called this."""
    ranges = ranges if ranges is not None else get_ranges()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for r in ranges:
        try:
            if addr in ipaddress.ip_network(r):
                return True
        except ValueError:
            continue
    return False
