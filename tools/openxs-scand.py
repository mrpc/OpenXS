#!/usr/bin/env python3
"""
OpenXS scan daemon: keeps the compiled YARA ruleset in memory and serves scan
requests over a Unix socket, instead of recompiling the ruleset (php.yar +
whitelist.yar, hundreds of hash rules) on every single file upload.

Protocol (one request per connection):
  client -> daemon: <absolute file path>\\n
  daemon -> client: "1\\n"              (clean)
                 or "0 <reason>\\n"      (malware match found)

This is the exact line format mod_security's @inspectFile approver-script
protocol expects, so inspectfile.sh just has to forward our response verbatim.

A second request form returns every matching rule name instead of just the
first (the watch daemon's use case - it wants the full finding list, not a
single approve/reject decision):
  client -> daemon: ALL <absolute file path>\\n
  daemon -> client: <JSON array of rule names>\\n   (e.g. ["ObfuscatedPhp"])

Either way, the point of this daemon is that the ruleset (php.yar +
whitelist.yar + our own openxs-rules/*.yar) is compiled exactly once and
shared by every consumer - the mod_security hook and the watch daemon both
go through this same process instead of each holding their own copy in
memory.

Reload: send SIGHUP to recompile the ruleset (e.g. after whitelist.yar changes)
without restarting the daemon and dropping the socket.
"""
import os
import json
import signal
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmf_scan

RULESET = os.environ.get("OPENXS_RULESET", "/opt/php-malware-finder/php.yar")
SOCKET_PATH = os.environ.get("OPENXS_SOCKET", "/run/openxs/scan.sock")
MAX_FILE_SIZE = 5 * 1024 * 1024
LOG = "/var/log/openxs-scand.log"

_rules_lock = threading.Lock()
_rules = None


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, file=sys.stderr, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def load_rules():
    global _rules
    compiled = pmf_scan.compile_ruleset(RULESET)
    with _rules_lock:
        _rules = compiled
    log(f"ruleset loaded from {RULESET}")


def handle_sighup(signum, frame):
    try:
        load_rules()
    except Exception as e:
        log(f"reload failed: {e}")


class ScanHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096).strip()
        text = data.decode("utf-8", errors="replace")
        all_mode = text.startswith("ALL ")
        path = text[4:] if all_mode else text

        try:
            size = os.path.getsize(path)
        except OSError:
            self.request.sendall(b"[]\n" if all_mode else b"1\n")  # vanished, nothing to approve/reject on
            return

        if size <= 0 or size > MAX_FILE_SIZE:
            self.request.sendall(b"[]\n" if all_mode else b"1\n")
            return

        with _rules_lock:
            rules = _rules
        matches = rules.match(path, fast=True)

        if all_mode:
            self.request.sendall((json.dumps([m.rule for m in matches]) + "\n").encode())
            return
        if matches:
            reason = matches[0].rule
            self.request.sendall(f"0 openxs-scan: {reason} {path}\n".encode())
        else:
            self.request.sendall(b"1\n")


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    load_rules()

    socket_dir = os.path.dirname(SOCKET_PATH)
    os.makedirs(socket_dir, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    signal.signal(signal.SIGHUP, handle_sighup)

    server = ThreadingUnixServer(SOCKET_PATH, ScanHandler)
    os.chmod(SOCKET_PATH, 0o666)  # readable/writable by the webserver user
    log(f"listening on {SOCKET_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
