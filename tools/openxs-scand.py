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

Reload: send SIGHUP to recompile the ruleset (e.g. after whitelist.yar changes)
without restarting the daemon and dropping the socket.
"""
import os
import signal
import socket
import socketserver
import sys
import threading

RULESET = os.environ.get("OPENXS_RULESET", "/opt/php-malware-finder/php.yar")
SOCKET_PATH = os.environ.get("OPENXS_SOCKET", "/run/openxs/scan.sock")
MAX_FILE_SIZE = 5 * 1024 * 1024

import yara

_rules_lock = threading.Lock()
_rules = None


def load_rules():
    global _rules
    compiled = yara.compile(RULESET, includes=True, error_on_warning=False)
    with _rules_lock:
        _rules = compiled
    print(f"openxs-scand: ruleset loaded from {RULESET}", file=sys.stderr)


def handle_sighup(signum, frame):
    try:
        load_rules()
    except Exception as e:
        print(f"openxs-scand: reload failed: {e}", file=sys.stderr)


class ScanHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096).strip()
        path = data.decode("utf-8", errors="replace")

        try:
            size = os.path.getsize(path)
        except OSError:
            self.request.sendall(b"1\n")  # file vanished, nothing to approve/reject on
            return

        if size <= 0 or size > MAX_FILE_SIZE:
            self.request.sendall(b"1\n")
            return

        with _rules_lock:
            rules = _rules
        matches = rules.match(path, fast=True)
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
    print(f"openxs-scand: listening on {SOCKET_PATH}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
