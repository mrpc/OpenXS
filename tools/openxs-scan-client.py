#!/usr/bin/env python3
"""Thin client for openxs-scand. Usage: openxs-scan-client.py <file-path>

Prints the daemon's response verbatim ("1" or "0 <reason>"). On any
connection failure, fails open ("1") - never block an upload because our own
daemon happens to be down.
"""
import os
import socket
import sys

SOCKET_PATH = os.environ.get("OPENXS_SOCKET", "/run/openxs/scan.sock")


def main():
    if len(sys.argv) != 2:
        print("1")
        return
    path = sys.argv[1]
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(SOCKET_PATH)
        s.sendall((path + "\n").encode())
        response = s.recv(4096).decode(errors="replace").strip()
        print(response if response else "1")
    except Exception as e:
        print("1")
        print(f"openxs-scan-client: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
