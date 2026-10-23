#!/usr/bin/env python3
"""Minimal, read-only MCP server for OpenXS: lets an agent (or a human via
an MCP client) ask "what's working, what's not" in structured form instead
of SSH + grep through log files - meant to run over stdio, launched
through `ssh <host> python3 .../openxs_mcp_server.py` from the operator's
own machine (see documentation.cgi for the .mcp.json snippet). No public
exposure, no auth of its own - it inherits whatever the SSH key allows.

Implements just enough of the MCP spec (initialize, tools/list, tools/call
over newline-delimited JSON-RPC 2.0 on stdio) to work with an MCP client -
not the full `mcp` SDK, to avoid pulling pip/async/pydantic/starlette onto
a production security host that's otherwise apt-only. No resources, no
prompts, no subscriptions: just tools, which is all this needs.

Every tool here is read-only by design - this exists to answer questions,
not to take actions (quarantine restore/delete, manual scan trigger, etc.
stay dashboard-only, where they're already one click away).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import openxs_status
import check_whitelist_drift

PMF_DIR = "/opt/php-malware-finder"
LOG_PATHS = {
    "scand": "/var/log/openxs-scand.log",
    "watchd": "/var/log/openxs-watchd.log",
    "quarantine": "/var/log/openxs-quarantine.log",
    "cron": os.path.join(PMF_DIR, "cron.log"),
    "scan": os.path.join(PMF_DIR, "scan.log"),
}
WHITELIST_PATH = os.path.join(PMF_DIR, "whitelist.yar")


def tool_status(args):
    return json.dumps(openxs_status.full_status(), indent=2)


def tool_tail_log(args):
    name = args.get("log", "scand")
    lines = int(args.get("lines", 50))
    path = LOG_PATHS.get(name)
    if not path:
        return f"Unknown log '{name}'. Known logs: {', '.join(LOG_PATHS)}"
    if not os.path.exists(path):
        return f"{path} does not exist yet (nothing logged there so far)."
    with open(path, errors="replace") as f:
        return "".join(f.readlines()[-lines:]) or "(empty)"


def tool_recent_findings(args):
    limit = int(args.get("limit", 50))
    path = os.path.join(PMF_DIR, "scan_results.txt")
    if not os.path.exists(path):
        return "No scan has produced scan_results.txt yet."
    with open(path, errors="replace") as f:
        lines = [l for l in f if l.strip()]
    return "".join(lines[-limit:]) or "(no findings in the last scan)"


def tool_list_quarantine(args):
    qdir = openxs_status.QUARANTINE_DIR
    if not os.path.isdir(qdir):
        return f"{qdir} does not exist - nothing has ever been quarantined."
    entries = []
    for name in sorted(os.listdir(qdir)):
        full = os.path.join(qdir, name)
        if os.path.isfile(full):
            entries.append(f"{name} ({os.path.getsize(full)} bytes, mtime {int(os.path.getmtime(full))})")
    return "\n".join(entries) or "(quarantine is empty)"


def tool_check_whitelist_drift(args):
    if not os.path.exists(WHITELIST_PATH):
        return f"{WHITELIST_PATH} not found."
    checked, changed, missing = check_whitelist_drift.check(WHITELIST_PATH)
    lines = [f"Checked {checked} whitelisted file(s): {len(changed)} changed, {len(missing)} missing"]
    lines += [f"CHANGED\t{p}" for p in changed]
    lines += [f"MISSING\t{p}" for p in missing]
    return "\n".join(lines)


TOOLS = {
    "status": {
        "description": "Overall OpenXS health: daemon states, detector (ClamAV/maldet) install/running status, last scan's own summary, quarantine count.",
        "inputSchema": {"type": "object", "properties": {}},
        "fn": tool_status,
    },
    "tail_log": {
        "description": "Tail one of OpenXS's own log files: scand, watchd, quarantine, cron, scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "log": {"type": "string", "enum": list(LOG_PATHS), "default": "scand"},
                "lines": {"type": "integer", "default": 50},
            },
        },
        "fn": tool_tail_log,
    },
    "recent_findings": {
        "description": "Tail the last scheduled/manual scan's findings (scan_results.txt).",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}},
        "fn": tool_recent_findings,
    },
    "list_quarantine": {
        "description": "List files currently sitting in quarantine (name, size, mtime).",
        "inputSchema": {"type": "object", "properties": {}},
        "fn": tool_list_quarantine,
    },
    "check_whitelist_drift": {
        "description": "Check whether any whitelisted file's content has changed since it was whitelisted (would start getting re-flagged). Read-only, does not re-whitelist anything.",
        "inputSchema": {"type": "object", "properties": {}},
        "fn": tool_check_whitelist_drift,
    },
}


def handle_request(req):
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "openxs", "version": "1.0"},
        }}
    if method == "tools/list":
        tools = [{"name": name, "description": t["description"], "inputSchema": t["inputSchema"]}
                  for name, t in TOOLS.items()]
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}
    if method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        tool = TOOLS.get(name)
        if not tool:
            return {"jsonrpc": "2.0", "id": req_id,
                     "error": {"code": -32602, "message": f"Unknown tool: {name}"}}
        try:
            text = tool["fn"](args)
        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id,
                     "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}}
        return {"jsonrpc": "2.0", "id": req_id,
                 "result": {"content": [{"type": "text", "text": text}], "isError": False}}
    if req_id is None:
        return None  # a notification (e.g. notifications/initialized) - no response expected
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
