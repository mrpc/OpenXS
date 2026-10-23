"""Unit tests for the MCP server's JSON-RPC dispatch (the actual tool
bodies are thin wrappers already covered by their own modules' tests)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_mcp_server as srv


def test_initialize_returns_protocol_info():
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "openxs"


def test_tools_list_includes_all_five_read_only_tools():
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"status", "tail_log", "recent_findings", "list_quarantine", "check_whitelist_drift"}


def test_tools_call_unknown_tool_is_an_error():
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                "params": {"name": "nope", "arguments": {}}})
    assert "error" in resp


def test_tools_call_dispatches_to_registered_fn(monkeypatch):
    monkeypatch.setitem(srv.TOOLS, "status", {**srv.TOOLS["status"], "fn": lambda args: "fake status"})
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                "params": {"name": "status", "arguments": {}}})
    assert resp["result"]["content"][0]["text"] == "fake status"
    assert resp["result"]["isError"] is False


def test_notification_without_id_returns_none():
    assert srv.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_with_id_is_method_not_found():
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 5, "method": "bogus"})
    assert resp["error"]["code"] == -32601
