"""Tests for mcpfw policy engine and parser."""

import json
import pytest
from mcpfw.parser import (
    MCPMessage,
    MessageDirection,
    MessageType,
    make_block_response,
    parse_message,
)
from mcpfw.policy import (
    Action,
    Policy,
    ResponseRule,
    ServerPolicy,
    Severity,
    ToolRule,
    Verdict,
    load_policy,
)


# --- Parser tests ---


class TestParseMessage:
    def test_parse_tool_call(self):
        raw = json.dumps({
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}},
            "jsonrpc": "2.0",
            "id": 1,
        })
        msg = parse_message(raw, MessageDirection.CLIENT_TO_SERVER)
        assert msg is not None
        assert msg.is_tool_call
        assert msg.tool_name == "read_file"
        assert msg.tool_arguments == {"path": "/tmp/test.txt"}
        assert msg.msg_id == 1
        assert msg.message_type == MessageType.REQUEST

    def test_parse_notification(self):
        raw = json.dumps({
            "method": "notifications/initialized",
            "jsonrpc": "2.0",
        })
        msg = parse_message(raw, MessageDirection.CLIENT_TO_SERVER)
        assert msg is not None
        assert msg.message_type == MessageType.NOTIFICATION
        assert msg.method == "notifications/initialized"
        assert not msg.is_tool_call

    def test_parse_tool_result(self):
        raw = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "file contents here"}]
            },
        })
        msg = parse_message(raw, MessageDirection.SERVER_TO_CLIENT)
        assert msg is not None
        assert msg.message_type == MessageType.RESPONSE
        assert msg.tool_result_text == "file contents here"

    def test_parse_empty_line(self):
        assert parse_message("", MessageDirection.CLIENT_TO_SERVER) is None

    def test_parse_invalid_json(self):
        assert parse_message("not json", MessageDirection.CLIENT_TO_SERVER) is None

    def test_make_block_response(self):
        resp = make_block_response(42, "Blocked by policy")
        data = json.loads(resp)
        assert data["id"] == 42
        assert data["result"]["isError"] is True
        assert "Blocked" in data["result"]["content"][0]["text"]


# --- Policy engine tests ---


class TestPolicyEvaluation:
    def _make_tool_call(self, tool_name: str, arguments: dict) -> MCPMessage:
        raw = json.dumps({
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "jsonrpc": "2.0",
            "id": 1,
        })
        return parse_message(raw, MessageDirection.CLIENT_TO_SERVER)

    def _make_response(self, text: str, msg_id: int = 1) -> MCPMessage:
        raw = json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": text}]
            },
        })
        return parse_message(raw, MessageDirection.SERVER_TO_CLIENT)

    def test_default_allow(self):
        policy = Policy()
        msg = self._make_tool_call("read_file", {"path": "/tmp/test.txt"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.action == Action.ALLOW

    def test_blocked_tool(self):
        policy = Policy(
            server_policies=[
                ServerPolicy(
                    server="test-server",
                    blocked_tools=["write_file"],
                )
            ]
        )
        msg = self._make_tool_call("write_file", {"path": "/tmp/test.txt", "content": "data"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.is_blocked
        assert "explicitly blocked" in verdict.reason

    def test_allowed_tools_whitelist(self):
        policy = Policy(
            server_policies=[
                ServerPolicy(
                    server="test-server",
                    allowed_tools=["read_file", "list_directory"],
                )
            ]
        )
        # Allowed tool
        msg = self._make_tool_call("read_file", {"path": "/tmp/test.txt"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.action == Action.ALLOW

        # Not in allowed list
        msg = self._make_tool_call("write_file", {"path": "/tmp/test.txt", "content": "data"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.is_blocked

    def test_path_restriction(self):
        policy = Policy(
            server_policies=[
                ServerPolicy(
                    server="test-server",
                    tool_rules=[
                        ToolRule(
                            name="restrict-paths",
                            tools=["read_file"],
                            allow_paths=["/tmp/", "/home/"],
                        )
                    ],
                )
            ]
        )
        # Allowed path
        msg = self._make_tool_call("read_file", {"path": "/tmp/test.txt"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert not verdict.is_blocked

        # Blocked path
        msg = self._make_tool_call("read_file", {"path": "/etc/passwd"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.is_blocked
        assert "outside allowed paths" in verdict.reason

    def test_block_pattern(self):
        policy = Policy(
            server_policies=[
                ServerPolicy(
                    server="test-server",
                    tool_rules=[
                        ToolRule(
                            name="block-ssh",
                            tools=["read_file"],
                            block_patterns=[r"\.ssh", r"\.env"],
                            severity=Severity.CRITICAL,
                        )
                    ],
                )
            ]
        )
        msg = self._make_tool_call("read_file", {"path": "/home/user/.ssh/id_rsa"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.is_blocked
        assert verdict.severity == Severity.CRITICAL

    def test_response_ssn_detection(self):
        policy = Policy(
            global_response_rules=[
                ResponseRule(
                    name="detect-ssn",
                    detect_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                    action=Action.LOG,
                    severity=Severity.CRITICAL,
                    reason="SSN detected",
                )
            ]
        )
        msg = self._make_response("User SSN: 123-45-6789")
        verdict = policy.evaluate_response("test-server", msg)
        assert verdict.action == Action.LOG
        assert verdict.severity == Severity.CRITICAL

    def test_response_clean(self):
        policy = Policy(
            global_response_rules=[
                ResponseRule(
                    name="detect-ssn",
                    detect_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                    action=Action.LOG,
                )
            ]
        )
        msg = self._make_response("Just a normal file with no sensitive data.")
        verdict = policy.evaluate_response("test-server", msg)
        assert verdict.action == Action.ALLOW

    def test_wildcard_server_policy(self):
        policy = Policy(
            server_policies=[
                ServerPolicy(
                    server="*",
                    blocked_tools=["dangerous_tool"],
                )
            ]
        )
        msg = self._make_tool_call("dangerous_tool", {})
        verdict = policy.evaluate_tool_call("any-server", msg)
        assert verdict.is_blocked

    def test_server_specific_over_wildcard(self):
        policy = Policy(
            server_policies=[
                ServerPolicy(
                    server="*",
                    blocked_tools=["write_file"],
                ),
                ServerPolicy(
                    server="trusted-server",
                    # No blocked tools — trusted
                ),
            ]
        )
        # Wildcard blocks it for unknown servers
        msg = self._make_tool_call("write_file", {"path": "/tmp/x", "content": "y"})
        verdict = policy.evaluate_tool_call("random-server", msg)
        assert verdict.is_blocked

        # Trusted server allows it
        verdict = policy.evaluate_tool_call("trusted-server", msg)
        assert not verdict.is_blocked


class TestLoadPolicy:
    def test_load_nonexistent_file(self):
        policy = load_policy("/tmp/nonexistent-policy-file.yaml")
        assert policy.default_action == Action.ALLOW

    def test_load_policy_from_yaml(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
version: 1
default_action: allow
servers:
  - server: "test-server"
    blocked_tools:
      - write_file
    tool_rules:
      - name: block-ssh
        tools: ["read_file"]
        block_patterns:
          - "\\\\.ssh"
        severity: critical
""")
        policy = load_policy(policy_file)
        assert policy.version == 1
        assert len(policy.server_policies) == 1
        assert policy.server_policies[0].blocked_tools == ["write_file"]
        assert len(policy.server_policies[0].tool_rules) == 1
        assert policy.server_policies[0].tool_rules[0].severity == Severity.CRITICAL
