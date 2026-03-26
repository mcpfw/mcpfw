"""Policy engine for mcpfw.

Loads YAML policy files and evaluates MCP messages against rules.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from .parser import MCPMessage


class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"  # allow but log with elevated priority


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Verdict:
    """The result of evaluating a message against the policy."""

    action: Action
    rule_name: str | None = None
    reason: str | None = None
    severity: Severity = Severity.INFO
    matched_pattern: str | None = None

    @property
    def is_blocked(self) -> bool:
        return self.action == Action.BLOCK


@dataclass
class ToolRule:
    """A rule that applies to a specific tool or all tools on a server."""

    name: str = "unnamed"
    tools: list[str] = field(default_factory=lambda: ["*"])
    action: Action = Action.ALLOW
    severity: Severity = Severity.INFO
    reason: str = ""
    # Block if any argument value matches these patterns
    block_patterns: list[str] = field(default_factory=list)
    # Block if any argument value matches these exact strings (case-insensitive)
    block_values: list[str] = field(default_factory=list)
    # Allow only these argument values for specific keys
    allow_paths: list[str] = field(default_factory=list)
    # Rate limiting (future)
    rate_limit: dict[str, Any] | None = None


@dataclass
class ResponseRule:
    """A rule that applies to tool results (server → client)."""

    name: str = "unnamed"
    # Regex patterns to detect in response text
    detect_patterns: list[str] = field(default_factory=list)
    action: Action = Action.LOG
    severity: Severity = Severity.WARNING
    reason: str = ""


@dataclass
class ServerPolicy:
    """Policy for a specific MCP server."""

    server: str = "*"
    default_action: Action = Action.ALLOW
    tool_rules: list[ToolRule] = field(default_factory=list)
    response_rules: list[ResponseRule] = field(default_factory=list)
    # Block these tools entirely
    blocked_tools: list[str] = field(default_factory=list)
    # Only allow these tools (if set, everything else is blocked)
    allowed_tools: list[str] | None = None


@dataclass
class Policy:
    """The complete mcpfw policy loaded from YAML."""

    version: int = 1
    default_action: Action = Action.ALLOW
    server_policies: list[ServerPolicy] = field(default_factory=list)
    # Global response scanning rules
    global_response_rules: list[ResponseRule] = field(default_factory=list)
    # Server integrity verification
    verify_server_tools: bool = False

    def evaluate_tool_call(
        self, server_name: str, msg: MCPMessage
    ) -> Verdict:
        """Evaluate a tools/call message against the policy."""
        if not msg.is_tool_call:
            return Verdict(action=self.default_action)

        tool_name = msg.tool_name
        arguments = msg.tool_arguments

        # Find matching server policy
        server_policy = self._find_server_policy(server_name)

        # Check blocked tools
        if server_policy.blocked_tools and tool_name in server_policy.blocked_tools:
            return Verdict(
                action=Action.BLOCK,
                rule_name="blocked_tools",
                reason=f"Tool '{tool_name}' is explicitly blocked",
                severity=Severity.CRITICAL,
            )

        # Check allowed tools whitelist
        if server_policy.allowed_tools is not None:
            if tool_name not in server_policy.allowed_tools:
                return Verdict(
                    action=Action.BLOCK,
                    rule_name="allowed_tools",
                    reason=f"Tool '{tool_name}' is not in the allowed list",
                    severity=Severity.WARNING,
                )

        # Evaluate tool-specific rules
        for rule in server_policy.tool_rules:
            if not self._tool_matches(tool_name, rule.tools):
                continue

            verdict = self._evaluate_tool_rule(tool_name, arguments, rule)
            if verdict is not None:
                return verdict

        # Default action
        return Verdict(action=server_policy.default_action)

    def evaluate_response(
        self, server_name: str, msg: MCPMessage
    ) -> Verdict:
        """Evaluate a tool result (server response) for sensitive data."""
        if not msg.tool_result_text:
            return Verdict(action=Action.ALLOW)

        text = msg.tool_result_text

        # Check server-specific response rules
        server_policy = self._find_server_policy(server_name)
        for rule in server_policy.response_rules:
            verdict = self._evaluate_response_rule(text, rule)
            if verdict is not None:
                return verdict

        # Check global response rules
        for rule in self.global_response_rules:
            verdict = self._evaluate_response_rule(text, rule)
            if verdict is not None:
                return verdict

        return Verdict(action=Action.ALLOW)

    def _find_server_policy(self, server_name: str) -> ServerPolicy:
        """Find the most specific matching server policy."""
        # Exact match first
        for sp in self.server_policies:
            if sp.server == server_name:
                return sp
        # Wildcard match
        for sp in self.server_policies:
            if sp.server == "*":
                return sp
        # Default
        return ServerPolicy(default_action=self.default_action)

    def _tool_matches(self, tool_name: str | None, tool_patterns: list[str]) -> bool:
        """Check if a tool name matches any of the patterns."""
        if tool_name is None:
            return False
        for pattern in tool_patterns:
            if pattern == "*":
                return True
            if pattern == tool_name:
                return True
            # Simple glob matching
            if "*" in pattern:
                regex = pattern.replace("*", ".*")
                if re.match(regex, tool_name):
                    return True
        return False

    def _evaluate_tool_rule(
        self,
        tool_name: str | None,
        arguments: dict[str, Any],
        rule: ToolRule,
    ) -> Verdict | None:
        """Evaluate arguments against a single tool rule."""
        # If rule action is block with no conditions, block immediately
        if rule.action == Action.BLOCK and not rule.block_patterns and not rule.block_values and not rule.allow_paths:
            return Verdict(
                action=Action.BLOCK,
                rule_name=rule.name,
                reason=rule.reason or f"Tool '{tool_name}' blocked by rule '{rule.name}'",
                severity=rule.severity,
            )

        # Check block_patterns against all argument values
        arg_text = self._flatten_arguments(arguments)
        for pattern in rule.block_patterns:
            try:
                if re.search(pattern, arg_text, re.IGNORECASE):
                    return Verdict(
                        action=Action.BLOCK,
                        rule_name=rule.name,
                        reason=rule.reason or f"Argument matched blocked pattern: {pattern}",
                        severity=rule.severity,
                        matched_pattern=pattern,
                    )
            except re.error:
                print(f"[mcpfw] Warning: invalid regex in rule '{rule.name}': {pattern}", file=sys.stderr)

        # Check block_values
        for val in rule.block_values:
            if val.lower() in arg_text.lower():
                return Verdict(
                    action=Action.BLOCK,
                    rule_name=rule.name,
                    reason=rule.reason or f"Argument contains blocked value: {val}",
                    severity=rule.severity,
                )

        # Check allow_paths (for filesystem tools)
        if rule.allow_paths:
            path_arg = arguments.get("path", arguments.get("directory", ""))
            if isinstance(path_arg, str) and path_arg:
                if not any(path_arg.startswith(p) for p in rule.allow_paths):
                    return Verdict(
                        action=Action.BLOCK,
                        rule_name=rule.name,
                        reason=rule.reason or f"Path '{path_arg}' is outside allowed paths",
                        severity=rule.severity,
                    )

        # If rule says LOG, return log verdict
        if rule.action == Action.LOG:
            return Verdict(
                action=Action.LOG,
                rule_name=rule.name,
                reason=rule.reason or f"Tool call logged by rule '{rule.name}'",
                severity=rule.severity,
            )

        return None

    def _evaluate_response_rule(
        self, text: str, rule: ResponseRule
    ) -> Verdict | None:
        """Evaluate response text against a response scanning rule."""
        for pattern in rule.detect_patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return Verdict(
                        action=rule.action,
                        rule_name=rule.name,
                        reason=rule.reason or f"Response matched pattern: {pattern}",
                        severity=rule.severity,
                        matched_pattern=pattern,
                    )
            except re.error:
                print(f"[mcpfw] Warning: invalid regex in rule '{rule.name}': {pattern}", file=sys.stderr)
        return None

    def _flatten_arguments(self, arguments: dict[str, Any]) -> str:
        """Flatten all argument values into a single searchable string."""
        parts = []
        for key, value in arguments.items():
            parts.append(f"{key}={value}")
        return " ".join(parts)


def load_policy(path: str | Path) -> Policy:
    """Load a policy from a YAML file."""
    path = Path(path)
    if not path.exists():
        print(f"[mcpfw] Warning: policy file not found: {path}. Using default (allow all).", file=sys.stderr)
        return Policy()

    with open(path) as f:
        data = yaml.safe_load(f)

    if not data or not isinstance(data, dict):
        return Policy()

    policy = Policy(
        version=data.get("version", 1),
        default_action=Action(data.get("default_action", "allow")),
        verify_server_tools=data.get("verify_server_tools", False),
    )

    # Parse global response rules
    for rule_data in data.get("response_rules", []):
        policy.global_response_rules.append(_parse_response_rule(rule_data))

    # Parse server policies
    for server_data in data.get("servers", []):
        policy.server_policies.append(_parse_server_policy(server_data))

    return policy


def _parse_server_policy(data: dict[str, Any]) -> ServerPolicy:
    """Parse a server policy from YAML data."""
    sp = ServerPolicy(
        server=data.get("server", "*"),
        default_action=Action(data.get("default_action", "allow")),
        blocked_tools=data.get("blocked_tools", []),
        allowed_tools=data.get("allowed_tools"),
    )

    for rule_data in data.get("tool_rules", []):
        sp.tool_rules.append(_parse_tool_rule(rule_data))

    for rule_data in data.get("response_rules", []):
        sp.response_rules.append(_parse_response_rule(rule_data))

    return sp


def _parse_tool_rule(data: dict[str, Any]) -> ToolRule:
    """Parse a tool rule from YAML data."""
    tools = data.get("tools", ["*"])
    if isinstance(tools, str):
        tools = [tools]

    return ToolRule(
        name=data.get("name", "unnamed"),
        tools=tools,
        action=Action(data.get("action", "allow")),
        severity=Severity(data.get("severity", "info")),
        reason=data.get("reason", ""),
        block_patterns=data.get("block_patterns", []),
        block_values=data.get("block_values", []),
        allow_paths=data.get("allow_paths", []),
    )


def _parse_response_rule(data: dict[str, Any]) -> ResponseRule:
    """Parse a response rule from YAML data."""
    return ResponseRule(
        name=data.get("name", "unnamed"),
        detect_patterns=data.get("detect_patterns", []),
        action=Action(data.get("action", "log")),
        severity=Severity(data.get("severity", "warning")),
        reason=data.get("reason", ""),
    )
