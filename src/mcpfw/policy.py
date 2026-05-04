"""Policy engine for mcpfw.

Loads YAML policy files and evaluates MCP messages against rules.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from .parser import MCPMessage

_PATH_ARG_KEYS: tuple[str, ...] = (
    "path", "directory", "file", "filepath", "filename",
    "src", "source", "destination", "dest", "target",
)


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
    # Allow only filesystem paths under these allowed roots (checked via canonical paths).
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
        """Check if a tool name matches any of the patterns (supports shell-style globs)."""
        if tool_name is None:
            return False
        for pattern in tool_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
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
            path_arg = next(
                (arguments[k] for k in _PATH_ARG_KEYS if k in arguments and isinstance(arguments[k], str)),
                None,
            )
            if path_arg:
                if not self._is_path_allowed(path_arg, rule.allow_paths):
                    return Verdict(
                        action=Action.BLOCK,
                        rule_name=rule.name,
                        reason=rule.reason or f"Path '{path_arg}' is outside allowed paths",
                        severity=rule.severity,
                    )
            else:
                return Verdict(
                    action=Action.BLOCK,
                    rule_name=rule.name,
                    reason=rule.reason or "No path argument found; blocked by allow_paths rule",
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

    def _is_path_allowed(self, raw_path: str, allowed_roots: list[str]) -> bool:
        """Check whether raw_path is under any allowed root (after canonicalization)."""
        try:
            candidate = Path(raw_path).expanduser()
            # Resolve without requiring the path to exist (prevents traversal bypass).
            candidate_resolved = candidate.resolve(strict=False)
        except Exception:
            return False

        for root in allowed_roots:
            try:
                root_path = Path(root).expanduser().resolve(strict=False)
            except Exception:
                continue

            # Exact match allowed, and any descendant allowed.
            if candidate_resolved == root_path:
                return True
            try:
                candidate_resolved.relative_to(root_path)
                return True
            except Exception:
                continue

        return False

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
        """Recursively flatten all argument values into a single searchable string."""
        def _extract_strings(obj: Any) -> list[str]:
            if isinstance(obj, str):
                return [obj]
            if isinstance(obj, dict):
                result = []
                for k, v in obj.items():
                    result.append(str(k))
                    result.extend(_extract_strings(v))
                return result
            if isinstance(obj, (list, tuple)):
                result = []
                for item in obj:
                    result.extend(_extract_strings(item))
                return result
            return [str(obj)]

        return " ".join(_extract_strings(arguments))


def _parse_action(value: str, context: str) -> Action:
    """Parse an action string with a descriptive error on failure."""
    try:
        return Action(value)
    except ValueError:
        valid = [a.value for a in Action]
        raise ValueError(f"Invalid action '{value}' in {context}. Valid values: {valid}") from None


def _parse_severity(value: str, context: str) -> Severity:
    """Parse a severity string with a descriptive error on failure."""
    try:
        return Severity(value)
    except ValueError:
        valid = [s.value for s in Severity]
        raise ValueError(f"Invalid severity '{value}' in {context}. Valid values: {valid}") from None


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
        default_action=_parse_action(data.get("default_action", "allow"), "policy.default_action"),
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
    server_name = data.get("server", "*")
    sp = ServerPolicy(
        server=server_name,
        default_action=_parse_action(data.get("default_action", "allow"), f"server '{server_name}'.default_action"),
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

    rule_name = data.get("name", "unnamed")
    return ToolRule(
        name=rule_name,
        tools=tools,
        action=_parse_action(data.get("action", "allow"), f"tool_rule '{rule_name}'.action"),
        severity=_parse_severity(data.get("severity", "info"), f"tool_rule '{rule_name}'.severity"),
        reason=data.get("reason", ""),
        block_patterns=data.get("block_patterns", []),
        block_values=data.get("block_values", []),
        allow_paths=data.get("allow_paths", []),
    )


def _parse_response_rule(data: dict[str, Any]) -> ResponseRule:
    """Parse a response rule from YAML data."""
    rule_name = data.get("name", "unnamed")
    return ResponseRule(
        name=rule_name,
        detect_patterns=data.get("detect_patterns", []),
        action=_parse_action(data.get("action", "log"), f"response_rule '{rule_name}'.action"),
        severity=_parse_severity(data.get("severity", "warning"), f"response_rule '{rule_name}'.severity"),
        reason=data.get("reason", ""),
    )
