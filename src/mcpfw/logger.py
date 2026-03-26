"""Audit logger for mcpfw.

Logs every MCP message with policy verdicts in JSONL format.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from .parser import MCPMessage
from .policy import Verdict


class AuditLogger:
    """Writes structured audit log entries in JSONL format."""

    def __init__(self, log_path: str | Path | None = None, stderr_summary: bool = True):
        self._file: IO[str] | None = None
        self._stderr_summary = stderr_summary
        self._stats = {"total": 0, "allowed": 0, "blocked": 0, "logged": 0}

        if log_path:
            path = Path(log_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(path, "a", buffering=1)  # line-buffered

    def log_tool_call(
        self,
        server_name: str,
        msg: MCPMessage,
        verdict: Verdict,
    ) -> None:
        """Log a tool call with its policy verdict."""
        self._stats["total"] += 1
        if verdict.is_blocked:
            self._stats["blocked"] += 1
        else:
            self._stats["allowed"] += 1

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "tool_call",
            "server": server_name,
            "tool": msg.tool_name,
            "arguments": msg.tool_arguments,
            "verdict": verdict.action.value,
            "rule": verdict.rule_name,
            "reason": verdict.reason,
            "severity": verdict.severity.value,
        }
        self._write(entry)

        if self._stderr_summary:
            icon = "\u2717" if verdict.is_blocked else "\u2713"
            severity_tag = f" [{verdict.severity.value.upper()}]" if verdict.severity.value != "info" else ""
            print(
                f"[mcpfw] {icon} {msg.tool_name} → {verdict.action.value}{severity_tag}"
                + (f" ({verdict.reason})" if verdict.reason and verdict.is_blocked else ""),
                file=sys.stderr,
            )

    def log_response_scan(
        self,
        server_name: str,
        msg: MCPMessage,
        verdict: Verdict,
    ) -> None:
        """Log a response scan result."""
        if verdict.action.value == "allow" and verdict.rule_name is None:
            return  # don't log clean responses

        self._stats["logged"] += 1

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "response_scan",
            "server": server_name,
            "msg_id": msg.msg_id,
            "verdict": verdict.action.value,
            "rule": verdict.rule_name,
            "reason": verdict.reason,
            "severity": verdict.severity.value,
            "matched_pattern": verdict.matched_pattern,
        }
        self._write(entry)

        if self._stderr_summary:
            print(
                f"[mcpfw] \u26a0 Response flagged: {verdict.reason}",
                file=sys.stderr,
            )

    def log_event(self, event: str, **kwargs: Any) -> None:
        """Log a general event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs,
        }
        self._write(entry)

        if self._stderr_summary and event in ("start", "stop", "error"):
            print(f"[mcpfw] {event}: {kwargs.get('message', '')}", file=sys.stderr)

    def print_stats(self) -> None:
        """Print summary statistics to stderr."""
        print(
            f"[mcpfw] Session stats: {self._stats['total']} tool calls, "
            f"{self._stats['allowed']} allowed, {self._stats['blocked']} blocked, "
            f"{self._stats['logged']} flagged",
            file=sys.stderr,
        )

    def close(self) -> None:
        """Close the log file."""
        if self._file:
            self._file.close()
            self._file = None

    def _write(self, entry: dict[str, Any]) -> None:
        """Write a log entry."""
        if self._file:
            self._file.write(json.dumps(entry) + "\n")
