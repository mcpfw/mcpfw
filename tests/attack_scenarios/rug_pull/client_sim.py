#!/usr/bin/env python3
"""
MCP client simulator for the Rug Pull attack scenario.

Mimics an AI agent that:
  1. Initializes the session and discovers tools (Phase 1 — benign list).
  2. Makes two legitimate calls to establish the server as "trusted".
  3. Re-lists tools to pick up any changes (Phase 2 — rug pull activated).
  4. Calls the newly appeared execute_shell and read_file tools.
  5. Calls the mutated search_web, which now embeds a prompt-injection payload.
"""

import json
import sys


def _msg(method: str, params: dict, msg_id=None) -> str:
    obj = {"jsonrpc": "2.0", "method": method, "params": params}
    if msg_id is not None:
        obj["id"] = msg_id
    return json.dumps(obj)


MESSAGES = [
    # ── Phase 1: trust establishment ─────────────────────────────────────────
    _msg("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "claude-desktop", "version": "0.9.0"},
    }, msg_id=1),

    _msg("notifications/initialized", {}),

    # Discover the initial (benign) tool list
    _msg("tools/list", {}, msg_id=2),

    # Legitimate call #1 — crosses phase boundary after this
    _msg("tools/call", {
        "name": "search_web",
        "arguments": {"query": "latest developments in AI safety"},
    }, msg_id=3),

    # Legitimate call #2 — rug pull activates after this call
    _msg("tools/call", {
        "name": "get_weather",
        "arguments": {"location": "San Francisco"},
    }, msg_id=4),

    # ── Phase 2: rug pull activated ───────────────────────────────────────────

    # Re-discover tools — server now advertises execute_shell + read_file
    _msg("tools/list", {}, msg_id=5),

    # ATTACK 1: Use newly appeared execute_shell (was NOT in original tool list)
    _msg("tools/call", {
        "name": "execute_shell",
        "arguments": {"command": "whoami && id && cat ~/.ssh/id_rsa 2>/dev/null || echo '(no key)'"},
    }, msg_id=6),

    # ATTACK 2: read_file also newly appeared — grab AWS creds
    _msg("tools/call", {
        "name": "read_file",
        "arguments": {"path": "~/.aws/credentials"},
    }, msg_id=7),

    # ATTACK 3: Call the *original* search_web — now mutated to inject
    # a prompt-injection payload + leak env vars in the response.
    _msg("tools/call", {
        "name": "search_web",
        "arguments": {"query": "how to use MCP safely"},
    }, msg_id=8),
]


def main() -> None:
    for m in MESSAGES:
        sys.stdout.write(m + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
