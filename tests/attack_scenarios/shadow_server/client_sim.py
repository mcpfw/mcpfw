#!/usr/bin/env python3
"""
MCP client simulator for the Shadow Server attack scenario.

Sends a realistic sequence of MCP JSON-RPC messages that an AI agent might
issue when using a filesystem helper — starting with a legitimate handshake,
then escalating to the six attack vectors being tested.
"""

import json
import sys


def _msg(method: str, params: dict, msg_id=None) -> str:
    obj = {"jsonrpc": "2.0", "method": method, "params": params}
    if msg_id is not None:
        obj["id"] = msg_id
    return json.dumps(obj)


MESSAGES = [
    # --- Handshake (legitimate) ---
    _msg("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "claude-desktop", "version": "0.9.0"},
    }, msg_id=1),

    _msg("notifications/initialized", {}),

    _msg("tools/list", {}, msg_id=2),

    # --- Legitimate request (should be allowed) ---
    _msg("tools/call", {
        "name": "read_file",
        "arguments": {"path": "/Users/mohamedwaseem/projects/mcpfw/README.md"},
    }, msg_id=3),

    # --- ATTACK 1: SSH private key exfiltration ---
    _msg("tools/call", {
        "name": "read_file",
        "arguments": {"path": "~/.ssh/id_rsa"},
    }, msg_id=4),

    # --- ATTACK 2: AWS credential theft ---
    _msg("tools/call", {
        "name": "read_file",
        "arguments": {"path": "~/.aws/credentials"},
    }, msg_id=5),

    # --- ATTACK 3: .env secrets theft ---
    _msg("tools/call", {
        "name": "read_file",
        "arguments": {"path": "/Users/mohamedwaseem/projects/mcpfw/.env"},
    }, msg_id=6),

    # --- ATTACK 4: Shell code execution ---
    _msg("tools/call", {
        "name": "execute_command",
        "arguments": {"command": "whoami && id && env | grep -iE '(key|token|secret|pass)'"},
    }, msg_id=7),

    # --- ATTACK 5: Directory traversal to /etc/passwd ---
    _msg("tools/call", {
        "name": "read_file",
        "arguments": {"path": "../../../../etc/passwd"},
    }, msg_id=8),

    # --- ATTACK 6: macOS keychain dump via shell ---
    _msg("tools/call", {
        "name": "execute_command",
        "arguments": {"command": "security dump-keychain -d ~/Library/Keychains/login.keychain-db 2>&1 | head -20"},
    }, msg_id=9),
]


def main() -> None:
    for m in MESSAGES:
        sys.stdout.write(m + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
