"""mcpfw CLI — The runtime firewall for Model Context Protocol."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .logger import AuditLogger
from .policy import load_policy
from .wrapper import MCPFirewall


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcpfw",
        description="The runtime firewall for Model Context Protocol (MCP)",
    )
    parser.add_argument("--version", action="version", version=f"mcpfw {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # mcpfw wrap — the main command
    wrap_parser = subparsers.add_parser(
        "wrap",
        help="Wrap an MCP server with firewall enforcement",
        description=(
            "Wraps an MCP server process, intercepting all JSON-RPC messages "
            "and enforcing policies before forwarding."
        ),
    )
    wrap_parser.add_argument(
        "--policy",
        type=str,
        default=str(Path.home() / ".mcpfw" / "policy.yaml"),
        help="Path to the policy YAML file (default: ~/.mcpfw/policy.yaml)",
    )
    wrap_parser.add_argument(
        "--server-name",
        type=str,
        default=None,
        help="Name of the MCP server (for policy matching and logging)",
    )
    wrap_parser.add_argument(
        "--log",
        type=str,
        default=str(Path.home() / ".mcpfw" / "audit.jsonl"),
        help="Path to the audit log file (default: ~/.mcpfw/audit.jsonl)",
    )
    wrap_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stderr output (still writes to log file)",
    )
    wrap_parser.add_argument(
        "server_command",
        nargs=argparse.REMAINDER,
        help="The MCP server command to wrap (after --)",
    )

    # mcpfw init — create a default policy file
    init_parser = subparsers.add_parser(
        "init",
        help="Create a default policy file",
    )
    init_parser.add_argument(
        "--path",
        type=str,
        default=str(Path.home() / ".mcpfw" / "policy.yaml"),
        help="Path to create the policy file (default: ~/.mcpfw/policy.yaml)",
    )

    # mcpfw verify — check a policy file for errors
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a policy file is valid",
    )
    verify_parser.add_argument(
        "policy_file",
        type=str,
        help="Path to the policy file to verify",
    )

    args = parser.parse_args()

    if args.command == "wrap":
        _cmd_wrap(args)
    elif args.command == "init":
        _cmd_init(args)
    elif args.command == "verify":
        _cmd_verify(args)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_wrap(args: argparse.Namespace) -> None:
    """Run the mcpfw wrapper."""
    # Parse server command — handle the -- separator
    server_cmd = args.server_command
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]

    if not server_cmd:
        print("[mcpfw] Error: no server command specified.", file=sys.stderr)
        print("[mcpfw] Usage: mcpfw wrap --policy policy.yaml -- npx @server/package", file=sys.stderr)
        sys.exit(1)

    # Derive server name from command if not specified
    server_name = args.server_name
    if server_name is None:
        # Try to extract a meaningful name from the command
        for part in server_cmd:
            if part.startswith("@") or (not part.startswith("-") and "/" in part):
                server_name = part
                break
        if server_name is None:
            server_name = server_cmd[0]

    # Load policy
    policy = load_policy(args.policy)

    # Set up audit logger
    logger = AuditLogger(
        log_path=args.log,
        stderr_summary=not args.quiet,
    )

    # Create and run the firewall
    firewall = MCPFirewall(
        server_command=server_cmd,
        policy=policy,
        server_name=server_name,
        audit_logger=logger,
    )

    try:
        exit_code = asyncio.run(firewall.run())
    except KeyboardInterrupt:
        logger.print_stats()
        exit_code = 0

    sys.exit(exit_code)


def _cmd_init(args: argparse.Namespace) -> None:
    """Create a default policy file."""
    path = Path(args.path)

    if path.exists():
        print(f"[mcpfw] Policy file already exists: {path}", file=sys.stderr)
        print("[mcpfw] Delete it first or specify a different path.", file=sys.stderr)
        sys.exit(1)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_POLICY)

    print(f"[mcpfw] Created default policy: {path}", file=sys.stderr)
    print("[mcpfw] Edit this file to customize your firewall rules.", file=sys.stderr)


def _cmd_verify(args: argparse.Namespace) -> None:
    """Verify a policy file."""
    path = Path(args.policy_file)
    if not path.exists():
        print(f"[mcpfw] Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        policy = load_policy(path)
        server_count = len(policy.server_policies)
        rule_count = sum(len(sp.tool_rules) for sp in policy.server_policies)
        response_rule_count = (
            len(policy.global_response_rules)
            + sum(len(sp.response_rules) for sp in policy.server_policies)
        )
        print(f"[mcpfw] Policy is valid.", file=sys.stderr)
        print(f"  Version: {policy.version}", file=sys.stderr)
        print(f"  Default action: {policy.default_action.value}", file=sys.stderr)
        print(f"  Server policies: {server_count}", file=sys.stderr)
        print(f"  Tool rules: {rule_count}", file=sys.stderr)
        print(f"  Response rules: {response_rule_count}", file=sys.stderr)
    except Exception as e:
        print(f"[mcpfw] Error: invalid policy file: {e}", file=sys.stderr)
        sys.exit(1)


DEFAULT_POLICY = """\
# mcpfw policy — The runtime firewall for MCP
# https://mcpfw.dev
#
# This policy file controls what MCP tool calls are allowed, blocked,
# or flagged. Edit it to match your security requirements.

version: 1
default_action: allow

# Global response scanning rules
# These apply to ALL MCP server responses regardless of server
response_rules:
  - name: detect-ssn
    detect_patterns:
      - "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
    action: log
    severity: critical
    reason: "Possible SSN detected in MCP response"

  - name: detect-api-key
    detect_patterns:
      - "(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\\\\s*[=:]\\\\s*\\\\S+"
    action: log
    severity: warning
    reason: "Possible API key or secret detected in MCP response"

# Per-server policies
servers:
  # Filesystem MCP server — restrict to safe directories
  - server: "@modelcontextprotocol/server-filesystem"
    default_action: allow
    blocked_tools:
      - write_file
      - create_directory
      - move_file
    tool_rules:
      - name: restrict-paths
        tools: ["read_file", "read_text_file", "list_directory", "search_files"]
        allow_paths:
          - /tmp/
          - /home/
        reason: "File access restricted to /tmp/ and /home/"

  # Example: block all tools on an untrusted server
  # - server: "untrusted-mcp-server"
  #   default_action: block

  # Example: allow only specific tools
  # - server: "@some/mcp-server"
  #   allowed_tools:
  #     - safe_tool_1
  #     - safe_tool_2
"""


if __name__ == "__main__":
    main()
