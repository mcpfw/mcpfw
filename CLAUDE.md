# CLAUDE.md — mcpfw project context

## What this is
mcpfw is a runtime security gateway for the Model Context Protocol (MCP).
It sits between MCP clients (Claude Desktop, Cursor, VS Code) and MCP servers,
intercepting JSON-RPC messages and enforcing YAML-based security policies.

## Architecture
- `src/mcpfw/wrapper.py` — core stdio proxy (spawns real MCP server, intercepts traffic)
- `src/mcpfw/parser.py` — JSON-RPC message parser
- `src/mcpfw/policy.py` — YAML policy engine (allow/block/log rules)
- `src/mcpfw/logger.py` — JSONL audit logger
- `src/mcpfw/cli.py` — CLI entry point (mcpfw wrap, mcpfw init, mcpfw verify)

## Key commands
- `pip install -e ".[dev]"` — install in dev mode
- `pytest tests/ -v` — run tests (17 tests, all should pass)
- `mcpfw init` — create default policy at ~/.mcpfw/policy.yaml
- `mcpfw wrap -- <server_command>` — wrap an MCP server

## Style
- Python 3.10+, type hints, dataclasses
- No external deps except PyYAML
- Tests in tests/ using pytest
