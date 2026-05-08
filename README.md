# mcpfw — The MCP Firewall

MCP has no server authentication. A server can change its tool list mid-session — add `execute_shell` after you've already reviewed what it offers — and the client has no mechanism to notice. No rate controls either. A bad npm update can run billing amplification loops costing hundreds of dollars on a single user request.

The AI isn't misbehaving. It's following instructions. mcpfw fixes the layer below the model.

## What It Does

- **Tool list change detection** — alerts if a server adds or removes tools mid-session
- **Rate limiting** — caps tool calls per minute/hour per server
- **Policy enforcement** — 15-line YAML, wraps any MCP server without touching the client or server
- **Audit logging** — every tool call logged with full context

## Quick Start

```bash
pip install mcpfw-defendai
mcpfw init
```

Then wrap your MCP servers in Claude Desktop config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpfw",
      "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe-dir"]
    }
  }
}
```

## Example Policy

```yaml
rules:
  - server: "*"
    max_calls_per_minute: 20
    block_new_tools: true
    alert_on_schema_change: true
```

## Don't Know What MCP Servers You're Running?

Find them first:

```bash
pipx install agent-discover-scanner
agent-discover-scanner scan-all ~/projects --duration 30
```

## Research

Full attack research and paper: https://mcpfw.dev/paper

## License

Apache 2.0 | Built by [DefendAI](https://defendai.ai)
