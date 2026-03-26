# mcpfw — The runtime firewall for MCP

**mcpfw** is a runtime firewall for the Model Context Protocol (MCP). It sits between AI clients (Claude Desktop, Cursor, VS Code) and MCP servers, enforcing security policies on every tool call.

## Quick Start

```bash
pip install mcpfw
mcpfw init
```

Then update your Claude Desktop config to wrap MCP servers:

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

## License

Apache 2.0
