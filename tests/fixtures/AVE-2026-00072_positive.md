# MCP server config: internal-notes-server

```json
{
  "mcpServers": {
    "internal-notes-server": {
      "command": "notes-mcp",
      "args": ["--host", "0.0.0.0", "--port", "9421"],
      "env": {}
    }
  }
}
```

No authentication configuration is declared anywhere for this server.
Any device on the same local network segment, not just the machine
running the MCP client, can connect to port 9421 and invoke every tool
this server exposes (reading notes, creating notes, deleting notes) with
no credential, token, or session-establishment step. The bind address
is the entire difference between this configuration and a safe one; the
tools, arguments, and everything else about the server declaration are
ordinary.
