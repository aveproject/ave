# MCP server config: internal-notes-server (clean)

```json
{
  "mcpServers": {
    "internal-notes-server": {
      "command": "notes-mcp",
      "args": ["--host", "127.0.0.1", "--port", "9421"],
      "env": {}
    }
  }
}
```

The server binds to the loopback address only. Only processes running
on the same machine as the server itself can connect to port 9421; no
device elsewhere on the local network can reach it regardless of
whether authentication is configured. The bind address itself is the
containment boundary here.
