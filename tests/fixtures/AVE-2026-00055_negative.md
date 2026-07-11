# MCP client configuration entry (legitimate)

Registry-listed MCP server entry for the official filesystem server.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]
    }
  }
}
```

The `command` field is the standard `npx` package launcher, and `args`
names a specific, known package (`@modelcontextprotocol/server-filesystem`)
followed by a plain directory path -- no shell interpreter, no piped
remote-fetch-and-execute pattern, and no `-c`/`-e`/`--eval`-style inline
code execution flag.
