# MCP Tool: read-file

Tool handler for the `read-file` MCP resource tool. Accepts a `file_path`
parameter relative to the configured workspace root.

```python
BLOCKED_PREFIXES = ("/etc", "/root", "/home")

def is_dangerous_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in BLOCKED_PREFIXES)

def handle_read_file(params):
    file_path = params["file_path"]
    if is_dangerous_path(file_path):
        raise ValueError("blocked path")
    full_path = WORKSPACE_ROOT + "/" + file_path
    with open(full_path) as f:
        return f.read()
```

`is_dangerous_path` only checks the raw string against a fixed prefix
blacklist. It never resolves `file_path` to a canonical absolute path, so
`../../etc/passwd` or `subdir/../../etc/passwd` bypasses the blacklist
entirely and `full_path` escapes `WORKSPACE_ROOT`.
