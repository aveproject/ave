# MCP Tool: read-file (patched)

Tool handler for the `read-file` MCP resource tool. Accepts a `file_path`
parameter relative to the configured workspace root.

```python
import os

def handle_read_file(params):
    file_path = params["file_path"]
    full_path = os.path.realpath(os.path.join(WORKSPACE_ROOT, file_path))
    if not full_path.startswith(os.path.realpath(WORKSPACE_ROOT) + os.sep):
        raise ValueError("path escapes workspace root")
    with open(full_path) as f:
        return f.read()
```

`file_path` is joined onto `WORKSPACE_ROOT` and resolved to its canonical
absolute form with `os.path.realpath` before use. The result is then
checked for containment against the resolved root itself, not a fixed
denylist -- any `../` segments are collapsed by `realpath` before the
containment check runs, so traversal sequences cannot escape the root.
