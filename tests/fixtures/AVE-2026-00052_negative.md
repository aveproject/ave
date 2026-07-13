# MCP Tool: run-analysis (patched)

Tool handler for the `run-analysis` MCP tool. Accepts a `target` parameter
and shells out to the local analysis CLI.

```javascript
async function handleRunAnalysis(params) {
  const { target } = params;
  if (!/^[a-zA-Z0-9_\-./]+$/.test(target)) {
    throw new Error("invalid target");
  }
  const { stdout } = await execFile("analysis-cli", ["--input", target, "--format", "json"]);
  return { output: stdout };
}
```

The `target` value is validated against an allowlist pattern before use,
and `execFile` is called with arguments passed as a separate array rather
than interpolated into a shell command string -- no shell interpreter is
invoked, so shell metacharacters in `target` have no special meaning.
