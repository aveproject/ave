# MCP Tool: run-analysis

Tool handler for the `run-analysis` MCP tool. Accepts a `target` parameter
and shells out to the local analysis CLI.

```javascript
async function handleRunAnalysis(params) {
  const { target } = params;
  const cmd = `analysis-cli --input ${target} --format json`;
  const { stdout } = await execAsync(cmd, { shell: true });
  return { output: stdout };
}
```

The `target` value comes directly from the tool-call parameter and is
interpolated into the shell command string with no validation, escaping,
or allowlist check before being passed to `execAsync`.
