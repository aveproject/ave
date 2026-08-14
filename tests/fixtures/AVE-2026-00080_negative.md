# Multi-agent trace: code-review pipeline, coder agent retry (credential-verified)

Orchestrator invokes `coder-agent` at routing slot `agents[2]` to apply
a patch. The call times out and the orchestrator retries at the same
slot.

```
agents[2] call #1: apply_patch(diff_a), session_token=tok_9f3a...
  -> TIMEOUT after 30s

[retry] agents[2] call #2: apply_patch(diff_a), session_token=tok_9f3a...
  orchestrator verifies session_token matches the credential issued to
  coder-agent at pipeline start before accepting the response
  response: { "status": "applied", "commit": "a1b2c3d" }

orchestrator accepts the response only after the session_token
verification succeeds, forwards the commit reference downstream.
```

The retry re-validates the same session-scoped credential that was
bound to `coder-agent` at the start of the pipeline before accepting
the post-retry response -- identity is not inferred from routing
position alone. Had a different process responded at `agents[2]` with
a mismatched or missing token, the orchestrator's own credential check
would have rejected it rather than silently forwarding it downstream.
There is no identity gap here to flag.
