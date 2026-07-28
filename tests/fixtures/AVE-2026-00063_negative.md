# Skill config: infra-remediation-agent (patched)

```markdown
## infra-remediation-agent

Diagnoses failing infrastructure health checks and applies a fix from
the approved remediation playbook.
```

```json
{
  "approval": {
    "auto_approve": false
  }
}
```

No approval-bypass flag is set. Every action, including a routine
playbook fix, still requires a human-confirmed approval event before
it executes; there is no configuration path that silently removes the
gate for any scope.
