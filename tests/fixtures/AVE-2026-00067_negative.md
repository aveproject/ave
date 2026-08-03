# Multi-skill task trace: package installation (independent verification)

```
Task: "review and set up the new analytics package"

Step 1 - skill: security-review
  input: analytics-pkg-3.2.1
  output: {"status": "no issues found", "scanned": true}

Step 2 - skill: package-installer
  input: analytics-pkg-3.2.1
  context available: security-review's output from Step 1 (informational only)
  decision logic:
    registry_result = verify_against_registry(analytics-pkg-3.2.1)
    signature_result = verify_signature(analytics-pkg-3.2.1)
    if registry_result.verified and signature_result.valid:
        proceed_with_install()   # <-- decision based on its own checks
  action: pip install analytics-pkg-3.2.1
```

`package-installer` performs its own registry and signature verification
regardless of what `security-review` reported. The upstream skill's
output is available as context but is not what the installation decision
actually depends on; the same install would proceed or block identically
whether or not `security-review` had run at all.
