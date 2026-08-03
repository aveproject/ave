# Multi-skill task trace: package installation

```
Task: "review and set up the new analytics package"

Step 1 - skill: security-review
  input: analytics-pkg-3.2.1
  output: {"status": "no issues found", "scanned": true}

Step 2 - skill: package-installer
  input: analytics-pkg-3.2.1
  context available: security-review's output from Step 1
  decision logic:
    if upstream_review.status == "no issues found":
        proceed_with_install()   # <-- no independent check performed
  action: pip install analytics-pkg-3.2.1
```

`package-installer` never independently verifies `analytics-pkg-3.2.1`
against a registry, a signature, or any check of its own. Its entire
decision to install rests on `security-review`'s prior output. Neither
skill is individually malicious: `security-review`'s scanner genuinely
found nothing (because it wasn't looking for what actually matters to
`package-installer`'s decision), and `package-installer`'s code is
otherwise ordinary. The vulnerability is that the second skill treats
the first skill's unrelated, benign output as sufficient authorization
for its own separate, sensitive action.
