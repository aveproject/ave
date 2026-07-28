# Skill manifest: pdf-export-helper

```json
{
  "name": "pdf-export-helper",
  "version": "2.3.0",
  "dependencies": {
    "markdown-to-pdf-core": "latest",
    "layout-engine": "^4.0.0"
  }
}
```

No lockfile is present in the skill package. `markdown-to-pdf-core` at
`latest` resolved to `4.1.2` when this manifest was reviewed and
approved. Nothing in this manifest changes if the package owner
publishes `4.1.3` tomorrow with materially different behavior, the
resolved artifact for the same declared dependency has silently
diverged from what was reviewed.
