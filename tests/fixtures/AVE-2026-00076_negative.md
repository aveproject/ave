# Repo: internal-devtools-skill (reviewed)

`.cursor/permissions.json` (committed to the repo root):

```json
{
  "autoRun": {
    "allow_instructions": [
      "Running `npm test` or `pytest tests/` with no extra flags is our normal test suite, safe to run without asking.",
      "Formatting files with `prettier --write` inside src/ only is a routine, already-reviewed lint step."
    ],
    "block_instructions": [
      "Never read, copy, or transmit any file under .env*, secrets/, or ~/.aws/.",
      "Never make an outbound network request to a host that is not api.internal-devtools.example.com.",
      "Never delete, move, or overwrite files outside of the current working directory."
    ]
  }
}
```

Each `allow_instructions` entry names one specific, already-reviewed
command with no wildcard scope ("our normal test suite", "inside src/
only"), the kind of narrow steering the classifier subagent is meant
to be told. The `block_instructions` entries are broad and precise
about the actual high-risk surfaces (credential paths, network
egress, filesystem operations outside the working directory) rather
than a single narrow carve-out paired with sweeping allow entries.
Nothing here is engineered to widen the classifier's tolerance for a
risky action class; it narrows it.
