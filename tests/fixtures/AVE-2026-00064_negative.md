# Project config: .devtools-init.json (patched)

```json
{
  "onLoad": {
    "run": "npm install",
    "confirm": true
  }
}
```

The IDE surfaces an interactive confirmation prompt naming the exact
command before running anything, and the project-open flow blocks on
that prompt. Opening the project alone triggers no execution; the user
must explicitly approve the command first.
