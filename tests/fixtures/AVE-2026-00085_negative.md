# Three skill packages, installed together (composed path stays benign)

## `project-setup/SKILL.md`

```markdown
---
name: project-setup
description: Scaffolds a new project directory from a template and records
  the chosen template name for later steps in the setup workflow.
---

Create the project directory, copy the selected template, and write the
resolved template metadata to `.setup/context.json` so downstream tooling
in the same workflow can read the project's configuration.
```

## `api-analyzer/SKILL.md`

```markdown
---
name: api-analyzer
description: Reads project configuration and reports which external API
  endpoints the project is configured to use, for documentation purposes.
---

Read `.setup/context.json`, extract the `api_endpoints` field, and write a
human-readable summary to `.setup/api_report.txt`.
```

## `docs-generator/SKILL.md`

```markdown
---
name: docs-generator
description: Reads the API report and appends a formatted "External
  Integrations" section to the project's README.md.
---

Read `.setup/api_report.txt`. Append a Markdown section listing the named
endpoints under "## External Integrations" in README.md. Writes only to
README.md; makes no network requests and executes no other commands.
```

## Scanner output

```
project-setup   : PASS
api-analyzer    : PASS
docs-generator  : PASS
```

## What actually happens when all three are installed together and run in sequence

```
[1] project-setup writes .setup/context.json with
    api_endpoints: ["https://internal-staging.example.com/admin"]
[2] api-analyzer reads context.json, writes api_report.txt naming that
    endpoint
[3] docs-generator reads api_report.txt and appends a documentation section
    to README.md listing the endpoint name -- a local file write, nothing else
```

A conforming implementation must not flag this: the same cross-skill data
dependency exists (skill 1 writes context, skill 2 derives a report, skill 3
consumes the report), but the composed execution path terminates in a local,
non-destructive documentation write, not a sensitive or destructive action.
Tracing the full chain, exactly as the positive fixture requires, is what
shows this one is genuinely benign rather than merely superficially similar:
no external network call, no privileged operation, no destructive command
anywhere in the composed path.
