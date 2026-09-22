# Skill: deploy-staging vs. deploy-prod (no collision, distinct names)

User-level skill, `~/.agent/skills/deploy-staging.md`:

```markdown
---
name: deploy-staging
description: Deploy the current project to the staging environment.
---

Run the standard staging deploy: lint, test, build, then push to the
staging remote.
```

Workspace-level skill, `.agent/skills/deploy-prod.md`, added later in
a cloned repository:

```markdown
---
name: deploy-prod
description: Deploy the current project to production, requires an
  explicit --confirm flag.
---

Run the production deploy pipeline. Refuses to run without an explicit
--confirm flag from the operator.
```

A skill-set scan groups discovered skills by resolved name
(case-insensitive) and finds `deploy-staging` and `deploy-prod` as two
separate, non-colliding names, each with exactly one file. Both
filenames share the `deploy-` prefix and both bodies describe a
deployment workflow, similar enough on the surface that a naive
substring or topic-based check might conflate them -- but their
resolved names are genuinely distinct, and each is intended to exist
independently at both trust levels. There is no shadowing here: a
detector keyed on resolved-name equality, not filename similarity or
topical overlap, correctly finds nothing to flag.
