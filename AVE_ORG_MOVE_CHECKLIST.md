# AVE_ORG_MOVE_CHECKLIST.md

Moving `bawbel/ave` and `bawbel/ave-site` to a new, neutral GitHub organization.
Two repos, same names, owner changes only; no renames in this pass (see
Section 0). PiranhaDB's code move is out of scope here, low urgency (see
ARCHITECTURE.md's revised PiranhaDB card); do not bundle it into this move.

## Status

**[DONE, confirmed]** Section 3 (transfer): `aveproject/ave` and
`aveproject/ave-site` are live under the new org.
**[DONE, confirmed]** Section 7 (Pages/DNS): `aveproject.org` resolves and serves
`ave-site`.

Confirmed dependents now unblocked, not yet independently confirmed executed:
- Section 5.1 (schema `$id`): safe to apply now; not yet confirmed done against
  the live `schemas/ave-1.1.0.schema.json` file. The copy checked two turns
  before this status update still had the old `ave.bawbel.io` `$id`.
- `AVE_V1.1.0_MIGRATION_BRIEF.md` Section 4.6 (repoint "AVE Registry" reference
  URL across all records): same, dependency satisfied, execution not yet
  confirmed. Check a live record before assuming this ran.
- `schema.html` (the site's own schema reference page): confirmed done, applied
  directly, domain and repo links now point at `aveproject.org` and
  `github.com/aveproject/ave`. `bawbel/scanner` and `bawbel.io` company
  references correctly left unchanged; see that file's own history for the
  exact diff.

Sections 1, 2, 4, 6 below remain as the historical record of how the move was
planned and executed; Sections 3 and 7 are left in their original form for the
same reason, not because they are still pending.

## 0. Decisions to lock before touching anything

- **Org name: confirmed.** `aveproject` was available and is created on GitHub.
  This is final; the `ave-standard`/`agentic-ave` fallback names considered
  earlier are not needed and are not reserved.
- **No renames this pass.** `aveproject/ave` and `aveproject/ave-site` keep
  their current repo names, only the owner changes. One variable changing at a time is the
  lowest-risk version of this move; GitHub's redirect guarantees are best
  understood for exactly this case.
- **PiranhaDB stays put for now.** Its code can move into `aveproject/piranhadb`
  later,
  its own low-stakes move; its hosted instance and domain stay with Bawbel
  regardless. Not part of this checklist.
- **After OWASP outreach, no second repo move is expected.** OWASP's Project
  Committee guidance explicitly supports project code living outside
  `github.com/OWASP`; what OWASP creates is a separate, thin `www-project-ave`
  landing-page repo inside their org that links out to wherever the real repo
  lives. Plan for one move, not two.

## 1. Fix the `ave-site` fetch first, before any transfer

`ave.bawbel.io` is served by `ave-site`, which fetches content from
`https://github.com/bawbel/ave`. This is the one dependency that can silently
break depending on *how* it fetches, so resolve it before transferring anything:

1. Open `ave-site`'s source and find where it references `bawbel/ave`. Determine
   the fetch mechanism:
   - `git clone` / `git fetch` against the repo URL: covered by GitHub's
     documented redirect, survives a transfer, but still update it (see below,
     don't rely on a redirect for your own public site's build).
   - `raw.githubusercontent.com/bawbel/ave/...` or `api.github.com/repos/bawbel/ave/...`:
     **not covered by GitHub's documented redirect guarantee.** Treat as will
     break. Update the hardcoded owner now.
2. Update the owner string to `aveproject` in the same change, even before the
   transfer happens; a build pointed at the future correct location fails
   loudly and safely until the transfer completes, rather than succeeding today
   and breaking silently after.
3. Run a local build of `ave-site` against the current `bawbel/ave` content to
   confirm the fetch path is understood correctly before moving on. If the
   fetch mechanism can't be determined confidently from the code, stop and
   trace it rather than guessing; this is the item most likely to fail silently.

## 2. Pre-move inventory (both repos)

- [ ] `grep -r "bawbel/ave" .` and `grep -r "raw.githubusercontent.com/bawbel"
      .` across `ave` and `ave-site`: README, CONTRIBUTING, package metadata
      (`pyproject.toml` / `package.json` `repository`/`homepage` fields), CI
      workflow files, any Pages config.
- [ ] `ave.bawbel.io` DNS/CNAME configuration: confirmed it is `ave-site`'s
      domain, not GitHub Pages on the `ave` repo itself (per your answer, it is
      `ave-site`-served; note this so nobody reflexively reconfigures GitHub
      Pages custom-domain settings that don't apply here).
- [ ] Any org-level Actions secrets/variables the `ave` or `ave-site` workflows
      use (these do not transfer with the repo; must be recreated at the new
      location).
- [ ] Any GitHub App or third-party integration installed at the `bawbel` org
      level that touches either repo (deploy hooks, bots).
- [ ] Current collaborator/team list on both repos (an org-to-personal-account
      transfer drops read-only collaborators automatically per GitHub's docs; an
      org-to-org transfer needs `aveproject`'s teams set up to receive them,
      if using teams).
- [ ] Confirm no PiranhaDB deploy trigger or CI process watches `bawbel/ave`
      directly (ARCHITECTURE.md's PiranhaDB card: "code changes come from the
      `ave` repo," that pointer needs updating too, tracked separately since
      PiranhaDB itself isn't moving in this pass).

## 3. Transfer, in order

1. `aveproject` already exists (Section 0); no creation step needed here.
2. Transfer `ave` first: repo Settings -> General -> Danger Zone -> Transfer
   ownership. Target `aveproject`. Do not rename during transfer.
3. Transfer `ave-site` the same way, same org.
4. Do not create a new repo at `bawbel/ave` or `bawbel/ave-site` afterward, ever.
   GitHub's redirect is permanently and irreversibly deleted the moment anything
   is created at the old location; this is the single mistake in this whole
   process that cannot be undone.

## 4. Immediately after transfer

- [ ] `git remote set-url origin <new-url>` on every local clone of both repos;
      don't rely on the redirect for ongoing work.
- [ ] Recreate any org-level Actions secrets/variables identified in Section 2
      at `aveproject`.
- [ ] Reconnect `ave-site`'s deploy pipeline (wherever it builds/deploys from)
      to the new repo location; confirm `ave.bawbel.io` rebuilds correctly from
      the new source.
- [ ] Re-add any collaborators lost in the transfer (Section 2 inventory).
- [ ] Update the `repository`/`homepage` fields in package metadata for the
      next release of anything published from `ave` (schemas, if packaged).
- [ ] Update README, GOVERNANCE.md, CONTRIBUTING.md, and any badges inside both
      repos to the new canonical URLs; don't leave your own docs depending on
      the redirect.

## 5. Sweep the wider Bawbel documentation set

Search DESIGN.md, ARCHITECTURE.md, IMPLEMENTATION_PLAN.md,
BAWBEL_GATE_MITIGATIONS_SPEC.md, AVE_V1.1.0_MIGRATION_BRIEF.md, TRUST_STRATEGY.md,
`ave`'s own README/CONTRIBUTING/SECURITY, and bawbel-gate's README for the literal
strings `bawbel/ave` and `ave.bawbel.io`.

**Confirmed live in README and other markdown files, checked directly, not just
searched for.** Two of the four common table entries need to change, two are
correct as-is; do not blind-replace every occurrence of `bawbel`, that would break
the two that are supposed to stay:

| Current | Change? | Target |
|---|---|---|
| `bawbel/ave` | **yes** | `aveproject/ave` |
| `ave.bawbel.io` | **yes** | `aveproject.org` (only once Section 7 below has landed and DNS resolves; do not point docs at a domain that doesn't serve yet) |
| `bawbel/scanner` (bawbel-scanner) | **no** | stays under `bawbel`. It is a Bawbel product implementing AVE (Layer 2), not the standard itself. |
| `api.piranha.bawbel.io` | **no** | stays under `bawbel`. PiranhaDB is Bawbel's commercial threat-intel product (Layer 3b); this is the existing Section 6 decision, restated here because it is exactly the row someone doing a fast find-and-replace is most likely to break by accident. |

For the two rows that stay, also check their *label text*, not just their URL:
if either is described anywhere as neutral standard infrastructure (e.g. "the AVE
reference API") rather than as a Bawbel product, fix the label. A correct URL
next to an incorrect label is the more damaging version of this problem.

### 5.1 The schema's own `$id` (unblocked, apply now)

`schemas/ave-1.1.0.schema.json`'s `$id` was
`https://ave.bawbel.io/schema/ave-record-1.1.0.schema.json`. Same class of
finding as the table above, in the standard's single most canonical,
self-referential field. Section 7 has landed and `aveproject.org` resolves, so
the earlier "wait for DNS" condition on this fix no longer applies; run it now.

```bash
grep -rl "ave.bawbel.io" schemas/ docs/ *.md
```

New `$id`: `https://aveproject.org/schema/ave-record-1.1.0.schema.json`, if
`ave-site` serves the schema file at that path; otherwise use the GitHub raw
content URL under `aveproject/ave` instead of a domain path that doesn't
resolve. Confirm which before writing the new value, don't assume.

## 6. Do not touch, this pass

- PiranhaDB's code repository (`bawbel/piranha-api` or wherever it currently
  lives): stays where it is. Moving it is a future, separate, low-stakes change
  (ARCHITECTURE.md's revised PiranhaDB card explains why it's decoupled from
  this move).
- The hosted instance at `api.piranha.bawbel.io`: domain and billing stay with
  Bawbel; this checklist does not touch infrastructure ownership, only the
  standard's own repos.
- Any already-published external links (Slack `#introductions`, Sam Stepanyan's
  reply thread): these are protected by the redirect as long as Section 3, item
  4 is honored. Nothing to do here except not break the redirect later.
- `aveproject/ave-reference-api`: not created this pass. No code exists for it yet;
  ARCHITECTURE.md already marks it `PLANNED`. See Section 8 for the actual, cheaper
  fix to the neutrality gap this would have been reached for.

## 7. Serve `aveproject.org` from `ave-site` via GitHub Pages

One repo, no new repo needed. `ave-site` gets the custom domain directly; GitHub
Pages does not require a repo named `<org>.github.io` to serve a custom domain,
that special name only matters for the free `*.github.io` URL with zero DNS setup.
Since a custom domain is being attached anyway, any repo with Pages enabled works.

Do this after the Section 3 transfer has landed, so `ave-site` is already sitting
in its final home before DNS is pointed at it.

### 7.1 DNS records in Namecheap (Advanced DNS tab, `aveproject.org`)

Root domain requires **A records, not a CNAME**; CNAME is not valid at a zone
apex per DNS spec, which is why GitHub's own docs specify A records for apex
domains. CNAME is only for the `www` subdomain.

| Type | Host | Value |
|---|---|---|
| A | `@` | `185.199.108.153` |
| A | `@` | `185.199.109.153` |
| A | `@` | `185.199.110.153` |
| A | `@` | `185.199.111.153` |
| CNAME | `www` | `aveproject.github.io` |

The CNAME target is always `<org>.github.io` regardless of which specific repo
is serving the content; GitHub's edge resolves it from the `CNAME` file inside
whichever repo has the custom domain configured (Section 7.2), so this is
correct even though `ave-site` is not named `aveproject.github.io`.

### 7.2 GitHub Pages configuration, in the `ave-site` repo

1. Settings -> Pages -> Custom domain -> enter `aveproject.org`. This commits a
   `CNAME` file to the repo automatically; do not hand-author one, let GitHub do
   it, to avoid a mismatch between the file and the Pages setting.
2. Wait for DNS propagation. GitHub's Pages settings page shows a DNS check
   status; do not proceed to step 3 until it shows resolved.
3. Once resolved, enable **Enforce HTTPS**. Do not enable it before propagation
   completes; it will fail certificate issuance and need to be retried, not a
   dangerous failure but a wasted round trip.

### 7.3 Preserve the old subdomain

Add a redirect (or note to add one later) from `ave.bawbel.io` to `aveproject.org`
in whatever DNS/hosting controls the `bawbel.io` zone. Same link-preservation
logic as the GitHub repo transfer redirect (Section 3, item 4): anything already
circulating with the old `ave.bawbel.io` link should not go dead.

## 8. Fix the "AVE Registry" reference URL in every record (unblocked, ready to run)

Every AVE record's `references` array carries an "AVE Registry" entry pointing at
`https://api.piranha.bawbel.io/records/AVE-2026-XXXXX`. This is not a hosting
detail; it is the standard's own published data citing a Bawbel-owned,
non-neutral domain as its own canonical registry URL, in every record. Same class
of problem as the vendor-name boilerplate already fixed in
`AVE_V1.1.0_MIGRATION_BRIEF.md` Section 4.5, one layer lower: not prose naming a
vendor, a citation URL baked into the data.

This is tracked in full, with the exact fix and validation steps, as
Section 4.6 in `AVE_V1.1.0_MIGRATION_BRIEF.md`. Its dependency, Section 7 above,
has landed; run it now. Not yet independently confirmed executed against the
live corpus as of this update, check a record before assuming it ran.