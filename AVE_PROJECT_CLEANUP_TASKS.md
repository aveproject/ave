# aveproject/ave: cleanup tasks

**For:** a Claude Code session with write access to `aveproject/ave`.
**How this brief was built:** no live browsing access to this repo was available
when writing it. Every task below is grounded in either (a) direct evidence seen
earlier in this project's working session (the live schema JSON, a live record),
or (b) tracked, unresolved items from `AVE_ORG_MOVE_CHECKLIST.md` and
`AVE_V1.1.0_MIGRATION_BRIEF.md`, both of which should already be in this repo or
adjacent to it. Every task therefore opens with a discovery step before any fix;
do not skip discovery on the assumption this brief already knows the current
state, only some of it is confirmed.

**One task, one branch, one PR.** Suggested branch names given per task. Do not
combine tasks into one PR even where they touch the same files; a reviewer
should be able to approve the boilerplate fix without also reviewing the schema
`$id` change.

---

## Task A1: corpus-wide hygiene confirmation

**Branch:** `fix/corpus-hygiene-confirm`

Everything in `AVE_V1.1.0_MIGRATION_BRIEF.md` Sections 4.1-4.5 was confirmed
applied to one sample record (AVE-2026-00028) partway through this project's
session. One record is one data point. Confirm corpus-wide before treating any
of it as closed.

```bash
# vendor-name boilerplate (4.5) - expect zero results
grep -rl "bawbel-scanner\|bawbel scan\b" records/AVE-2026-*.json

# old _mapping field names (4.4) - expect zero results
grep -rl "owasp_mapping\|mitre_atlas_mapping\|nist_ai_rmf_mapping" records/AVE-2026-*.json

# nested duplicate (4.3/4.4) - expect zero results
grep -rl "owasp_mcp_mapping" records/AVE-2026-*.json

# template artifacts (4.1) - expect zero results
grep -rlE '\-{2,}"?\s*$' records/AVE-2026-*.json

# behavioral_vector still holding raw payload text instead of short tags (4.2)
# heuristic: flag any behavioral_vector entry over 40 chars, tags should be short
python3 -c "
import json, glob
for f in sorted(glob.glob('records/AVE-2026-*.json')):
    d = json.load(open(f))
    bv = d.get('behavioral_vector', [])
    long_entries = [t for t in bv if len(t) > 40]
    if long_entries:
        print(f, '-> suspicious long behavioral_vector entries:', long_entries)
"
```

If any command returns results, fix them using the exact instructions already
in `AVE_V1.1.0_MIGRATION_BRIEF.md` Sections 4.1-4.5, not improvised replacements.
If all four commands return clean, this PR is a no-op confirmation; still open
it, with the commands and their clean output in the PR description, so the
confirmation itself is on record.

---

## Task A2: repoint the "AVE Registry" reference URL

**Branch:** `fix/registry-reference-url`

Confirmed still needed as of the last direct check: AVE-2026-00028's
`references` array contained an "AVE Registry" entry pointing at
`https://api.piranha.bawbel.io/records/AVE-2026-00028`. The dependency this was
gated on (`AVE_ORG_MOVE_CHECKLIST.md` Sections 3 and 7, the repo transfer and
the `aveproject.org` DNS/Pages cutover) is confirmed landed. Nothing blocks this
anymore.

```bash
grep -rl "api.piranha.bawbel.io/records" records/AVE-2026-*.json
```

For every match, replace the "AVE Registry" reference's `url` value. Follow
`AVE_V1.1.0_MIGRATION_BRIEF.md` Section 4.6 exactly: confirm the real file path
convention in this repo first (the brief assumed `records/AVE-2026-NNNNN.json`;
verify against `ls records/` before scripting a bulk replace), then set the url
to `https://github.com/aveproject/ave/blob/main/records/AVE-2026-NNNNN.json`
using the confirmed real path.

```bash
# after the fix, expect zero results
grep -rl "api.piranha.bawbel.io/records" records/AVE-2026-*.json
```

---

## Task A3: fix the schema's own `$id`

**Branch:** `fix/schema-id-domain`

**Confirmed still needed, not merely suspected:** the live
`schemas/ave-1.1.0.schema.json` was read directly earlier in this project's
session and its `$id` was `https://ave.bawbel.io/schema/ave-record-1.1.0.schema.json`.
This is the standard's single most canonical, self-referential field, and it
was pointing at a domain that is no longer the standard's home.

```bash
grep -n '"$id"' schemas/ave-1.1.0.schema.json
```

Decide the correct target before editing: does `aveproject/ave-site` serve this
schema file at a stable path on `aveproject.org` (check that repo's Task B
brief first), or should `$id` point at the GitHub raw content URL under this
repo instead? Do not guess; confirm which resolves, then set `$id` to that URL,
not a domain path that returns 404.

```bash
grep -rl "ave.bawbel.io" schemas/ docs/ *.md 2>/dev/null
```

Fix every other match found by the same command in the same PR; they are the
same finding in different files, not separate tasks.

---

## Task A4: land the Cisco skill-scanner crosswalk work

**Branch:** `feat/cisco-crosswalk`

This is drafted, reviewed, and ready in `AVE_CISCO_SKILLSCANNER_CROSSWALK.md`
from earlier in this project's session, but not yet confirmed applied to the
live repo.

```bash
# discovery: are these already applied?
jq -e '.indicators_of_compromise | any(contains("Tag Block"))' records/AVE-2026-00029.json \
  && echo "00029 fix: already applied" || echo "00029 fix: NOT yet applied"
test -f records/AVE-2026-00057.json && echo "00057: exists" || echo "00057: MISSING"
test -f records/AVE-2026-00058.json && echo "00058: exists" || echo "00058: MISSING"
grep -q "Considered and rejected: a .cisco_aitech" AVE_V1.1.0_MIGRATION_BRIEF.md \
  && echo "7.1 decision record: present" || echo "7.1 decision record: MISSING"
```

For whatever discovery shows missing, apply exactly the corresponding part of
`AVE_CISCO_SKILLSCANNER_CROSSWALK.md`: Part 1 (the 00029 IOC addition), Part 2
(the two new records, exactly as drafted, arithmetic already verified), Part 3
(the Section 7.1 decision record explaining why no `cisco_aitech` field was
added). Do not add a `cisco_aitech` field or any structured crosswalk field to
this schema as part of this task; that was a deliberate rejection, not an
oversight, see Part 3 for the reasoning.

Validate per `AVE_CISCO_SKILLSCANNER_CROSSWALK.md`'s own Part 2.3 commands
before opening the PR.

---

## Task A5: governance and licensing files, audit and fill gaps

**Branch:** `chore/governance-files`

Discovery first; do not assume any of these are missing or present.

```bash
ls GOVERNANCE.md LICENSE LICENSE-SPEC CONTRIBUTING.md SECURITY.md 2>&1
```

If `GOVERNANCE.md` is missing or thin: it needs, at minimum, a maintainer role
description, a decision process, a succession clause (what happens if the
maintainer is unavailable for 90 days), and a trademark note stating any
conforming implementation may use the AVE name. This was specified in this
project's TRUST_STRATEGY.md Phase 0 and should not have been lost in the move.

If `LICENSE` and `LICENSE-SPEC` are not split: code (scripts, schema
validators) should be Apache-2.0; the specification text and record content
should be CC BY 4.0. A single blanket license for both is a mismatch with how
mature standards actually license themselves (spec content and implementation
code have different reuse expectations).

If `CONTRIBUTING.md` is missing or does not mention the thin-submission model:
add or update it to explain the draft-record path from
`AVE_V1.1.0_MIGRATION_BRIEF.md` Section 6.1, the eight core fields a
contributor needs versus what's added in review. This is a real adoption
lever; if it is undocumented, nobody submitting a draft record will know it
exists.

If `SECURITY.md` is missing: this repo needs one regardless of the
bawbel-gate `SECURITY.md` already drafted elsewhere in this project, since this
is a different repo with a different scope (vulnerability classification data,
not enforcement software). A minimal version: how to report an error in a
published record (a misclassification is not a security vulnerability in the
traditional sense, but a wrong severity or wrong mitigation strategy on a
published record is a real-world risk if someone acts on it).

Open one PR per file that needs creating or substantively fixing, not one PR
for all four; they have different review stakeholders (governance content
likely needs Saray's own sign-off specifically, licensing may want a second
pair of eyes, CONTRIBUTING is lower-stakes).

---

## Task A6: sweep README and other markdown for stale references

**Branch:** `fix/readme-domain-sweep`

Same finding as Task A3, applied to prose documentation rather than the schema
file.

```bash
grep -rln "bawbel/ave\b\|ave.bawbel.io" --include="*.md" .
```

For every match: replace `bawbel/ave` with `aveproject/ave` and
`ave.bawbel.io` with `aveproject.org`, **except** any reference to
`bawbel/scanner` (or `bawbel-scanner`) or `api.piranha.bawbel.io`, which
correctly stay under `bawbel` - they are Bawbel products implementing or
consuming AVE, not the standard itself. Check label text around any surviving
`bawbel` reference too, not just the URL: if anything describes
`api.piranha.bawbel.io` as neutral standard infrastructure rather than a
Bawbel product, fix the label, that is the more damaging version of this
problem.

```bash
# after the fix
grep -rln "bawbel/ave\b\|ave.bawbel.io" --include="*.md" .
# expect zero, or only occurrences inside historical/decision-record prose
# explicitly discussing the old name (e.g. AVE_V1.1.0_MIGRATION_BRIEF.md
# Section 0's own correction-of-prior-planning text), not live references
```

---

## Task A7: full corpus schema validation

**Branch:** `test/corpus-validation-ci`

Not a content fix; a safety net so none of the above tasks silently broke
something. Run after Tasks A1-A6 have merged, as its own final PR, adding a CI
job if one does not already exist rather than only running this once by hand.

```bash
for f in records/AVE-2026-*.json; do
  python3 -m jsonschema -i "$f" schemas/ave-1.1.0.schema.json || echo "FAILED: $f"
done
```

If this repo does not already have a GitHub Actions workflow running this on
every PR touching `records/` or `schemas/`, add one as part of this task. A
schema-conformance CI gate is table stakes for a standard that expects
external contributions eventually; without it, a bad draft PR merges silently.