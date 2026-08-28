# Scaling and governance

How AVE handles growth, versioning, and correction as the corpus and its
review process scale. Written at 59 records, deliberately, not after
scale made it urgent.

## 1. Record-growth discipline

A new AVE record requires a genuinely distinct behavioral mechanism, not
an organizational wrapper around coverage that already exists.

**The precedent this guards against, stated directly.** MITRE's CWE
version 4.19 added twelve new entries. Per independent analysis, zero
described actual weaknesses; all twelve were organizational containers
mirroring OWASP's Top Ten 2025 categories. The same release had 903
entries with "major changes," overwhelmingly metadata cleanup rather
than substantive content. This is documented behavior in the taxonomy
AVE is closest in kind to, not a hypothetical risk. AVE is small enough
right now that this policy is cheap to hold; it gets expensive to
introduce after the fact.

**The mechanical test** for whether something is a genuine new class or
a mutation of an existing one is owned by a separate, dedicated policy
(tracked in its own issue, credited to the community member who raised
it), not restated here. This document states the principle the test
serves.

**Named anti-pattern**: a record whose entire content is "this other
framework's category, applied to agentic AI" is not a record. A record
earns its place with the same evidentiary bar as every other AVE record,
a real disclosed incident, a real CVE, real published research describing
an actual mechanism, not a cross-reference to another taxonomy's name.

**Review authority**: currently one maintainer, matching CWE's own actual
practice (MITRE's team, not the community, moves submissions through
review) more closely than it might appear. This is the current state,
not the permanent one; a second maintainer with real review authority is
a tracked, active goal, not an afterthought.

## 2. Schema versioning policy

The pattern already in practice, stated as policy so it doesn't depend on
being reverse-engineered from file names.

**The alias, always current**: `schema/ave-record.schema.json` and
`dist/ave-records-latest.json`. These update in place with every change.

**Frozen versioned snapshots, permanent once published**:
`schema/ave-record-X.Y.Z.schema.json` and `dist/ave-records-vX.Y.Z.json`.
Never edited retroactively, including typo fixes; a correction ships in
the next version, not a silent edit to a version already published and
potentially already depended on by an implementer who pinned to it.

**Version bump rules**:

- Additive, optional field: minor bump (1.1 to 1.2).
- Removing or renaming a required field, or changing an existing field's
  meaning: major bump (1.x to 2.0).

Every record must validate against the schema version it declares in its
own `schema_version` field, enforced in CI.

## 3. Deprecation policy

Modeled directly on CVE's own approach: a rejected or superseded entry is
never deleted, stays permanently resolvable, with a stated reason.

**No published `ave_id` is ever deleted or reused.** Hard rule. An
implementer or a citation that already depends on an ID must never find
it silently gone.

**`status` gains values beyond `active`**:

- `deprecated`: superseded by better understanding of the same class.
  Content stays, a note explains why it's no longer primary.
- `merged`: a genuine duplicate or sub-case of another record. Adds
  `merged_into`, pointing at the surviving `ave_id`. The merged record's
  own content and ID remain permanently resolvable.
- `rejected`: found invalid, not a real distinct class. Adds
  `rejection_reason`. Stays resolvable, matching CVE's own REJECT state.

**Implementation note**: the `status` enum expansion and the
`merged_into`/`rejection_reason` fields are a real schema change, tracked
separately as part of a future version bump (alongside `owasp_ast`, see
`AVE_V1.1.0_MIGRATION_BRIEF.md` Section 7.0), not implied to already exist
by this policy document. This section states the policy the schema change
will implement, it does not implement it.

## 4. Crosswalk numbering caution

External frameworks still being drafted (OWASP's MCP Top 10 has not
been formally ratified as of this writing) get independently
interpreted by every project that adopts them early. Two projects can
both number their own categories MCP01 through MCP10 and mean entirely
different things by the same number, confirmed directly during the
Ramparts crosswalk (issue #138): Ramparts' MCP03 is Excessive Agency,
AVE's MCP03 is Tool Poisoning, unrelated categories sharing a number by
coincidence, not agreement.

**Any crosswalk to an external tool's own OWASP MCP Top 10 tagging
must match by category meaning, not by tag number.** Matching by number
alone will silently produce wrong pairings whenever the external
project drafted its own reading independently, which is the common
case for an unratified standard, not the exception. This applies
symmetrically: if another project ever crosswalks to AVE's own
`owasp_mcp` field by number rather than meaning, the same risk runs the
other way.

## 5. ID stability policy

The pieces of this guarantee already exist scattered across Sections 2
and 3 above; this section states it once, directly, as a policy
commitment a compliance-minded reader or implementer can cite without
reconstructing it from elsewhere in this document.

**An AVE ID, once published, is never renumbered or reused. Full
stop.** No exception exists for a record later found to be mistaken,
redundant, or poorly scoped, that is what `deprecated`, `merged`, and
`rejected` status exist for (Section 3), not a reason to free up a
number.

**A record's content can be revised as evidence improves; its
identifier cannot.** Description, remediation, severity, AIVSS score,
and every other field are expected to be corrected when a better
understanding of the same behavioral class emerges, the way any of
this project's own corrections passes have done. None of that touches
the `ave_id` itself. The number is a permanent pointer; what it points
at is allowed to get more accurate over time.

**A deprecated or merged record keeps its own number.** If
`AVE-2026-00019` is later found to be a variant of `AVE-2026-00007`,
`00019` does not get deleted, freed, or handed to a future unrelated
record, it is marked `merged` with `merged_into` pointing at `00007`
(Section 3), and `00019` itself stays permanently resolvable at its own
URL with its own history intact.

**This is a commitment this project holds itself to going forward, not
a description of what has merely happened so far.** Nothing has yet
forced a real test of this guarantee at scale; stating it as policy
now, while the corpus is still small, is deliberately the same
discipline Section 1 already applies to record-growth: cheap to commit
to early, expensive to retrofit credibly after an implementer has
already depended on a number that then moved.
