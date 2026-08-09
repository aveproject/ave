# Researcher process

A practical, step-by-step walkthrough for taking a candidate attack class
from raw research to a published AVE record. Written so it can be
followed directly, not just understood in principle. For the higher-level
policy this process implements, see `docs/specs/scaling-and-governance.md`
Section 1 and the README's "How AVE stays current" section; this document
is the mechanics.

## Step 1: find a real candidate

Not a hypothetical scenario. A candidate needs to trace to something
checkable: a disclosed CVE, a vendor security advisory, a published
research paper, a real incident writeup. If you can't cite something a
skeptical reader could go verify themselves, it doesn't clear this step,
no matter how plausible it sounds.

Where candidates actually come from in practice: live search for recent
disclosures, gaps flagged by an independent contributor's own crosswalk
(credit them by name), or a new technique surfacing in an adjacent
framework's own update (MITRE ATLAS, OWASP's ASI Top 10).

## Step 2: apply the mechanical growth-discipline test

Two questions, in order:

**Is this a category label or an actual mechanism?** "Container security
issues exist" is a label. "A declared config flag disables a required
approval gate for high-risk actions, independent of any instruction
text" is a mechanism. If you're still describing a topic rather than a
specific behavior, stop, don't draft yet, go find the specific mechanism
first.

**Does this already exist in the corpus under a different name?** This is
the step most likely to go wrong if rushed, and it has to be done by
comparing real fields, not by comparing how similar two labels sound.

```bash
curl -s https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json | python3 -c "
import json, sys
records = json.load(sys.stdin)
keywords = ['REPLACE WITH YOUR CANDIDATE KEYWORDS']
for r in records:
    text = (r.get('description','') + r.get('behavioral_fingerprint','') + r.get('attack_class','')).lower()
    if any(k.lower() in text for k in keywords):
        print(r['ave_id'], '-', r['attack_class'])
"
```

If that turns up a plausible match, pull its full `provenance_vector`
(`entry_class`, `payload_surface`, `escalation`) and compare it directly
against your candidate's actual mechanism. Only call it a duplicate if
the entry surface and mechanism genuinely match, a similar-sounding
label with a different underlying mechanism is a new record; an
identically-mechanismed candidate with a different label is not, no
matter how novel the framing sounds. This has gone wrong in both
directions in this project's own history: a "delayed memory activation"
candidate that sounded new turned out to be `AVE-2026-00019` restated,
caught only by comparing real fields; A2A agent card poisoning sounded
similar to MCP server-card injection but was confirmed genuinely
distinct the same way.

## Step 3: assign the next ave_id

```bash
ls records/AVE-*.json | grep -oE "AVE-[0-9]{4}-[0-9]{5}" | sort | tail -3
```

Format `AVE-YYYY-NNNNN`. Never reuse a number, including a number
belonging to a record later marked `rejected` or `merged`.

## Step 4: draft the record, every required field

Miss any of these and the record fails validation or, worse, passes but
ships incomplete. This list is what `scripts/validate_records.py`
actually checks for, not a padded ideal:

**Identity and classification**
- `ave_id`, `schema_version`, `status`, `component_type`, `title`,
  `attack_class`, `severity`

**The mechanism itself**
- `description`: the real mechanism, in prose, grounded in your Step 1
  sourcing
- `behavioral_fingerprint`: what a detector should actually look for
- `provenance_vector.entry_class`: reuse an existing value if the role
  matches (see `references/schema-fields.md` for the confirmed enum and
  what each value means); fork a new one only if nothing existing fits
  even loosely
- At least one of `behavioral_vector` or `example_patterns` must be
  non-empty, both empty fails validation

**Evidence fields** (explicitly required, not optional extras)
- `evidence_kind_default`, `detection_stage`, `detection_layer`,
  `confidence_baseline`, `evidence_basis_engines`, `derivable_into`

**Response fields**
- `mitigation.strategy`, `mitigation.enforcement_point`,
  `mitigation.trifecta_control`, each from the closed enum lists only,
  not free text (see the Common Mistakes section below, this is the
  single most common real error caught in this project's own records)
- `detection_methodology`, `indicators_of_compromise`, `remediation`

**Accountability and sourcing**
- `researcher`: whoever actually did the real, primary vulnerability
  research this record is based on, not whoever wrote the AVE record.
  Nearly every record traces to a real external CVE, paper, vendor
  disclosure, or a tool's own detection implementation, in which case
  the named researcher, security team, or organization behind that
  original source goes here, by name. Use an AVE maintainer's own name
  only in the genuinely rare case where AVE itself is the original
  discoverer of a behavioral class with no prior external source to
  credit, which has not actually happened yet in this project's real
  history. If you're unsure whether your candidate has a real external
  source or is a first discovery, it almost certainly has one, check
  again before defaulting to your own name.
- `researcher_url`: must point at whoever is actually named in
  `researcher`, not default to the AVE project's own site. If
  `researcher` names an external party, find their real URL, or omit
  `researcher_url` entirely if no clean one exists (it's optional),
  rather than leave it pointing at an unrelated site. A
  `researcher_url` that doesn't match `researcher` is the same
  inconsistency this rule exists to prevent, just in a second field.
- `published`, `last_updated`
- `references`: at least one, with a real, working URL, not a
  placeholder

**Scoring**, see Step 5 for how to compute these, not just what to fill in
- `aivss_score` (top level, must match the nested one exactly)
- `aivss.cvss_base`, `aivss.aarf` (all ten factors), `aivss.aars`,
  `aivss.thm`, `aivss.mitigation_factor`, `aivss.aivss_score`,
  `aivss.aivss_severity`, `aivss.spec_version`

**Optional, omit rather than force a fit**
- `owasp_asi`, `owasp_mcp`, `mitre_atlas`, `nist_ai_rmf`: only include a
  mapping you can actually defend field by field, not because a record
  feels like it should have one
- `affected_platforms`, `affected_registries`, `kill_switch_active`,
  `mutation_count`

## Step 5: score it

Full formula and worked examples in `references/aivss-scoring.md`.
Short version: `aivss_score = round(((cvss_base + aars) / 2) * thm * mitigation_factor, 1)`,
where `aars` is the sum of the ten `aarf` factors.

Compute it, then independently re-verify the arithmetic before moving on,
don't trust your own mental math:

```bash
python3 -c "
aarf = {'autonomy': 0, 'tool_use': 0, 'multi_agent': 0, 'non_determinism': 0,
        'self_modification': 0, 'dynamic_identity': 0, 'persistent_memory': 0,
        'natural_language_input': 0, 'data_access': 0, 'external_dependencies': 0}
# fill in your candidate's real values above
aars = sum(aarf.values())
cvss_base = 0  # fill in
thm = 1
mitigation_factor = 1  # 1 if no broad ecosystem-wide mitigation exists yet, 0.83 if a simple standard fix exists
score = round(((cvss_base + aars) / 2) * thm * mitigation_factor, 1)
print('aars:', aars, '| aivss_score:', score)
"
```

**Don't inflate factors to hit a more severe-sounding band.** A narrow,
single-vector mechanism can honestly score MEDIUM even with a
near-maximum `cvss_base`, AARF rewards breadth of amplification, not raw
impact alone. If the honest number feels low relative to the mechanism's
intuitive severity, say so in `aivss.notes`, don't adjust the inputs to
force a different result.

## Step 6: validate

```bash
python3 scripts/validate_records.py
pytest tests/ -x -q
```

This checks schema conformance, the AIVSS arithmetic against your
record's own stated inputs, that `mitigation` fields use only the closed
enum values, that stale pre-v1.1.0 field names haven't crept back in,
and vendor-neutral language. If it fails on AIVSS arithmetic, figure out
which specific value is actually wrong rather than adjusting whichever
one is more convenient to change; a mismatch usually means the record
was drafted against a different set of factors than what got written
down.

## Step 7: write conformance fixtures

`tests/fixtures/AVE-YYYY-NNNNN_positive.md`: a conforming implementation
MUST flag this. `tests/fixtures/AVE-YYYY-NNNNN_negative.md`: a
conforming implementation MUST NOT flag this, a realistic, benign file
that looks similar to the malicious one, this is the false-positive
guard and deserves real effort, an easy negative fixture tests nothing.

## Step 8: publish

- `dist/ave-records-latest.json`: add or replace this record's entry,
  keep the array sorted by `ave_id`.
- `CHANGELOG.md`: one line under Unreleased/Added.
- `README.md`: the record count lives in three separate places that
  don't share a common text pattern, a single grep won't catch all of
  them, update each explicitly:
  - the badge (`grep -n "records-[0-9]\+-" README.md`)
  - the Stats table (`grep -n "Total records" README.md`)
  - the collapsible record index's summary label (`grep -n "records, click to expand" README.md`)

Don't bump `schema_version` or create a new versioned dist snapshot as a
side effect of adding one record, that's a separate, deliberate decision.

## Common mistakes, caught in this project's own real records

- **Confusing `provenance_vector.entry_class` with
  `mitigation.enforcement_point`.** These are two different enums.
  `registry_metadata` is a valid `entry_class` value; it is not a valid
  `enforcement_point` value. This exact mistake shipped in a real record
  once and was only caught by actually running the validator, not by
  reading the JSON back.
- **Stating an `aars` that doesn't match the sum of the `aarf` values.**
  Caught in a pre-existing, already-published record
  (`AVE-2026-00048`): the stated `aars` was 7.5, the actual sum of its
  ten factors was 8.0. The downstream `aivss_score` was already correct,
  only the intermediate value was a transcription error, worth checking
  both independently, not assuming one is right because the other looks
  fine.
- **Comparing candidate labels instead of candidate fields when checking
  for duplicates.** Covered in Step 2, worth repeating here because it's
  the single most consequential mistake to make: it either creates a
  real duplicate record or wrongly discards a genuinely distinct one.

## Full worked example: AVE-2026-00060

**Step 1, the real source**: OX Security's April 2026 disclosure that
the STDIO transport implementation in several official MCP SDKs passed
tool call parameters directly to a host shell without sanitization,
independently corroborated by CSA and Microsoft, affecting SDKs across
Python, TypeScript, Java, and Rust.

**Step 2, the mechanical test**: this is a specific, syntactic
mechanism, unsanitized shell passthrough, not a category label. A
keyword sweep for `stdio`, `shell`, `rce` against the live corpus
returned nothing, confirmed clean, no existing record covers this.

**Step 3**: next free ID confirmed as `AVE-2026-00060` against the live
`records/` directory at the time.

**Step 4, the drafted record** (abbreviated to the fields that matter
most for illustration; the full record includes every field from the
Step 4 checklist above):

```json
{
  "ave_id": "AVE-2026-00060",
  "schema_version": "1.1.0",
  "status": "active",
  "component_type": "mcp_server",
  "title": "STDIO transport shell injection via unsanitized tool call parameters",
  "attack_class": "Remote Code Execution - STDIO Transport Shell Injection",
  "severity": "HIGH",
  "description": "The STDIO transport implementation in affected MCP SDKs passes incoming tool call parameters directly to the host shell without sanitization, turning a tool call into arbitrary remote code execution.",
  "behavioral_fingerprint": "Tool call parameters containing shell metacharacters are passed to a host shell without escaping, resulting in execution of attacker-controlled commands.",
  "provenance_vector": {
    "entry_class": "transport",
    "payload_surface": "tool call parameters passed unsanitized to a host shell",
    "escalation": "data_to_instruction"
  },
  "behavioral_vector": ["transport-layer-rce", "unsanitized-shell-passthrough"],
  "mitigation": {
    "strategy": ["validate_input"],
    "enforcement_point": "server_card_fetch",
    "trifecta_control": "break_external_comms"
  },
  "researcher": "OX Security",
  "researcher_url": "https://www.ox.security",
  "published": "2026-07-27T00:00:00Z",
  "references": [
    {"tag": "OX Security disclosure", "text": "Original disclosure across multiple MCP SDKs, April 2026", "url": "https://www.ox.security"}
  ]
}
```

**Worth noting explicitly**: an earlier version of this worked example
listed "Saray Chak" as researcher and "https://bawbel.io" as
researcher_url here, both wrong for exactly the reason this document
now states above, OX Security did the actual research; AVE catalogued
it. Both fields needed correcting together, crediting the right name
while still linking to AVE's own site would have been the same mistake
relocated rather than fixed. Caught via an external maintainer's
correction on a different pair of records, not caught internally
first. Left this note rather than silently fixing it, the same
standard this project has applied to every other correction.

**Step 5, scoring**:

```bash
python3 -c "
aarf = {'autonomy':1,'tool_use':1,'multi_agent':0,'non_determinism':0,'self_modification':0,
        'dynamic_identity':0,'persistent_memory':0,'natural_language_input':0.5,'data_access':1,'external_dependencies':1}
aars = sum(aarf.values())
score = round(((9.8 + aars) / 2) * 1 * 1, 1)
print('aars:', aars, '| aivss_score:', score)
"
```
Output: `aars: 4.5 | aivss_score: 7.2`, HIGH, not CRITICAL, honestly, because
this is a narrow, single-vector mechanism even though the underlying
impact (RCE) is severe. Noted directly in the record's own
`aivss.notes` rather than adjusted to score higher.

**Step 6, validation**: ran clean against the schema, arithmetic check,
and mitigation-enum check on first pass for this record specifically
(the `enforcement_point` mistake described above happened on a
different record in the same batch, not this one, worth remembering
that passing once doesn't mean the whole batch is automatically
correct).

**Step 8, publish**: added to `dist/ave-records-latest.json`,
`CHANGELOG.md` entry appended, record count in `README.md` updated from
the pre-batch total to the real post-batch total.
