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

**Governance and framework mappings — the fields a CISO reads first**
These four crosswalk fields are what lets a security team map an AVE
record onto the frameworks they already report against. Get the key
presence right even when you can't get a value: a missing key reads as
"nobody checked," an empty array reads as "checked, no fit yet." Never
let a record ship with the key silently absent.

- `owasp_mcp`: **required** once `status` is `active` or `deprecated`
  (enforced by the schema, `minItems: 1`) — every published record
  needs at least one real, defensible mapping to a primary-source OWASP
  MCP Top 10 category, verified against the category's own text (see
  the researcher-process worked examples in this project's PRs for what
  that verification looks like), not inferred from how a similarly-
  labeled record in the corpus happened to tag itself.
- `owasp_asi`, `mitre_atlas`, `nist_ai_rmf`: **always include the key**,
  even when you find no defensible mapping — set it to `[]` rather than
  omitting the field. Only include a real value in the array when you
  can defend it field-by-field against the framework's own primary
  source (the live `ATLAS.yaml` for MITRE ATLAS, the actual NIST AI
  100-1 text for NIST AI RMF, the framework's own published category
  list for OWASP ASI); never force a value onto a record because it
  feels like it should have one, and never infer one from corpus usage
  alone (see `feedback_verify_framework_mappings`). A record whose
  `aivss.notes` explains "checked, no technique/category fits, left
  empty" has done the work; a record with the key missing hasn't, even
  if the reasoning happened somewhere in your own head while drafting.

  **"Primary source" means the actual document, fetched and read, not
  a summary of it.** A search engine result, a WebFetch-summarized
  page, or a third-party blog's own restatement of a framework is not
  the framework — go get the framework's own artifact (its GitHub
  repo's raw files, its own published PDF, its own site) and read the
  real thing before writing a value into any of these four fields.
  This is not a hypothetical caution: issue #179 documents `owasp_asi`
  values across roughly 65 records, and the schema's own
  `owasp_asi.items.pattern` regex, all built around an `ASI01`-`ASI10`
  numbering that does not exist anywhere in OWASP's actual Agentic
  Security Initiative document (`genai.owasp.org`'s "Agentic AI –
  Threats and Mitigations," v1.1) — confirmed by fetching the real PDF
  and grepping it, zero matches for `ASI0` anywhere in 47 pages. The
  document's own taxonomy uses `T1`-`T17` Threat IDs, seventeen of
  them, not ten. The fabricated numbering traces to a third-party
  blog's own reinterpretation of the initiative, which is presumably
  how it entered this corpus and then kept propagating by each new
  record copying the previous one's pattern rather than any record
  ever going back to OWASP's own document. Comparing corpus precedent
  against corpus precedent, no matter how many records agree, never
  substitutes for comparing against the actual source once.

  Schema currently only *requires the key to exist* as a matter of this
  process document's convention, not (yet) as a schema-enforced
  constraint for these three — enforcing it at the schema level is
  tracked as a deliberate v1.2.0 change, not something to bump
  `schema_version` for on an individual record's own PR.
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
- **Omitting `owasp_asi`, `mitre_atlas`, or `nist_ai_rmf` entirely when
  no mapping was found, instead of including the key with `[]`.**
  Shipped on AVE-2026-00078/00079/00080 (`owasp_asi` silently absent
  from all three despite real research having ruled it out, not simply
  skipped) and caught reviewing the same PR that drafted them. An
  absent key and a documented empty array look identical in a diff at
  a glance but mean opposite things to the CISO reading the record:
  one says nobody checked, the other says checking happened and came
  up empty. Fixed by adding the key with `[]` plus a one-line
  `aivss.notes` explanation of what was checked and why nothing fit.
- **Assuming there's only one possible primary-source document for a
  framework, and stopping once the first fetch confirms a hypothesis.**
  Issue #179 fetched OWASP's "Agentic AI – Threats and Mitigations" PDF
  (`T1`-`T17`), found zero `ASI0` matches in it, and concluded the
  corpus's `ASI01`-`ASI10` values (used consistently across ~65
  records, and by the schema's own `owasp_asi` regex) were fabricated.
  They aren't: a separate, also-current OWASP document, "Top 10 for
  Agentic Applications 2026," uses `ASI01`-`ASI10` as its own category
  IDs, and its own Appendix A formally cross-maps the two, describing
  `T1`-`T17` as the more granular, subordinate taxonomy the `ASI0X`
  framework references — not a competing or replacement scheme.
  Corrected in issue #179's own thread once found (during the docs
  write-up for #196, a genuinely unrelated audit). The lesson isn't
  "trust corpus consensus less than a fetched PDF" — it's that a
  single fetched PDF isn't automatically *the* primary source either
  when a framework's publisher maintains more than one document under
  the same initiative; check that a fetched document is the *right*
  one, specifically the one whose own ID format matches what's being
  verified, before concluding the corpus is wrong.

### owasp_asi tagging, common mistakes worth checking before assigning

Found via a full-corpus audit (#196) that corrected 48 of 70 tagged
records, most tracing to two specific, avoidable patterns. Check the
real ASI category definition, not just the closest-sounding label,
before assigning any of these three:

- **ASI08 (Cascading Failures)** requires described, measurable
  propagation across multiple agents or sessions. A severe but
  single-instance failure with no actual fan-out doesn't qualify, no
  matter how bad that one instance is.
- **ASI07 (Insecure Inter-Agent Communication)** requires actual
  messaging between agents as the mechanism. Tool misuse by a single
  agent doesn't qualify on its own, a tool call isn't inter-agent
  communication.
- **ASI06 (Memory & Context Poisoning)** excludes one-time
  exfiltration events by its own definition. Check both directions,
  this tag was both over-applied to records that didn't qualify and
  missing from records that were clean matches.

The general rule underneath all three: verify against OWASP's actual,
current category definitions before tagging, not against how similar
the record's own title or attack_class sounds to a category name. That
similarity is exactly what produced 48 wrong tags across this corpus.

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
