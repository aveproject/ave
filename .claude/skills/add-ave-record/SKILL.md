# add-ave-record

The main workflow for this repo. Adds one new AVE record end to end.

## Steps

### 1. Grill the vulnerability class first
Run grill-with-docs. Answer:
- What does a vulnerable component DO? (behavioral_fingerprint)
- What attack_class is this? (new or existing?)
- What is the worst-case impact? (drives AIVSS)
- Which engines can detect it? (evidence_basis_engines)
- Can a static scan see it, or does it need runtime? (detection_stage)
- Does it chain with other AVEs? (derivable_into)

### 2. Assign the next ave_id
Format AVE-YYYY-NNNNN. Never reuse a number. Check records/ for the highest.

### 3. Write the record JSON
records/AVE-YYYY-NNNNN.json. Must validate against the schema.
Include the evidence fields:
- evidence_kind_default
- detection_stage
- detection_layer
- confidence_baseline
- evidence_basis_engines
- derivable_into

**The `researcher` field, a common, real mistake, not a hypothetical
one**: defaulting to the AVE maintainer's own name because it's the
name most readily at hand while drafting. Check first: does this
record trace to a real external CVE, paper, vendor disclosure, or
existing tool implementation? If yes, and it almost always is yes,
that source's own name or organization belongs in `researcher`, not
the person writing the AVE record. This exact mistake shipped on two
published records before being caught by an external maintainer being
credited incorrectly himself. See docs/specs/researcher-process.md's
Accountability and sourcing section for the full rule.

**The four governance/framework fields — `owasp_mcp`, `owasp_asi`,
`mitre_atlas`, `nist_ai_rmf` — always include the key, never let one go
missing.** These are the fields a CISO reads first; a security team
maps an AVE record onto their own reporting frameworks through these.
An absent key silently reads as "nobody checked this framework." An
empty array reads as "checked, no real fit was found." Only the second
one is an honest, defensible state.

- `owasp_mcp`: **required** once `status` is `active`/`deprecated`
  (schema-enforced, `minItems: 1`) — needs at least one real mapping,
  verified against the OWASP MCP Top 10's own primary-source category
  text, not inferred from how a similar-sounding record in the corpus
  happened to tag itself.
- `owasp_asi`, `mitre_atlas`, `nist_ai_rmf`: not yet schema-required
  (that's a tracked v1.2.0 change, see the roadmap issue), but always
  write the key. Verify each against its own primary source (live
  `ATLAS.yaml` for MITRE ATLAS, the actual NIST AI 100-1 text for NIST
  AI RMF, the framework's own published category list for OWASP ASI)
  before adding a value. Genuinely checked and found nothing that
  fits? Set it to `[]` and say so in `aivss.notes` — don't just leave
  the key out because the array would otherwise be empty. This exact
  mistake (a silently-missing `owasp_asi` key, not an empty one)
  shipped on AVE-2026-00078/00079/00080 and was caught reviewing that
  same PR — see docs/specs/researcher-process.md's Common Mistakes
  section.

  **"Its own primary source" means fetch and read the actual document
  — a repo's raw files, the framework's own published PDF — never a
  search result, a summarized page, or a third-party blog's retelling
  of it, and never corpus precedent no matter how many existing
  records agree with each other.** `ASI01`-`ASI10`, the numbering this
  corpus and the schema's own `owasp_asi` regex both use, is correct —
  it's OWASP's own "Top 10 for Agentic Applications 2026" document's
  category IDs. A separate OWASP document, "Agentic AI – Threats and
  Mitigations," uses a different, `T1`-`T17` numbering; issue #179
  fetched only that second document, found no `ASI0` matches in it,
  and initially (wrongly) concluded the corpus's numbering was
  fabricated — corrected in that issue's own thread once the first
  document was found. Same underlying discipline either way: fetch and
  read the actual primary source before trusting corpus precedent, and
  when a framework's publisher maintains more than one document, check
  that the one fetched is actually the one whose ID format is being
  verified.

  **Before assigning `owasp_asi`, also check the real category
  definition, not just the label that sounds closest.** A full-corpus
  audit (#196) found 48 of 70 tagged records wrong, mostly `ASI08`
  applied to single-instance failures with no real cross-agent
  propagation, and `ASI07` applied to single-agent tool misuse with no
  actual inter-agent messaging involved. See
  docs/specs/researcher-process.md's own note on this for the full
  pattern.

### 4. Write conformance fixtures (TDD — fixtures first)
tests/fixtures/AVE-YYYY-NNNNN_positive.md — a conforming implementation MUST flag this
tests/fixtures/AVE-YYYY-NNNNN_negative.md — a conforming implementation MUST NOT flag this
The negative fixture is the false-positive guard. Make it realistic —
a benign file that looks similar to the malicious one.

### 5. Open a coordinated detection-rule PR
Detection rule implementations (pattern, YARA, semgrep, or anything else)
are implementation artifacts, not standard artifacts — they live in
whichever tool implements against this standard, not in this repo. Open a
PR in that tool's own repo (e.g. bawbel/scanner) referencing the ave_id and
the fixtures above; see CONTRIBUTING.md Step 4.

### 6. Validate
```bash
python scripts/validate_records.py
pytest tests/ -x -q
```

If validate_records.py fails on AIVSS arithmetic, fix the record's own
aarf/cvss_base/thm/mitigation_factor values or the stated aivss_score,
don't just adjust one to match the other without checking which one is
actually wrong; a computed mismatch usually means the record was drafted
against a different set of factors than what got written down.

### 7. Publish
A record passing validation is not yet a published one. Update:

- **dist/ave-records-latest.json**: add or replace this record's entry,
  keeping the array sorted by ave_id.
- **CHANGELOG.md**: one line under Unreleased/Added: the ave_id, title,
  severity, and aivss_score.
- **README.md, three separate things, don't assume any of them share a
  format**:

  1. **Prose record count.** Find it first:
     ```bash
     grep -n "[0-9]\+ records\|[0-9]\+ behavioral class" README.md
     ```
     Update to the real count from `ls records/AVE-*.json | wc -l`, not by
     incrementing the old number, more than one record can land in a
     single batch.

  2. **A record-count badge**, if one exists. Badges are usually
     shields.io-style, with the count embedded as a URL path segment, not
     free prose, so the prose grep above won't reliably catch it. Find it
     separately:
     ```bash
     grep -n "shields.io\|badge.*record\|records.*badge" README.md
     ```
     If found, the count sits inside the badge URL itself (something like
     `.../badge/records-59-blue`), update that specific segment to the
     real count, don't touch the rest of the badge's color, label text, or
     link target.

  3. **A list or table enumerating individual records**, if one exists.
     This is not a number to update, it needs a new row appended for
     whatever record just landed, matching the exact column structure and
     formatting of the existing rows exactly, so it doesn't stand out as
     the one inconsistently-formatted entry. Find it first:
     ```bash
     grep -n "AVE-2026-" README.md
     ```
     If this is a comprehensive, actively-maintained list, append the new
     record's row after whatever the file's own existing ordering
     convention is (chronological, by ID, by severity, confirm which
     before assuming). If it's a curated set of examples rather than a
     complete enumeration (a handful of illustrative records, not all of
     them), don't add to it automatically, that's an editorial decision
     about which records are worth featuring, not a mechanical update; ask
     before changing this one.

  For all three: if the grep for any of them finds nothing, that specific
  piece doesn't exist in README.md, skip it, don't invent one. If any grep
  finds something whose format doesn't match what's described above, stop
  and ask rather than force an edit that might not fit.

Do not bump schema_version or create a new versioned dist snapshot
(dist/ave-records-vX.Y.Z.json) as part of this step. That's a separate,
deliberate decision tied to an actual schema change, not something that
happens automatically because one record got added.

## Severity / AIVSS consistency

CRITICAL → aivss_score >= 9.0
HIGH     → 7.0 to 8.9
MEDIUM   → 4.0 to 6.9
LOW      → < 4.0

If severity and aivss_score disagree, the record fails validation.

A mechanism that reads as severe in plain English can still land MEDIUM,
correctly, if it's narrow and single-vector, AARF's ten factors reward
breadth of amplification, not just raw impact. cvss_base alone carries
the severity of the underlying impact. Don't inflate AARF factors to
force a record into a more severe-sounding band; if the honestly computed
score feels low relative to the mechanism's intuitive severity, say so in
the record's own aivss.notes field rather than adjusting the inputs to
hit a target. See references/aivss-scoring.md for the full formula and
worked examples of this exact situation.

## confidence_baseline guide

High-signal AVE (hardcoded AWS key, explicit external fetch): 0.85-0.95
Medium-signal (suspicious instruction phrasing): 0.55-0.75
Low-signal (vague, needs corroboration): 0.40-0.55
The scanner adjusts from this baseline via the FP pipeline.

## Reference files

- references/aivss-scoring.md: the AARF formula, how aars is computed
  from the ten factors, and worked examples spanning MEDIUM through HIGH,
  including the specific trap of inflating factors to chase a severity
  band.
- references/schema-fields.md: the provenance_vector.entry_class enum
  (confirmed live against the corpus) and escalation values, distinct
  from grill-with-docs Q7's detection_layer, a coarser, separate field;
  don't conflate the two when writing provenance_vector.