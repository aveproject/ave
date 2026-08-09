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