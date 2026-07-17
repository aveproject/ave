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

## Severity / AIVSS consistency

CRITICAL → aivss_score >= 9.0
HIGH     → 7.0 to 8.9
MEDIUM   → 4.0 to 6.9
LOW      → < 4.0

If severity and aivss_score disagree, the record fails validation.

## confidence_baseline guide

High-signal AVE (hardcoded AWS key, explicit external fetch): 0.85-0.95
Medium-signal (suspicious instruction phrasing): 0.55-0.75
Low-signal (vague, needs corroboration): 0.40-0.55
The scanner adjusts from this baseline via the FP pipeline.
