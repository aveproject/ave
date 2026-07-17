# CLAUDE.md — aveproject/ave

Read this file completely before touching anything.
Single source of truth for how work happens in this repo.

---

## Project

aveproject/ave — the behavioral classification standard for agentic AI components.
An independent standard that bawbel-scanner implements. NOT a feature of the scanner.

- Records: 56 published (schema_version 1.1.0)
- Schema: schema/ave-record-1.1.0.schema.json
- Scoring: OWASP AIVSS v0.8
- Registry: aveproject.org
- Public API: api.piranha.bawbel.io
- Scanner: github.com/bawbel/scanner (reference implementation)

This repo contains DEFINITIONS, not detections.
An AVE record defines a behavioral class. A scanner Finding is one
detection that references an AVE record by ave_id.

---

## The critical distinction — read this twice

```
AVE Record (this repo)              Finding (scanner repo)
──────────────────────              ──────────────────────
static behavioral class definition  runtime detection instance
authored once by a human            produced by every scan
one per behavioral class            one per detection
NO confidence field                 HAS confidence field
NO evidence_stage field             HAS evidence_stage field
declares confidence_baseline        assigns actual confidence
declares evidence_kind_default      assigns actual evidence_kind
declares detection_stage            reaches an actual evidence_stage
```

confidence is PER-DETECTION. It never lives in an AVE record.
The record declares the BASELINE; the scanner assigns the ACTUAL value.

---

## Record schema v1.1.0

Every record validates against schema/ave-record-1.1.0.schema.json.

**15 required fields** (once `status` is `active` or `deprecated`):
ave_id · schema_version · status · published
title · description · attack_class · severity · behavioral_fingerprint
aivss · owasp_mcp
indicators_of_compromise · remediation
references · researcher

**Draft submit-required core** (`status: "draft"` only needs these 8):
ave_id · schema_version · status · title · description · attack_class ·
behavioral_fingerprint · references

**Optional framework fields** (add when applicable, omit rather than force):
owasp_asi · mitre_atlas · nist_ai_rmf

**Optional runtime/mitigation classification fields** (vendor-neutral only —
no enforcement-tool config ever belongs here):
provenance_vector · trifecta_profile · mitigation · example_patterns

**Optional scanner evidence declarations** (declare defaults the scanner uses):
evidence_kind_default · detection_stage · detection_layer
confidence_baseline · evidence_basis_engines · derivable_into

**Optional ecosystem fields:**
component_type · affected_platforms · affected_registries
behavioral_vector · mutation_count · detection_methodology
kill_switch_active · aivss_score · cvss_base_vector
researcher_url · last_updated

Full reference: aveproject.org/schema.html

---

## Adding a record

Use the add-ave-record skill. Every record requires:
1. A JSON record in records/ validating against the schema
2. A positive fixture in tests/fixtures/ that a conforming implementation
   must flag
3. A negative fixture in tests/fixtures/ that a conforming implementation
   must not flag

Detection rule implementations (pattern, YARA, semgrep, or anything else)
are implementation artifacts, not standard artifacts. They live in whichever
tool implements against this standard — open a coordinated PR in that
tool's own repo (see CONTRIBUTING.md Step 4).

Open an issue first to confirm the id. A new ave_id is only for a
genuinely distinct behavioral class — variants go as sub-case notes
in the parent record, not as new ids.

---

## Function comments — What/Why/How

Every function in validation scripts gets a What/Why/How comment.

```python
# What: validates one AVE record against the JSON schema
# Why:  a malformed record breaks every downstream scanner that loads it
# How:  jsonschema.validate against schema/ave-record-1.1.0.schema.json
def validate_record(record: dict) -> tuple[bool, list[str]]:
    ...
```

---

## TDD loop

```
1. Write the failing test (record validation, rule match, fixture)
2. Run -> MUST FAIL
3. Add the record / rule / fixture
4. Run -> MUST PASS
5. Run full suite -> green before commit
```

---

## Local commands

```bash
npm install ajv ajv-formats           # schema validation deps
npm run build:local                   # build records.js for ave-site

# Python validation
pip install -e ".[dev]"
pytest tests/ -x -q                   # validate records + fixtures
python scripts/validate_records.py    # schema-check every record
python scripts/check_fixtures.py      # every record has +/- fixtures
```

---

## Hard rules

1. Every record validates against schema/ave-record-1.1.0.schema.json.
2. confidence NEVER appears in an AVE record — it is per-detection.
3. Behavioral fingerprints over signatures — describe what it DOES.
4. Every record has a positive + negative conformance fixture. Detection
   rule implementations live in the implementing tool's own repo, not here.
5. ave_id is immutable once published. Never renumber. Deprecate, never delete.
6. severity and aivss.aivss_score must agree (CRITICAL implies >= 9.0).
7. All names from LANGUAGE.md.
8. owasp_mcp is required. owasp_asi, mitre_atlas, nist_ai_rmf
   are optional — add when they apply, omit rather than force a poor fit.
9. references must have at least one citable primary source.
10. Never commit records/INDEX.md — it is removed. The README is the index.

---

## Agent skills

| Skill | When |
|---|---|
| setup-ave-skills | First time setup |
| add-ave-record | Adding a new AVE record (the main workflow) |
| research-new-attack-classes | Research threat landscape, benchmark against existing records, open issues for genuinely new classes |
| grill-with-docs | Before defining a new vulnerability class |
| tdd | Implementing record validation or rules |
| diagnose | When a rule misfires or a record fails validation |
| handoff | Session start/end |
| git-guardrails | Block dangerous git commands |

---

## Product context

Read PRODUCT.md. AVE is a standalone standard, Layer 1 of the Bawbel
five-layer architecture. Treat it as its own product.

The records grow with research, not with quotas. Target ~60-65 high-quality
records by Product Hunt, reached deliberately. A new ave_id requires a
distinct behavioral class and a citable primary source. No padding.