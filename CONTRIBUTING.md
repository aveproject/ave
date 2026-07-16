# Contributing to AVE

The AVE (Agentic Vulnerability Enumeration) standard is open. Every
contribution makes AI agents safer for everyone.

---

## Ways to contribute

| Type | Description |
|---|---|
| New AVE record | Research and document a new agentic behavioral class |
| Schema improvement | Propose field additions or clarifications |
| Detection rule | Add a YARA, Semgrep, or pattern rule to bawbel/scanner |
| AIVSS scoring review | Review or improve AARF scores on existing records |
| Framework mapping | Add OWASP, NIST, or MITRE ATLAS mappings to existing records |
| Bug report | An existing record has an error or a broken link |
| Documentation | Fix a typo, add an example, improve clarity |
| Crosswalk | Map another scanner's finding types to AVE ids |

---

## Before you start

1. **Search the registry** at [aveproject.org/registry.html](https://aveproject.org/registry.html)
   and the `records/` directory for existing coverage of the attack class
   you have in mind. Check `behavioral_fingerprint` values, not just titles —
   the same class appears under many names across different tools.

2. **Check variants** — if the behavior you found is a delivery mechanism for
   an existing class (e.g. unicode smuggling for tool description injection),
   it is a sub-case note in the parent record, not a new id. A new `ave_id`
   is only for a genuinely distinct behavioral class.

3. **Open an issue first** for new records or schema changes to get alignment
   before writing JSON. The maintainer will confirm the next available id.

4. **Read the schema** at
   [`schema/ave-record-1.1.0.schema.json`](schema/ave-record-1.1.0.schema.json)
   for field definitions, types, and required/optional status. The schema
   reference page is at [aveproject.org/schema.html](https://aveproject.org/schema.html).

---

## Submitting a new AVE record

### Step 1 -- Open an issue

Use the **New AVE Record** issue template. Include:

- Proposed `attack_class` (snake_case or short phrase)
- One-sentence `behavioral_fingerprint` — what the component *does*
- Link to the primary source (CVE, paper, disclosure, or working PoC)
- Whether this is a new class or a variant of an existing record

The maintainer will confirm the next `ave_id` and whether it is net-new
or a variant update before you write any JSON.

### Step 2 -- Fork and create the record

```bash
git clone https://github.com/aveproject/ave
cd ave
git checkout -b feat/AVE-2026-NNNNN-attack-class
cp records/AVE-2026-00001.json records/AVE-2026-NNNNN.json
```

Fill every required field. The 15 required fields are:

```
ave_id · schema_version · status · published
title · description · attack_class · severity · behavioral_fingerprint
aivss · owasp_mcp
indicators_of_compromise · remediation
references · researcher
```

Key rules:

- `behavioral_fingerprint` describes what the component *does*, not a string
  it contains. "Component fetches remote content and executes it as
  instructions" not "contains the word fetch."
- `owasp_mcp` is required with at least one entry. `owasp_asi`,
  `mitre_atlas`, and `nist_ai_rmf` are optional — add
  them when they apply, omit rather than force a poor fit.
- `indicators_of_compromise` must have at least one entry that a defender
  can actually search for in a real file.
- `references` must have at least one citable primary source — a CVE, an
  arXiv paper, a vendor disclosure, or a scan report.
- `researcher` is required. Use your name or handle.
- `severity` and `aivss.aivss_score` must agree:
  CRITICAL >= 9.0 · HIGH 7.0-8.9 · MEDIUM 4.0-6.9 · LOW < 4.0.

### AIVSS v0.8 calculation

```
AIVSS = ((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor
```

Score each AARF factor 0.0 (not applicable) to 1.0 (fully applicable):

| Factor | Score when... |
|---|---|
| autonomy | agent acts without human confirmation |
| tool_use | component grants access to external tools or APIs |
| multi_agent | attack chains across multiple agents |
| non_determinism | behavior varies unpredictably across runs |
| self_modification | component can alter its own instructions at runtime |
| dynamic_identity | component assumes roles or personas |
| persistent_memory | state is retained across sessions |
| natural_language_input | instructions are delivered via natural language |
| data_access | component reads sensitive data (files, env, databases) |
| external_dependencies | component loads remote code or content |

ThM values:
- `0.75` -- theoretical, no known PoC
- `0.90` -- PoC exists
- `1.0` -- exploited in the wild or weaponised

Write a one-line rationale for each non-zero AARF factor in the PR
description. Reviewers will ask for this if it is missing.

### Step 3 -- Validate locally

```bash
npm install ajv ajv-formats
node -e "
const Ajv = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const ajv = new Ajv({ strict: false });
addFormats(ajv);
const schema = require('./schema/ave-record-1.1.0.schema.json');
const record = require('./records/AVE-2026-NNNNN.json');
const ok = ajv.validate(schema, record);
if (!ok) { console.error(ajv.errors); process.exit(1); }
else console.log('valid');
"
```

The record must validate clean before opening a PR. A PR with a
schema-invalid record will not be reviewed.

### Step 4 -- Open a coordinated scanner PR

Every AVE record needs at least one detection rule in
[bawbel/scanner](https://github.com/bawbel/scanner) with:

- A **positive fixture** — a file that must trigger the rule
- A **negative fixture** — a benign lookalike that must not trigger

Open the scanner PR alongside the record PR. Reference each from the other.
A record without a detection rule will not be merged.

### Step 5 -- Open the record PR

Target `main`. Title format:

```
feat: AVE-2026-NNNNN -- <attack class>
```

Example: `feat: AVE-2026-00049 -- header injection (BadHost)`

PR description must include:

- Link to the issue
- Link to the primary source
- AARF score table with one-line rationale per non-zero factor
- Link to the coordinated scanner PR

---

## Schema changes

**Additive changes** (new optional fields, clarified descriptions):
standard PR. No version bump required.

**Structural changes** (new required fields, renamed fields, removed fields,
changed validation rules): open an issue first. These require a schema
version bump, a migration path for existing records, and a 30-day comment
period before merging.

Current schema: **v1.1.0**.
Canonical file: `schema/ave-record-1.1.0.schema.json`.
(`schema/ave-record-1.0.0.schema.json` remains, permanently, as the frozen v1.0.0 canonical.)

---

## Improving existing records

To update an existing record:

```bash
git checkout -b fix/AVE-2026-NNNNN-description
# edit records/AVE-2026-NNNNN.json
# update last_updated to today: "2026-MM-DDTHH:MM:SSZ"
git commit -m "fix: AVE-2026-NNNNN -- <what changed>"
```

AIVSS score changes require written rationale for each AARF factor that
changes. Framework mapping additions (`owasp_asi`, `mitre_atlas`)
are welcome without prior issue if the mapping is clear.

`ave_id` values are immutable. Never renumber a record. If a record is wrong
or obsolete, set `status: "deprecated"` — never delete.

---

## Crosswalk contributions

If you maintain a scanner with its own taxonomy, mapping your finding types
to AVE ids makes your results interoperable with every other AVE
implementation. Add a JSON crosswalk file to `crosswalks/` following the
format in [`crosswalks/skillspector-to-ave.json`](crosswalks/skillspector-to-ave.json).

See [docs/specs/ave-implementer-guide.md](docs/specs/ave-implementer-guide.md)
for the full guide on adding AVE ID emission to your scanner output.

---

## Code of conduct

All contributors are expected to treat each other with respect. Security
research involves difficult topics. Disagree on technical grounds, not
personal ones. We are all trying to make AI agents safer.

---

## Researcher recognition

Every accepted AVE record permanently credits the `researcher` field by
name. Records are immutable once published — your attribution stays forever.

---

## Questions

Open a [GitHub Discussion](https://github.com/aveproject/ave/discussions) or
email [bawbel.io@gmail.com](mailto:bawbel.io@gmail.com).