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

Before opening a PR that adds a new record, read
`docs/specs/scaling-and-governance.md` Section 1. A record needs a
genuinely distinct behavioral mechanism; PRs that mirror another
framework's category without describing a real, evidenced mechanism will
be asked to either strengthen the evidence or fold into an existing
record's `mutation_count` instead.

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
git checkout -b feat/AVE-2026-NNNNN-attack-class origin/develop
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
- `owasp_mcp` is required with at least one entry, verified against the
  category's own primary-source text — not inferred from how a
  similar-sounding record in the corpus happened to tag itself.
  `owasp_asi`, `mitre_atlas`, and `nist_ai_rmf` are not yet
  schema-required (tracked for a future schema version, see issue
  #178) but **always include the key**, even with no value: set it to
  `[]` when you've genuinely checked and nothing fits, rather than
  omitting the field. An absent key reads as "nobody checked"; an
  empty array reads as "checked, no fit yet" — only the second is
  honest. See `docs/specs/researcher-process.md`'s "Governance and
  framework mappings" section for the full rule and the real
  corpus-wide mistake (issue #179) this is written to prevent.
- `indicators_of_compromise` must have at least one entry that a defender
  can actually search for in a real file.
- `references` must have at least one citable primary source — a CVE, an
  arXiv paper, a vendor disclosure, or a scan report.
- `researcher` is required — **but it is almost never your own name.**
  Nearly every record traces to a real external CVE, paper, vendor
  disclosure, or existing tool's detection implementation; that
  source's own name or organization goes in `researcher`, not the
  person writing the AVE record. This exact mistake (defaulting to the
  PR author because it's the name at hand while drafting) has shipped
  on published records more than once and been caught and corrected
  after the fact — see `docs/specs/researcher-process.md`'s
  Accountability and sourcing section and its `AVE-2026-00060` worked
  example for the full rule and a real corrected instance. Use your
  own name only in the genuinely rare case where you are the original
  discoverer of a behavioral class with no prior external source to
  credit.
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
pip install -e ".[dev]"
python scripts/validate_records.py    # schema-checks every record, including yours
python scripts/check_fixtures.py      # confirms every record has +/- fixtures
python scripts/check_confidence_signal.py  # soft-warns on #98 high-confidence floor-basis records
python scripts/write_verification_basis.py   # derives verification_basis; reports declarations its axes refute
pytest tests/ -x -q                   # full suite: schema, AIVSS arithmetic, mitigation enums
```

These are the actual scripts this project runs, including in CI --
`validate_records.py` also checks the AIVSS arithmetic against your
record's own stated `aarf`/`cvss_base`/`thm`/`mitigation_factor`
values (a common failure mode is drafting against one set of factors
and writing down another), and `check_fixtures.py` confirms
`tests/fixtures/AVE-YYYY-NNNNN_positive.md` and `_negative.md` both
exist -- required for every record, see Step 4. If your record states
`evidence_vantage` or `evidence_method`, `validate_records.py` also
recomputes `verification_basis` from them and fails when a declared value
disagrees, so the declaration is checkable rather than taken on trust --
see docs/guides/evidence-vantage-producer-guide.md. If `npm`-based schema
tooling (`ajv`) is more convenient for your own workflow, it's a valid
supplementary check, but the record must pass the scripts above before
a PR is reviewed, not just an ad-hoc schema validator.

The record must validate clean before opening a PR. A PR with a
schema-invalid record will not be reviewed.

### Step 4 -- Write conformance fixtures (in this repo, required to merge)

**Corrected**: fixtures live in *this* repo, not in bawbel/scanner --
`scripts/check_fixtures.py` (Step 3) enforces this on every PR, which
is the actual, current gate. Add two files:

```
tests/fixtures/AVE-2026-NNNNN_positive.md   # a conforming implementation MUST flag this
tests/fixtures/AVE-2026-NNNNN_negative.md   # a conforming implementation MUST NOT flag this
```

The negative fixture is the false-positive guard and deserves real
effort -- a realistic file that looks similar to the malicious one, not
an easy case that tests nothing.

**Separately**, once the record and its fixtures are merged here,
detection *rule implementations* (the actual YARA/Semgrep/pattern code
that uses these fixtures) are implementation artifacts, not standard
artifacts -- they live in whichever tool implements against this
standard, e.g. [bawbel/scanner](https://github.com/bawbel/scanner), not
in this repo. Open a coordinated PR there referencing the `ave_id` and
the fixtures above; it's a real, encouraged step for getting a class
actually detected, but it is not what this repo's own PR is gated on.

### Step 5 -- Open the record PR

Target `develop`, not `main` -- `main` is the GitHub default branch but
not this project's actual integration branch; real record PRs merge
into `develop` and get promoted to `main` separately. Title format:

```
feat: AVE-2026-NNNNN -- <attack class>
```

Example: `feat: AVE-2026-00049 -- header injection (BadHost)`

PR description must include:

- Link to the issue
- Link to the primary source
- AARF score table with one-line rationale per non-zero factor
- Any coordinated scanner-repo PR, if one exists yet (not required to
  open the record PR itself, see Step 4)

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
git checkout -b fix/AVE-2026-NNNNN-description origin/develop
# edit records/AVE-2026-NNNNN.json
# update last_updated to today: "2026-MM-DDTHH:MM:SSZ"
git commit -m "fix: AVE-2026-NNNNN -- <what changed>"
```

Target `develop` for the PR, same as new records.

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
email [aveproject.org@gmail.com](mailto:aveproject.org@gmail.com).
