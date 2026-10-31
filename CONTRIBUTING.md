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
   [`schema/ave-record-1.3.0.schema.json`](schema/ave-record-1.3.0.schema.json)
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
  instructions" not "contains the word fetch." It is a whole sentence: it ends in
  `.`, `!`, `?` or a closing bracket, quote or backtick, and is not exactly 200
  characters long, which `scripts/validate_records.py` checks.
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
- Add the record's row to the README record index and update the Stats
  total and band count, the records badge, the index summary and the
  record count in the "Independent validation" paragraph;
  `tests/test_readme_sync.py` checks all but the last against `records/`.

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
python scripts/check_confidence_signal.py  # soft-warns on #98 high-confidence records, naming the vantage and independence floors separately
python scripts/write_verification_basis.py   # derives verification_basis; reports declarations its axes refute
python scripts/check_vulnerability_taxonomy.py  # soft-warns on records missing security_boundary/missing_control/vulnerability_rationale
python scripts/check_vulnerability_taxonomy.py --strict --only AVE-2026-NNNNN   # your new record must carry all three taxonomy fields
python scripts/check_mutation_thm_trail.py  # soft-warns on records with mutation_count >= 1 and no ThM-decision trail in aivss.notes
python scripts/check_mutation_thm_trail.py --strict --only AVE-2026-NNNNN   # if your edit raises mutation_count, aivss.notes must state the ThM decision (raised or unchanged, either way)
python scripts/check_framework_sources.py --strict --only AVE-2026-NNNNN   # CI enforces this for every record now; run it scoped to yours before pushing, same check either way
python scripts/generate_terms.py      # regenerate docs/terms.md after any schema field or description change
python scripts/check_terms_sync.py    # hard failure if docs/terms.md disagrees with the live schema -- run before opening a PR
python3 scripts/build_taxonomy.py --check   # dist/ave-taxonomy-latest.json must match dist/ave-records-latest.json; run python3 scripts/build_taxonomy.py after you change that file
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

Open an issue first. Every schema change is a new version, sized by the
compatibility rule in
[the scaling spec, section 2](docs/specs/scaling-and-governance.md#2-schema-versioning-policy):

- **Minor:** it only adds: an optional field, a wider enum, or a requirement
  every published record already meets. It ships as a new versioned schema
  file with the alias updated to match, every record's `schema_version`
  bumped, and the new files added to `schema/frozen-artifacts.json`.
- **Major:** anything that removes, renames or narrows a field, or changes its
  meaning. It also needs a migration path for existing records and a 30-day
  comment period before merging.

A published versioned schema file never changes, not even a description; a
correction ships in the next version.

Current schema: **v1.3.0**.
Canonical file: `schema/ave-record-1.3.0.schema.json`.
(`schema/ave-record-1.0.0.schema.json`, `schema/ave-record-1.1.0.schema.json` and
`schema/ave-record-1.2.0.schema.json` remain, permanently, as frozen earlier versions;
`tests/test_frozen_artifacts.py` fails if any of them changes.)

**Any change to a field's description, additive or structural, requires
regenerating `docs/terms.md`**: `python scripts/generate_terms.py`, then
confirm with `python scripts/check_terms_sync.py` before opening the PR.
That file's per-field definitions are generated from the schema's own
descriptions and are never hand-edited; `check_terms_sync.py` is a hard
CI failure, not a soft warning, if the two disagree.

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

If the change moves `aivss.aivss_score` or `severity`, update the record's
row in the README record index, and the Stats band counts when the
severity band changes; `tests/test_readme_sync.py` fails until they agree.

`ave_id` values are immutable. Never renumber or delete a record. If a record
is wrong or obsolete, change its `status` and keep its content:

- `"deprecated"`: superseded by a better understanding of the same class; say
  why in the pull request and in the record.
- `"merged"`: a duplicate or sub-case of another record; set `merged_into` to
  the surviving record, which must be `active`.
- `"rejected"`: not a real distinct class; set `rejection_reason` to a short
  explanation that links the public decision, a GitHub issue or discussion.

`scripts/validate_records.py` checks the last two. See
[the scaling spec, section 3](docs/specs/scaling-and-governance.md#3-deprecation-policy).

### Recording a change: `revisions`

Consumers gate on a record's `severity`, `status` and derived
`verification_basis`, so a change to one of them has to say so in the record,
not only in `last_updated`. Append an entry to the record's `revisions` array
in the same pull request:

```json
{ "date": "2026-10-29", "field": "severity", "from": "MEDIUM", "to": "HIGH",
  "reason_code": "score_revised", "reason": "Rescored in #294." }
```

`date` is the day the change merges. `from` is the value before (`null` when
the field was absent) and `to` the value after, never `null`. The array is
append-only: an earlier entry is never edited, reordered or removed. CI runs
`python scripts/check_revisions_ratchet.py --ratchet-since origin/develop`,
which compares each record you add or edit with its version where your branch
left `develop`, and fails the pull request when

- an earlier entry was changed, or the array was dropped, or
- `severity`, `status` or the derived `verification_basis` changed and no new
  entry explains it.

A new record, and one that was still a `draft`, needs no entry: nothing a
consumer could have gated on existed yet. Which `field` and `reason_code`:

| What changed | `field` | `reason_code` |
|---|---|---|
| The record was rescored, so its severity moved | `severity` | `score_revised` |
| The status changed (`deprecated`, `merged`, `rejected`) | `status` | `status_changed` |
| A declaration the basis derives from was added | the declaration (`evidence_vantage`, `evidence_method` or `evidence_basis_engines`) | `declaration_added` |
| Such a declaration was wrong and now differs | the same declaration | `declaration_corrected` |
| A fingerprint was cut off or wrong and is corrected (the ratchet does not require this entry, but it is the record of the change) | `behavioral_fingerprint` | `declaration_corrected` |
| The schema gained a vocabulary member, or the derivation rule changed, and the derived basis moved with no declaration changing | `verification_basis` | `vocabulary_member_added` or `derivation_rule_changed` |

The derived `verification_basis` comes from
`scripts/write_verification_basis.py`. When it moves because a declaration
changed, the entry names that declaration, as AVE-2026-00074's does, and
`reason` says the derived value moved. When no declaration changed, the entry
names `verification_basis` itself, so the record must then carry that value
(`python scripts/write_verification_basis.py --write` writes it into records
already in that script's formatting). `scripts/validate_records.py` checks each
entry's field, its from/to chain and its agreement with the record.

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

Every accepted AVE record credits the original researcher by name in the
`researcher` field. A published record is never deleted and its `ave_id`
never changes. Its content can be corrected after publication (a score, a
source, a mapping, or the credit itself when it named the wrong source),
and every such correction is listed in CHANGELOG.md.

---

## Questions

Open a [GitHub Discussion](https://github.com/aveproject/ave/discussions) or
email [aveproject.org@gmail.com](mailto:aveproject.org@gmail.com).
