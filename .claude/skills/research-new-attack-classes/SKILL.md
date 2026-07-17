# research-new-attack-classes

Keep AVE current with the real threat landscape. This skill researches
agentic AI / MCP attack classes from primary sources, benchmarks each
against the existing AVE record set, and for every class decides one of
three outcomes: ALREADY COVERED, VARIANT OF EXISTING, or NEW CLASS.

For NEW CLASS only, it opens a GitHub issue and hands off to add-ave-record.

This skill never pads. It maps to distinct behavioral classes that exist
in cited research. If a "new" attack is just a textual variant of a class
AVE already covers, it is logged as a variant, not a new record.

---

## When to run this

- Monthly cadence (the field moves fast — set a recurring reminder)
- After a major disclosure (a new CVE, a new OX/Invariant/HiddenLayer report)
- After a new academic taxonomy or benchmark paper drops
- Before a release (close the gap deliberately)

Do NOT run this to hit a record-count target. Run it to stay current.
There is no quota. The right number of records equals the number of
distinct behavioral classes that exist — no more.

---

## Inputs

- The current record set in `records/*.json`
- The schema in `schema/ave-record.schema.json`
- LANGUAGE.md (attack_class vocabulary, behavioral_fingerprint discipline)
- docs/adr/0001-behavioral-fingerprints.md (the no-signatures rule)

---

## The pipeline — five phases

### Phase 1: Research (gather, do not judge yet)

Search primary sources only. Rank by authority:

1. MITRE ATLAS (atlas.mitre.org) — the AI-specific ATT&CK. The most
   authoritative existing enumeration of adversarial AI tactics and
   techniques. Treat it as BOTH a primary source AND a benchmark target.
   Capture the ATLAS technique ID (AML.Txxxx) for every candidate that
   maps to one — these IDs go in the AVE record for cross-referencing.
2. CVE/NVD entries and vendor disclosures (OX Security, Invariant Labs,
   HiddenLayer, Unit 42, Snyk, Trail of Bits)
3. Peer-reviewed / arXiv taxonomies and benchmarks
   (MCPSecBench, MCP-SafetyBench, MCPTox, Formal Security Framework,
   Hou et al. lifecycle taxonomy, parasitic toolchain studies)
4. OWASP updates (MCP Top 10, Agentic AI Top 10, AIVSS, AIBOM)
5. Microsoft / Google / NSA / NIST taxonomy and guidance updates
   (note: ATT&CK proper for any technique that crosses into conventional TTPs)
6. Framework changelogs and security advisories (MCP spec, OpenClaw, etc.)

ATLAS scope note: ATLAS covers the entire ML/AI attack surface — model
extraction, data poisoning, evasion, membership inference, and more. Most
of that is OUT OF SCOPE for AVE, which enumerates AGENT COMPONENT behaviors
(skills, MCP servers, tool descriptions), not model training or inference
attacks. Expect many ATLAS techniques to be correctly out of scope. That is
not a gap in AVE — it is the boundary of the standard.

Avoid: vendor marketing blogs without a primary source, forum speculation,
LinkedIn hot takes. Every candidate must trace to a citable origin.

For each candidate attack, record:
- A one-line behavioral description (what the component DOES)
- The primary source URL and date
- The MITRE ATLAS technique ID (AML.Txxxx) if one maps, else "none"
- The surface/layer it operates on (content / server_card / registry / transport / runtime)
- Whether a real CVE or in-the-wild exploit exists
- The proposed attack_class name (kebab/snake, from LANGUAGE.md style)

Output of Phase 1: a candidate list. Do not write records yet.

### Phase 2: Benchmark against existing AVE records

For each candidate, load every record in `records/` and compare on
BEHAVIOR, not wording. The question is never "do the strings match" —
it is "does an existing AVE already describe this behavior?"

Compare against each existing record's:
- `attack_class`
- `behavioral_fingerprint`
- `description`
- `detection_layer`

Decide one of four outcomes:

**ALREADY COVERED** — an existing record's behavioral_fingerprint already
describes this. Even if the research uses a different name, if the behavior
is the same, it is covered. Log it, do nothing else.
Example: a paper's "TV1 Description Injection" maps to an existing
tool_description_injection record → ALREADY COVERED.

**VARIANT OF EXISTING** — same parent behavior, meaningfully different
mechanism or surface, but not a distinct class. Do NOT create a new record.
Instead, note it as a sub-case in the parent record's description or
indicators_of_compromise. A variant never gets its own ave_id.
Example: "tool poisoning via unicode tag smuggling" is a variant of
tool_description_injection, not a new class.

**OUT OF SCOPE** — a real, often ATLAS-catalogued attack that AVE
deliberately does not cover because it targets the model or training
pipeline, not an agent component. Log it as out of scope with the reason.
This is not a gap — it is the boundary of the standard.
Example: ATLAS data poisoning of training data, model extraction,
membership inference → OUT OF SCOPE (AVE covers agent components, not
model training or inference).

**NEW CLASS** — no existing record describes this behavior, it is in scope
(an agent-component behavior), and it is not a thin variant. It operates on
a different surface, exploits a different trust assumption, or chains
differently. This earns a new record.
Example: "parasitic toolchain attack — multi-tool collaboration without a
single malicious server" is behaviorally distinct from single-server tool
poisoning → NEW CLASS.

The bar for NEW CLASS is the deletion test applied to taxonomy:
"If we folded this into an existing record, would we lose a real
detection distinction, or just add a synonym?" Lose a distinction → NEW.
Add a synonym → VARIANT or ALREADY COVERED.

### Phase 3: Report before implementing

Produce a benchmark report. Do not skip this — it is the human checkpoint.

```
## AVE research benchmark — YYYY-MM-DD

### Sources reviewed
- [source, date, what it covers]

### Candidates assessed: N

#### ALREADY COVERED (M)
| Candidate (research name) | ATLAS ID | Existing AVE | Why |
|---|---|---|---|
| TV1 Description Injection | AML.T0051 | AVE-2026-00002 | same behavioral_fingerprint |

#### VARIANT OF EXISTING (K) — update parent, no new record
| Variant | Parent AVE | Suggested update |
|---|---|---|
| unicode tag smuggling | AVE-2026-00002 | add to indicators_of_compromise |

#### OUT OF SCOPE (S) — ATLAS-catalogued but not an agent-component behavior
| Candidate | ATLAS ID | Why out of scope |
|---|---|---|
| training data poisoning | AML.T0020 | targets model training, not agent components |

#### NEW CLASS (J) — open issues
| Proposed attack_class | ATLAS ID | Surface | Source | Severity est. |
|---|---|---|---|---|
| parasitic-toolchain | none | runtime | arxiv 2509.06572 | HIGH |
```

Present this report and STOP. Wait for confirmation before Phase 4.
The maintainer confirms which NEW CLASS candidates proceed.

### Phase 4: Open a GitHub issue per confirmed NEW CLASS

One issue per new class. Title and body:

```
Title: [AVE] New class: <attack_class> (<surface> layer)

## Behavioral fingerprint
<one sentence: what the component DOES>

## Why this is a new class, not a variant
<which existing records were checked, why none cover this>

## Primary source
<URL, date, authors>

## Proposed record skeleton
- attack_class: <name>
- severity: <est> (AIVSS to be computed during implementation)
- owasp_mcp: [MCPxx]
- mitre_atlas: [AML.Txxxx] (if a technique maps, else omit)
- detection_layer: content | server_card | registry_metadata | runtime
- detection_stage: static_detection | runtime_observed
- evidence_basis_engines: [pattern | yara | semgrep | llm | sandbox]
- confidence_baseline: <est>
- derivable_into: [chain ids if any]

## Real-world exploit?
<CVE id or "theoretical only" — affects THM in AIVSS>

## Labels: ave-record, new-class, research-sourced
```

### Phase 5: Implement via add-ave-record

For each confirmed issue, hand off to the add-ave-record skill.
That skill enforces: record JSON validates against schema, a detection
rule exists, a positive fixture triggers it, a negative fixture does not.

Close the issue when the record + rule + fixtures are merged and
`pytest tests/ -x -q` is green.

---

## Hard rules

1. Behavior, not strings. Benchmark on behavioral_fingerprint, never on
   keyword overlap. ADR-0001 governs.
2. No quota, no padding. The record count tracks distinct classes, nothing
   more. A round number is never a reason to create a record.
3. Variants update their parent record. They never get their own ave_id.
4. Every NEW CLASS must trace to a citable primary source. No speculative
   classes. If it has not been demonstrated or disclosed, it is not a record
   yet — it is a research note in docs/agents/.
5. ALREADY COVERED is a success, not a failure. Confirming coverage keeps
   the standard honest and is a publishable signal ("AVE already covered
   the class this paper describes").
6. Report and stop before implementing. Phase 3 is a human checkpoint.
   Never auto-create records without confirmation.
7. ave_id is immutable. New classes get the next number. Never renumber
   to "make room" or reorganize.
8. Severity/AIVSS consistency holds (CRITICAL implies aivss_score >= 9.0).
   A theoretical-only attack with no in-the-wild exploit usually has a
   lower THM and thus lower AIVSS than a class with an active CVE.

---

## Anti-patterns to refuse

- Splitting one behavioral class into N records by delivery mechanism
  (emoji vs unicode vs base64 are all one class: tool_description_injection)
- Creating a record for an attack with no primary source ("I think someone
  could..." is a research note, not a record)
- Renaming an existing class and calling it new
- Creating records to reach a target count before a launch
- Treating every new paper's taxonomy entry as a new AVE — most map to
  classes you already cover under a different name

---

## Output artifacts

Each run produces:
- `docs/agents/research/YYYY-MM-DD-benchmark.md` — the Phase 3 report (committed)
- One GitHub issue per confirmed NEW CLASS
- (After Phase 5) new records, rules, fixtures via add-ave-record

The benchmark report is committed even when zero new classes are found —
it is the audit trail showing AVE was checked against the current landscape
on that date. "We reviewed the field on 2026-06-13 and AVE already covered
all 17 MCPSecBench attack types" is a strong adoption signal.

---

## Example run summary (what good looks like)

```
Reviewed: MCPSecBench (17 types), MCP-SafetyBench (20 types),
          Microsoft taxonomy update (June 2026), 3 new CVEs.
Candidates assessed: 24

ALREADY COVERED: 19  (mapped to existing records)
VARIANT OF EXISTING: 3  (parent records updated)
NEW CLASS: 2
  - parasitic-toolchain (runtime layer, arxiv 2509.06572)
  - oauth-discovery-rebinding (transport layer, CVE-2025-6514)

Issues opened: #82, #83
Records to add: AVE-2026-00049, AVE-2026-00050
```

Two new records from 24 candidates is a healthy ratio. If a run produces
"15 new classes from 20 candidates," stop — the benchmark in Phase 2 was
too loose. Real net-new classes are rare. Most research maps to coverage
you already have.
