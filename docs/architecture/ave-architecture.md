# AVE Architecture

This document explains the AVE standard at two levels:

1. A high-level view for partners, adopters, and decision-makers — what AVE
   is and why it matters.
2. A detailed view for developers and security engineers — how an AVE record
   is structured, validated, consumed, and emitted.

If you read only one section, read the one for your role. The two describe
the same standard at different depths.

---

## 1. High-level view (partners, adopters, decision-makers)

### The diagram

```mermaid
graph TB
    classDef gap fill:#F1EFE8,stroke:#5F5E5A,stroke-width:2px,color:#2C2C2A;
    classDef threat fill:#FAEEDA,stroke:#854F0B,stroke-width:2px,color:#412402;
    classDef ave fill:#E1F5EE,stroke:#0F6E56,stroke-width:3px,color:#04342C,font-weight:bold;
    classDef pillar fill:#E1F5EE,stroke:#0F6E56,stroke-width:2px,color:#04342C;
    classDef prize fill:#FAEEDA,stroke:#854F0B,stroke-width:2px,color:#412402,font-weight:bold;

    EXISTING["Existing standards<br>CVE · CVSS · OSV<br>Map to package + version<br>Blind to agent behavior"]
    THREAT["Agent component threats<br>Prompt injection, toxic flows,<br>rug pulls, tool poisoning<br>No package. No version."]

    AVE["AVE — Agentic Vulnerability Enumeration<br>The behavioral vulnerability enumeration standard for agentic AI components<br>Stable IDs · AIVSS v0.8 scored · behavioral fingerprints"]

    P1["Trusted frameworks<br>OWASP MCP Top 10<br>MITRE ATLAS<br>OWASP AIVSS v0.8"]
    P2["Scanner interop<br>Bawbel · SkillSpector<br>ClawScan · others<br>one shared vocabulary"]
    P3["Open governance<br>Apache 2.0<br>Path to OWASP project<br>No vendor lock-in"]

    PRIZE["The prize: findings from any tool interoperate<br>One vocabulary the field shares — the CVE moment for AI agents"]

    EXISTING -->|the gap| AVE
    THREAT -->|the gap| AVE
    AVE --> P1
    AVE --> P2
    AVE --> P3
    P1 --> PRIZE
    P2 --> PRIZE
    P3 --> PRIZE

    class EXISTING gap
    class THREAT threat
    class AVE ave
    class P1,P2,P3 pillar
    class PRIZE prize
```

### The gap AVE fills

Conventional vulnerability standards were built for conventional software.
CVE identifies a flaw, CVSS scores its severity, and OSV maps it to a
specific package and version range. This works because traditional
vulnerabilities live in code you can pin to a release.

Agent component threats do not work this way. A prompt injection hidden in
an MCP tool description, a skill file that fetches its real instructions from
a remote URL, a rug pull that changes behavior after install, a toxic flow
that chains two individually-benign capabilities into an exfiltration path —
none of these map to a package and version. The same malicious behavior
appears in infinitely many textual forms, and the danger is in what the
component *does*, not in which dependency it pulls.

That is the gap. The existing standards are blind to it because there is no
package to flag and no version range to constrain. AVE exists to enumerate
these behavioral vulnerability classes the way CVE enumerates software flaws.

### What AVE is

AVE (Agentic Vulnerability Enumeration) is an open standard that assigns a
stable identifier to each distinct behavioral vulnerability class in agentic
AI. Each record describes the behavior that makes a component dangerous,
scores it with OWASP AIVSS v0.8, and maps it to the frameworks the security
field already uses. It is behavioral, not signature-based: one AVE record
catches many textual variants of the same underlying attack.

AVE is a standard, not a product. The Bawbel scanner implements it, but AVE
is designed to be implemented by anyone. The record set is published openly;
the schema is open; the identifiers are stable and citable.

### Why it wins — three pillars

**Trusted frameworks.** Every AVE record maps to OWASP MCP Top 10, the
OWASP Agentic AI Top 10, MITRE ATLAS, and is scored with OWASP AIVSS v0.8.
AVE does not ask anyone to abandon a framework they trust — it gives them a
machine-readable, lintable way to enforce those frameworks in a pipeline.

**Scanner interoperability.** The field has many scanners and no shared
vocabulary. Independent studies have found that different agent-security
scanners barely agree on what they flag — overlap between any two tools can
be in the single digits of a percent. That is not a quality problem; it is a
vocabulary problem. Without a common reference, findings from two tools
cannot be compared, deduplicated, or aggregated. AVE is the shared reference
that makes cross-tool findings interoperate.

**Open governance.** As long as a standard is owned by one company, adopters
fear lock-in. AVE is published under Apache 2.0 with an explicit path toward
neutral governance as an OWASP project. The standard is meant to outlive any
single implementation, including Bawbel's.

### The prize

If the field adopts one vocabulary, findings from any tool interoperate, and
a security team can finally compare and correlate results across scanners.
That is the position AVE is built to occupy — the CVE moment for AI agents.

---

## 2. Detailed view (developers and security engineers)

### The diagram

```mermaid
graph TB
    classDef record fill:#E1F5EE,stroke:#0F6E56,stroke-width:2px,color:#04342C;
    classDef validate fill:#F1EFE8,stroke:#5F5E5A,stroke-width:2px,color:#2C2C2A;
    classDef consume fill:#EEEDFE,stroke:#534AB7,stroke-width:2px,color:#26215C;
    classDef output fill:#E1F5EE,stroke:#0F6E56,stroke-width:2px,color:#04342C;
    classDef store fill:#EEEDFE,stroke:#534AB7,stroke-width:2px,color:#26215C;

    RECORD["AVE record — records/AVE-YYYY-NNNNN.json<br>───────────────<br>Definition (static): ave_id · attack_class ·<br>behavioral_fingerprint · severity · aivss{} ·<br>owasp_mcp · mitre_atlas · remediation · iocs<br>───────────────<br>Evidence declarations (v1.1): confidence_baseline ·<br>evidence_kind_default · detection_stage ·<br>detection_layer · evidence_basis_engines · derivable_into"]

    RULE["Rule<br>pattern / yara / semgrep"]
    POS["Positive fixture<br>must trigger"]
    NEG["Negative fixture<br>must NOT trigger"]

    CONSUME["Consumption — the record DECLARES, the scanner ASSIGNS<br>───────────────<br>confidence_baseline → confidence (FP-adjusted)<br>evidence_kind_default → evidence_kind<br>detection_stage → evidence_stage (floor)<br>evidence_basis_engines → evidence_basis<br>derivable_into → ToxicFlow.derived_from_findings<br>───────────────<br>Finding: confidence ≠ aivss_score — separate fields, always"]

    SARIF["Finding → SARIF<br>ave_id in ruleId + taxonomies<br>→ GitHub Security tab / CI"]
    PIRANHA["Record set → PiranhaDB<br>→ api.piranha.bawbel.io<br>→ aveproject.org"]
    CROSS["Crosswalks<br>SkillSpector & ClawScan finding types map to AVE ids"]

    RECORD -->|has a| RULE
    RULE --> POS
    RULE --> NEG
    RECORD -->|declares baselines| CONSUME
    CONSUME -->|emits| SARIF
    RECORD -->|published as| PIRANHA
    RECORD -->|referenced by| CROSS

    class RECORD record
    class RULE,POS,NEG validate
    class CONSUME consume
    class SARIF output
    class PIRANHA,CROSS store
```

### Anatomy of a record

An AVE record is a single JSON file at `records/AVE-YYYY-NNNNN.json` that
validates against `schema/ave-record.schema.json` (currently v1.1). It has
two conceptual halves.

**The static definition** is the part that describes the vulnerability class
itself and never changes per scan:

- `ave_id` — the immutable identifier. Once published it is never renumbered
  or reused. A wrong record is deprecated via `status`, never deleted.
- `attack_class` — the behavioral category (for example
  `external_instruction_fetch`), not a "vulnerability type" string.
- `behavioral_fingerprint` — what the component *does* that is dangerous.
  Behavioral, not a byte signature. This is the heart of the record.
- `severity` and `aivss` — the OWASP AIVSS v0.8 breakdown (`cvss_base`,
  `aars`, `thm`, `mitigation_factor`, `aivss_score`, `spec_version`).
  Severity and score must agree: CRITICAL implies `aivss_score >= 9.0`.
- `owasp_mcp`, `owasp`, `mitre_atlas` — framework mappings.
- `remediation`, `indicators_of_compromise`, `references`.

**The evidence declarations** were added in schema v1.1 (issues #69-72).
They are all optional, so every pre-v1.1 record still validates. They do not
carry per-detection values — they declare the *defaults and baselines* a
scanner uses to assign per-finding evidence metadata:

- `confidence_baseline` — the base confidence for a single-engine match
  before false-positive adjustment.
- `evidence_kind_default` — the default `evidence_kind` for findings of this
  class.
- `detection_stage` — the earliest lifecycle stage at which this class is
  detectable (`static_detection`, `runtime_observed`, `runtime_drift_detected`).
- `detection_layer` — where the class surfaces (`content`, `server_card`,
  `registry_metadata`, `runtime`).
- `evidence_basis_engines` — which engines can detect this class.
- `derivable_into` — the toxic-flow chains this class can participate in.

### Validation — the record/rule/fixture triangle

A definition nobody can detect is not useful, and a detection with no
false-positive guard is a liability. Every record therefore requires three
things beyond the JSON:

1. A **rule** (`pattern`, `yara`, or `semgrep`) that implements detection and
   references the `ave_id`.
2. A **positive fixture** — a file that must trigger the rule.
3. A **negative fixture** — a benign file that resembles the positive one but
   must *not* trigger the rule. This is the false-positive guard, and a rule
   without one is incomplete.

The validation tooling in `scripts/` enforces that every record has a rule
and that every rule has both fixtures. `pytest` runs the rules against the
fixtures and fails if a positive fixture stops triggering or a negative
fixture starts.

### Consumption — the record declares, the scanner assigns

This is the most important concept for anyone implementing AVE, and the
reason the v1.1 evidence fields exist.

An AVE **record** is static. A scanner **Finding** is a runtime instance —
one detection of one file at one moment. Confidence belongs to the Finding,
never to the record: the same class detected in a `docs/` folder and in a
live skill file deserves different confidence. So the record never carries a
`confidence` number. Instead it declares the baseline, and the scanner does
the per-detection math:

| Record DECLARES (static) | Scanner ASSIGNS to Finding (runtime) |
|---|---|
| `confidence_baseline` | `confidence` (then FP-adjusted) |
| `evidence_kind_default` | `evidence_kind` |
| `detection_stage` | `evidence_stage` (floor) |
| `evidence_basis_engines` | `evidence_basis` |
| `derivable_into` | `ToxicFlow.derived_from_findings` |

The invariant that falls out of this: in any Finding, `confidence` and
`aivss_score` are separate fields with separate meaning and are never merged
or substituted. AIVSS answers "how bad would this be"; confidence answers
"how sure are we." A HIGH-severity, low-confidence finding and a HIGH-severity,
high-confidence finding require different responses, and the output keeps
them distinct.

Putting the baselines in the standard rather than in scanner code is
deliberate. If the scanner hardcoded them, a second implementation would
invent its own and the two tools would produce divergent evidence metadata
for the same class. Baselines belong in the standard so every implementation
agrees. (See `docs/adr/0003-records-declare-baselines.md`.)

### What stays out of the record

These are per-detection runtime values. They live only on the scanner
Finding, never in an AVE record: `confidence`, `confidence_band`, the actual
`evidence_stage` reached, `confidence_reason`, `derived`, `line`, `match`,
`suppressed`, and the engine that actually fired.

### Output and distribution

- **SARIF.** A scanner emits Findings as SARIF with the `ave_id` in `ruleId`
  and referenced under `taxonomies`, plus `aivss_score`, `confidence`,
  `owasp_mcp`, and `mitre_atlas` in the properties bag. Because SARIF is
  already consumed by the GitHub Security tab and CI systems, AVE ids travel
  into those surfaces for free.
- **PiranhaDB and the public site.** The record set is ingested by PiranhaDB
  (the deploy-time `sync_records.py` export) and served at
  `api.piranha.bawbel.io` and the public registry at `aveproject.org`.
- **Crosswalks.** Published mappings let other scanners' finding types
  (SkillSpector's categories, ClawScan's types) resolve to AVE ids, so
  findings from different tools become comparable through the AVE layer.

### Adding a record

Use the `add-ave-record` skill. To keep the standard current with real
research without padding it, use the `research-new-attack-classes` skill,
which benchmarks the threat landscape against existing records and only
proposes a new record when a genuinely distinct behavioral class exists.

---

## Related documents

- `schema/ave-record.schema.json` — the record schema (v1.1)
- `docs/guides/schema-vs-finding.md` — record vs Finding in depth
- `docs/adr/0001-behavioral-fingerprints.md` — behavioral over signature
- `docs/adr/0002-immutable-ave-id.md` — why ids never change
- `docs/adr/0003-records-declare-baselines.md` — the declares/assigns split
- `docs/guides/aibom-alignment.md` — how records feed an OWASP AIBOM