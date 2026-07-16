# AVE v1.0.0 -> v1.1.0 Migration Brief

**For:** a Claude Code session with write access to the `ave` repository.
**Purpose:** evolve AVE from v1.0.0 to v1.1.0 as a stronger, more complete, and
strictly vendor-neutral behavioral standard for agentic components, while fixing
real data-quality issues in the current 51-record corpus. This version
deliberately does **not** add any enforcement-tool-specific fields; the companion
document `BAWBEL_GATE_MITIGATIONS_SPEC.md` explains where those live instead.

**How to use this document.** This is a complete task specification, not a
discussion starter. Section 3 is the exact schema diff. Section 4 is the exact,
mechanical hygiene fix. Section 5 is the migration script spec. Section 6 is the
enrichment workflow. Section 9 is the checklist. If something here conflicts with
what you find in the repo, stop and say so rather than reconciling silently.

## Status (confirmed against the live corpus)

Most of this brief has already executed. Confirmed directly against
AVE-2026-00028 as it exists in the live repo today, field by field:

- `schema_version: "1.1.0"` -- Section 5's migration script has run.
- `owasp_asi`, `mitre_atlas`, `nist_ai_rmf` present, no `_mapping` suffix
  anywhere, no nested `aivss.owasp_mcp_mapping` -- Sections 2.5 and 4.4's
  renames and removal are live.
- `provenance_vector.entry_class: "user_input"`,
  `provenance_vector.escalation: "data_to_instruction"`,
  `trifecta_profile.requires: ["untrusted_content"]`,
  `mitigation.strategy: ["validate_input", "isolate_scope"]`,
  `mitigation.enforcement_point: "runtime_proxy"`,
  `mitigation.trifecta_control: "break_untrusted_content"` -- every value
  matches the Section 3 schema's enums exactly. Section 6.2's draft-and-review
  enrichment has reached at least this record, and the implementation is
  faithful to the spec as written, not an approximation of it.
- `behavioral_vector: ["file-inject", "prompt-injection", "data-exfil"]` --
  short tags, not a raw payload dump. Section 4.2's retagging has reached this
  record.

**Still confirmed pending, by the same record:** the `references` "AVE
Registry" entry still points at `https://api.piranha.bawbel.io/records/...`.
Section 4.6 has not run yet, correctly, since it is gated on the org move
landing first (`AVE_ORG_MOVE_CHECKLIST.md` Section 7).

**Not yet confirmed either way:** whether every record has reached this same
enriched state, or only some. AVE-2026-00028 was not in the original Section
6.2 Priority 1 batch, which is a good sign the enrichment pass went wider than
just Priority 1, but one record is one data point. Before treating Section 6.2
as fully closed, run a corpus-wide check rather than extrapolate from this
single confirmation:

```bash
for f in records/AVE-2026-*.json; do
  jq -e '.provenance_vector and .trifecta_profile and .mitigation' "$f" > /dev/null \
    || echo "NOT YET ENRICHED: $f"
done
```

Sections 1 through 6 below are left in their original imperative form
("rename this field," "add this object") because they remain the accurate
record of what was done and why; treat them as historical specification, not
as a to-do list to re-run. Section 9's checklist is annotated with current
status per item.

---

## 0. The design principle that governs every decision below

AVE is a standard. A standard describes a vulnerability class in terms true for
everyone, and stops at the boundary where description ends and one vendor's
product begins. This is not a stylistic preference; it is the difference between
a standard other people implement and a proprietary format nobody else will
touch.

The mature security standards all draw this line the same way. A CVE record
describes a vulnerability: type, impact, references. It does not contain the
patch, the exploit, or a specific firewall rule; MITRE and CNAs explicitly do
not supply mitigation artifacts. The concrete, environment-specific enrichment
(CVSS scores, CWE taxonomy, CPE product coverage, exploited-in-the-wild status,
vendor patches) is added downstream by the NVD, CISA KEV, JVN, and vendor tools,
keyed by CVE ID, in separate systems. The CVE schema working group, debating
whether to add a structured remediation field at all, is converging on the
minimal shape: an enum of abstract routes (Eliminate / Defend / ...) or a tagged
reference URL, never the runnable control itself.

AVE v1.1.0 applies that exact line:

- **In AVE (the standard):** what the vulnerability is, how it behaves at every
  layer including runtime, how severe it is, what it maps to, how to detect it,
  and an **abstract** description of what class of defense mitigates it.
- **Not in AVE:** any runnable enforcement artifact tied to one tool's config
  format. bawbel-gate's capability-manifest fragments are bawbel-gate's data,
  keyed by AVE ID, living in the bawbel-gate repo. See
  `BAWBEL_GATE_MITIGATIONS_SPEC.md`.

This directly answers the question "should AVE cover runtime?" Yes, and it
already does correctly: runtime is a property of the vulnerability
(`detection_layer: runtime`, `detection_stage: runtime_observed`, the async,
A2A, memory-poisoning, and code-mode classes). v1.1.0 deepens that classification.
What v1.1.0 does not do is embed one product's runtime *config* into the record;
that would bind the standard to that product and is the failure mode this whole
design avoids.

## 1. Correction to prior planning

Earlier bawbel-gate design work (DESIGN.md Section 9) assumed AVE was already at
schema v1.1 and planned a "v1.1 -> v1.2" migration that inserted three fields,
one of which (`capability_mitigation`) carried a bawbel-gate manifest stanza
directly inside the AVE record. Both assumptions were wrong. The real schema,
checked against `ave-record-1.0.0.schema.json` and the live 51-record corpus, is
**v1.0.0**, and embedding the manifest stanza would have made AVE vendor-owned.
This brief supersedes that plan. After v1.1.0 ships, patch DESIGN.md Section 9
and ARCHITECTURE.md Section 4.3 to match; track that as a follow-up in the
bawbel-gate repo.

v1.1.0 is a semver minor bump in spirit (mostly additive) but includes three
field renames and one field removal (Section 2.5). That is a deliberate one-time
exception to the additive-only rule, justified in Section 2.5 by the fact that
AVE currently has zero external implementers, so the renames cost nothing
external now and would cost a second implementer's trust later. After this
version, additive-only resumes with no exceptions.

## 2. What changes

### 2.1 Runtime and provenance classification (new, belongs in the standard)

`provenance_vector`: where in the agent context supply chain the class enters and
what authority escalation it performs. A descriptive property of the
vulnerability, not of any defense. It reconciles with the existing
`detection_layer` rather than duplicating it (Section 3).

`trifecta_profile`: which of the three lethal-trifecta conditions (private-data
access, untrusted-content exposure, external-communication capability) make the
class exploitable. The lethal trifecta is now an industry concept (Simon
Willison / Palo Alto, cited in OWASP's Agentic Skills Top 10), not a
bawbel-gate concept, so classifying a record against it is standard-appropriate.
It is a deployment-applicability filter and does not affect `severity` or
`aivss_score`.

Both are runtime-shape classification. Both are true regardless of who defends
against the class or how. Both belong in AVE.

### 2.2 Abstract mitigation structure (new, replaces the free-text-only approach)

The current `remediation` is a required free-text string and stays. v1.1.0 adds
an optional structured `mitigation` object alongside it, carrying the **class**
of defense in vendor-neutral enums: what strategy neutralizes the vulnerability,
where an enforcement point would sit, and which trifecta leg to sever. Every
value is true for any enforcement tool. A second implementer reads
`strategy: [deny_by_default]` + `enforcement_point: runtime_proxy` and builds
their own control from it. This is the CVE working group's abstract-remediation
shape applied to agentic runtime. It is explicitly **not** a config fragment.

### 2.3 `example_patterns` (new, closes finding 4.2)

Illustrative attack payloads and code fragments, distinct from
`behavioral_vector` (short attack-path tags) and `indicators_of_compromise`
(defender-facing observables). Researcher-facing, for detection-rule authoring.
Needed because two-thirds of the corpus currently misuses `behavioral_vector`
to hold exactly this content (Section 4.2).

### 2.4 Thin submission path (new capability, not a new field)

To keep AVE contributable by outsiders and not just its authors, v1.1.0 formally
splits **submit-required** from **enrichment-added** fields. A contributor should
be able to file a valid draft record with a small core; AIVSS scoring, framework
mappings, detection-engine hints, and the structured `mitigation` object are
added during review, by maintainers or tooling, exactly as the NVD enriches a
thin CVE after publication. This is a `status: "draft"` lifecycle change plus a
documented minimal field set (Section 6), not a schema field. It lowers
contributor burden, which is a precondition for AVE ever having contributors
beyond its authors.

### 2.5 Renames and one removal (one-time breaking change)

| Current | New | Why |
|---|---|---|
| `owasp_mapping` | `owasp_asi` | Values are `ASI##` (OWASP Agentic Security Initiative Top 10). Naming the field after the code family it holds matches `owasp_mcp`'s pattern and reads correctly in a schema browser. Verified current: ASI is the active identifier prefix for the OWASP Top 10 for Agentic Applications 2026. (Note: a separate, newer OWASP project, Agentic Skills Top 10, uses `AST##`; that is a future additional mapping field, not a rename of this one. See Section 7.) |
| `mitre_atlas_mapping` | `mitre_atlas` | `_mapping` conveys nothing the field name and array type don't. |
| `nist_ai_rmf_mapping` | `nist_ai_rmf` | Same. |
| `aivss.owasp_mcp_mapping` | *(removed)* | Duplicates the required top-level `owasp_mcp` and silently drifted out of sync with it on five records (finding 4.3). Two sources of truth for one fact; delete the nested one, top-level is authoritative. |

## 3. Schema diff

Two ordered parts: renames and removal first, additions second. Bump `$id` to
`.../ave-record-1.1.0.schema.json` and the description version string to
"Schema v1.1.0." Do not add any new field to the `active`-record `required` list
(Section 6 governs the required set and loosens it for drafts, not tightens it).

### 3.1 Renames and removal

Rename property `owasp_mapping` -> `owasp_asi` (keep the `^ASI[0-9]{2}$` item
pattern; update its description to "OWASP Agentic Security Initiative (ASI) Top
10 categories. Format: ASINN."). Rename `mitre_atlas_mapping` -> `mitre_atlas`.
Rename `nist_ai_rmf_mapping` -> `nist_ai_rmf`. Delete `owasp_mcp_mapping` from
the `aivss` object's `properties`.

### 3.2 Additions

```json
"provenance_vector": {
  "type": "object",
  "additionalProperties": false,
  "description": "Where in the agent context supply chain this class enters and what authority escalation it performs. A descriptive property of the vulnerability, independent of any defense. Optional; absent means not yet classified, not 'does not apply'.",
  "properties": {
    "entry_class": {
      "type": "string",
      "description": "Origin point in the context supply chain. Use the record's own detection_layer value when the class is layer-scoped; use a session-scoped token when more precise.",
      "pattern": "^(content|server_card|registry_metadata|runtime|transport|tool_response|tool_schema|server_card_document|model_generated|memory|retrieved_document|user_input|operator_config|skill_file)$"
    },
    "payload_surface": {
      "type": "string",
      "description": "The concrete field or channel carrying the payload, e.g. tool_schema.description, server_card.jwks_uri, http.header.host. Free text; controlled vocabulary grown by convention."
    },
    "escalation": {
      "type": "string",
      "enum": ["data_to_instruction", "instruction_to_capability", "capability_to_identity"],
      "description": "The authority jump this class performs when exploited. If none fits, leave the whole object absent rather than forcing a fit."
    }
  }
},
"trifecta_profile": {
  "type": "object",
  "additionalProperties": false,
  "description": "Which lethal-trifecta conditions make this class exploitable (Simon Willison / Palo Alto; cited in OWASP Agentic Skills Top 10). A deployment-applicability filter. Does not affect severity or aivss_score.",
  "properties": {
    "requires": {
      "type": "array",
      "minItems": 1,
      "items": {"type": "string", "enum": ["private_data", "untrusted_content", "external_comms"]},
      "description": "Conditions that must be present for the class to be exploitable."
    },
    "amplifies": {
      "type": "array",
      "items": {"type": "string", "enum": ["private_data", "untrusted_content", "external_comms"]},
      "description": "Conditions that worsen impact without being strict preconditions."
    }
  }
},
"mitigation": {
  "type": "object",
  "additionalProperties": false,
  "description": "Abstract, vendor-neutral description of what class of defense neutralizes this class. Names the strategy, not a runnable control. Any enforcement tool can build a concrete control from these values; no tool's config syntax appears here. The prose remediation field remains the required human-readable form; this object is the structured, machine-consumable companion.",
  "properties": {
    "strategy": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string",
        "enum": [
          "deny_by_default",
          "require_human_approval",
          "pin_integrity",
          "isolate_scope",
          "validate_input",
          "sanitize_output",
          "verify_identity",
          "sever_egress",
          "least_privilege",
          "provenance_label"
        ]
      },
      "description": "The class(es) of control that neutralize this vulnerability. Vendor-neutral verbs, not product config."
    },
    "enforcement_point": {
      "type": "string",
      "enum": ["static_scan", "server_card_fetch", "runtime_proxy", "agent_framework", "downstream_system", "network_layer"],
      "description": "Where in the agent lifecycle a defense against this class would sit."
    },
    "trifecta_control": {
      "type": "string",
      "enum": ["break_private_data", "break_untrusted_content", "break_external_comms", "not_applicable"],
      "description": "Which trifecta leg to sever to neutralize the class, conceptually. not_applicable for classes not exploitable via the trifecta."
    }
  }
},
"example_patterns": {
  "type": "array",
  "items": {"type": "string"},
  "description": "Illustrative attack payload strings or code fragments demonstrating this class. Distinct from behavioral_vector (short tags) and indicators_of_compromise (defender observables). Researcher-facing examples for detection-rule authoring, not verbatim signatures."
}
```

Note on `entry_class` values: they are underscore-cased neutral tokens, not any
tool's internal class strings. A mapping from AVE `entry_class` to a tool's own
class names lives in that tool, not here. `entry_class` is a superset of
`detection_layer`'s five values plus finer session-scoped tokens.

## 4. Record hygiene fixes (mechanical, independent of the new fields)

### 4.1 Strip template artifacts

Roughly half the corpus (the 2026-04-19 and 2026-04-20 batch, IDs
AVE-2026-00016 through 00040, but confirm programmatically, do not trust the
range) carries authoring-template residue: a trailing `---` on `description`,
`behavioral_fingerprint`, `detection_methodology`, and `remediation`, and
trailing empty-string entries in `indicators_of_compromise` and sometimes
`behavioral_vector`.

For every record, strip a trailing `\s*-{2,}\s*$` from those four string fields.
For every string-array field, drop empty or whitespace-only elements, then
re-check `minItems` still holds (it must; `""` was never a real indicator).
Script it, diff the output, do not hand-edit.

### 4.2 Repopulate `behavioral_vector`, populate `example_patterns`

`behavioral_vector` is used three ways across the corpus: correct short tags
(records 1-3), empty (4-15), and repurposed to hold full example payloads
(16-51). The schema documents it as short tags. Fix: for records 16-51, move the
existing array content verbatim into the new `example_patterns` field, then draft
fresh short kebab-case tags for `behavioral_vector`. For records 4-15, draft tags
(currently empty). This is an LLM batch task over all 51, grounded in each
record's `attack_class`, `title`, and `behavioral_fingerprint`; a human
spot-checks a sample of 10-15 rather than reviewing all 51. No enforcement
consequence rides on tag quality, so no review gate.

### 4.3 Sync then remove on records 41-45

Five records (AVE-2026-00041 through 00045) have top-level `owasp_mcp` stuck at a
placeholder `["MCP01"]` while the nested `aivss.owasp_mcp_mapping` holds the
correct, specific value:

| Record | top-level `owasp_mcp` (wrong) | nested (correct) |
|---|---|---|
| 00041 | `["MCP01"]` | `["MCP03", "MCP09"]` |
| 00042 | `["MCP01"]` | `["MCP05", "MCP10"]` |
| 00043 | `["MCP01"]` | `["MCP03", "MCP10"]` |
| 00044 | `["MCP01"]` | `["MCP06", "MCP10"]` |
| 00045 | `["MCP01"]` | `["MCP02", "MCP07"]` |

Copy the nested value up to top-level `owasp_mcp` for these five, then delete
`aivss.owasp_mcp_mapping` from all 51 (per 2.5). On the other 46 the nested value
was already redundant; drop it without copying.

### 4.4 Apply renames

Rename `owasp_mapping` -> `owasp_asi`, `mitre_atlas_mapping` -> `mitre_atlas`,
`nist_ai_rmf_mapping` -> `nist_ai_rmf` across all 51 records. Mechanical key
rewrite, scriptable exactly.

### 4.5 Remove vendor-name boilerplate (highest priority, ship first and alone)

A large share of records carry a near-identical opening line in
`detection_methodology`: "1. Static scan: search for patterns matching this
attack class using bawbel-scanner." Unlike every other finding in this
document, this is not an API-layer or schema-layer coupling issue; the vendor
name is stored directly in the standard's own record data. A reader opening
any of these records sees the standard's own detection guidance naming one
company's product, which is the single most concrete, easiest-to-spot piece of
evidence against the neutral-standard framing Section 0 exists to establish.

Fix this before any external technical audience reads the raw records, ahead
of the OWASP `#project-genai` outreach specifically. It ships independently
and first: a text edit to existing fields on the current
`schema_version: "1.0.0"` records, no schema change, no version bump, no
dependency on Sections 3 or 5. If the outreach has a target date, this is the
one hygiene item that gates it.

Grep every string field on every record for `bawbel-scanner`, `bawbel scan`,
and `bawbel` generally, not only `detection_methodology`; check `remediation`
and `description` too before assuming the pattern is confined to one field.
Replace with neutral phrasing, e.g. "using a compatible static analysis tool"
or "using pattern-matching against the indicators below."

### 4.6 Repoint the "AVE Registry" reference URL (unblocked, run now)

Every record's `references` array carries an entry shaped like:

```json
{
  "tag": "AVE Registry",
  "text": "AVE-2026-00046 -- AVE behavioral vulnerability registry",
  "url": "https://api.piranha.bawbel.io/records/AVE-2026-00046"
}
```

The `url` points at a Bawbel-owned, non-neutral domain as the standard's own
canonical self-citation, in every record. Same class of finding as 4.5: not
prose naming a vendor, but a citation baked into the data. This does not
require standing up a neutral API first; a citation can point at an
already-existing static artifact.

**Dependency: satisfied.** `AVE_ORG_MOVE_CHECKLIST.md` Sections 3 and 7 have
both landed; `aveproject/ave` is the repo's final home and `aveproject.org`
resolves. Run this now. Not yet independently confirmed executed against the
live corpus; check a record's `references` array before assuming it ran.

**Fix:** replace the `url` value on every record's "AVE Registry" reference
with the record's own path in the `aveproject/ave` repo:

```
https://github.com/aveproject/ave/blob/main/records/AVE-2026-XXXXX.json
```

Confirm the actual file path convention in the live repo before scripting this;
the pattern above assumes `records/AVE-2026-NNNNN.json` matches what
`AVE_ORG_MOVE_CHECKLIST.md` and this brief have assumed throughout, but verify
against the real tree rather than trust the assumption blindly. If `ave-site`
later grows per-record pages at `aveproject.org/records/AVE-2026-XXXXX`, that
becomes the better target and this can be re-run once; not before then.

**Validate:**

```bash
grep -rl "api.piranha.bawbel.io/records" records/AVE-2026-*.json
# expect zero results after the fix
```

Commit message: `fix(ave): repoint AVE Registry reference URLs to github.com/
aveproject/ave, remove self-citation to a non-neutral domain`

## 5. Migration script

```
scripts/migrate_ave_v1_1_0.py
  --in  records/            # 51 x AVE-2026-*.json at schema_version 1.0.0
  --out records/            # in-place
  --schema schemas/ave-1.1.0.schema.json
```

Behavior: bump `schema_version` to `"1.1.0"`. Apply the 4.4 renames and the
`aivss.owasp_mcp_mapping` deletion (safe, exact). Insert `provenance_vector`,
`trifecta_profile`, and `mitigation` as `null` on every record. Do not touch
`example_patterns` or `behavioral_vector` (those are the 4.2 content task) and do
not draft the three new nullable objects (that is Section 6, run separately over
the freshly-versioned records). Idempotent, git-diffable, validates each record
against the new schema on write, never classifies.

Run order: 4.1 artifact strip, 4.3 owasp_mcp sync, 4.4 renames, then this script,
then Section 6 enrichment.

## 6. Enrichment workflow: required vs added, and how the new objects get filled

### 6.1 Submit-required vs enrichment-added (the thin-submission split)

v1.1.0 documents two tiers. A draft record (`status: "draft"`) is valid with only
the core: `ave_id`, `schema_version`, `status`, `title`, `description`,
`attack_class`, `behavioral_fingerprint`, and at least one `references` entry.
Everything else, including `severity`, the full `aivss` object, framework
mappings, `indicators_of_compromise`, `remediation`, and the three new nullable
objects, is enrichment, added before a record moves `status` to `active`.

Implementation: the schema keeps its current `required` list for `active`
records (so published records stay complete), but applies a *reduced* required
set to records with `status: "draft"`, via JSON Schema `if`/`then`
(`if status is draft then require [core] else require [full]`). Document the core
set prominently in CONTRIBUTING so a contributor knows the eight fields that get
them a valid draft.

This is the CVE model: thin submission, downstream enrichment. It is the answer
to "the record is too complicated for a contributor to feed all the fields" that
does not involve making the standard shallower.

### 6.2 Filling `provenance_vector`, `trifecta_profile`, `mitigation`

These three describe the vulnerability and carry no enforcement config, so
unlike the removed `capability_mitigation` they do not need a product-side review
gate. They do benefit from consistency, so:

**Draft pass (LLM, all 51 at once):** propose `provenance_vector`,
`trifecta_profile`, and `mitigation` for every record from its existing
`attack_class`, `description`, `behavioral_fingerprint`, `detection_layer`,
`indicators_of_compromise`, and `example_patterns`. Some records legitimately
draft to `trifecta_control: not_applicable` or an absent `trifecta_profile`
(e.g. AVE-2026-00014, pure social engineering with no tool-call path); that is a
correct outcome.

**Review pass (human, prioritized):** a maintainer confirms the drafts. Priority
order, driven by which records the bawbel-gate demo and PiranhaDB mitigation
lookups will consume first: (1) AVE-2026-00041, 00042, 00045, 00046, 00050,
00051; (2) remaining `mcp_server` / `server_card` / `transport` records;
(3) HIGH and MEDIUM `skill` records with a clear trifecta shape; (4) the rest,
ongoing. This is standard-quality review (is the classification correct), not
enforcement-safety review; the enforcement-safety gate lives on the bawbel-gate
side (`BAWBEL_GATE_MITIGATIONS_SPEC.md`).

## 7. Future mapping fields (not this version, noted so they are not forgotten)

- `owasp_ast`: OWASP Agentic Skills Top 10 (`AST##`), a separate active OWASP
  project targeting the skill content layer. Many AVE `skill` records will map
  cleanly. Add as an optional field in a future additive version once AST10 IDs
  stabilize.
- `cwe`: several records already cite CWE IDs in `references` as prose; a
  structured `cwe` array (`^CWE-[0-9]+$`) would make AVE queryable by CWE and is
  a strong candidate for the same future version. This also positions AVE for the
  CWE-upstream-citation path in the trust strategy.
- `reversibility` (or `action_class`): a fourth candidate field, sourced from
  external community input rather than internal design, documented in full below
  because the framing is precise enough to build against directly once this is
  scheduled.

  **Source:** OWASP `www-project-artificial-intelligence-vulnerability-scoring-system`
  repo, issue #36 ("Discussion: Action-Class Authority as a scoring dimension for
  autonomous-execution risk"), opened by Mayur021 (Mayur Agnihotri, OWASP AISVS
  Contributor). Cross-references OWASP AISVS 1.0 controls C9.2.3, C9.2.4
  (reversibility classification and enforcement) and C9.2.10 (highest-impact-
  across-chain rule for multi-step/multi-agent action chains).

  **The four classes**, declared in a component's tool/action manifest, not
  inferred from a runtime self-report: `read-only` (agent can observe and
  report), `reversible` (action can be cleanly rolled back by the engine
  itself), `external-reversible` (undo routes through another system or
  person), `irreversible` (no clean rollback path).

  **Why this is a genuinely new axis, not a duplicate of `escalation` or
  `trifecta_profile`.** Per Mayur021's own framing in the thread, the three
  dimensions compose rather than overlap:
  - `provenance_vector.escalation` (already in this version): a **capability**
    dimension. How much authority a class confers.
  - `trifecta_profile` (already in this version): a **likelihood** dimension.
    What preconditions make the class reachable.
  - `reversibility` (this candidate): a **consequence** dimension. How
    recoverable the resulting effect is, independent of how it was reached or
    how much authority it took.

  **The scoring algorithm, stated precisely enough to implement directly:**
  reversibility is scored as the worst case reachable across the delegation or
  workflow graph at the moment of vulnerability, not the class stamped on the
  tool the agent nominally holds. A read-only agent that can delegate to a
  write-capable one is not read-only at the system level unless the delegation
  protocol provably enforces narrowing at every edge (monotonic and checkable,
  not assumed by convention). Any unclassified edge in that graph counts as
  irreversible; this is a fail-closed default on the delegation graph, matching
  the same fail-closed discipline already used elsewhere in this schema
  (Section 3, `provenance_vector.escalation`: "if none fits, leave the whole
  object absent rather than forcing a fit" is the same instinct applied to a
  different field).

  **Two records in the existing corpus are already, unprompted, real-world
  instances of exactly this failure mode** (identified by Mayur021 in the
  thread as "cleaner evidence for the axis than a synthetic example"):
  AVE-2026-00048 (unsafe agent delegation, no declared allowlist: the textbook
  case, parent's worst case must be scored, not the child's nominal class) and
  AVE-2026-00046 (tool hook hijack, our only CRITICAL record: reachable class
  becomes unbounded the moment declared scope is silently violated).

  **Status:** not scheduled, no timeline committed in either direction (matches
  Mayur021's own "no timeline pressure from my side"). When this is designed,
  do it against the actual shipped AISVS C9.2.3/C9.2.4/C9.2.10 text, not a
  paraphrase of it, and credit issue #36 and Mayur021 by name in the schema
  changelog when it lands; the three-dimension decomposition above is his
  framing, not independently derived.

All three are additive and neutral. None are in v1.1.0; listing them here keeps
the v1.1.0 scope tight while ensuring none of this is lost between now and
whenever it's actually scheduled.

### 7.1 Considered and rejected: a `cisco_aitech` crosswalk field

Cisco AI Defense's skill-scanner project (Apache-2.0) publishes its own threat
taxonomy (`AITech-*`/`AISubtech-*` codes) and was reviewed as a candidate fifth
future field, alongside `owasp_ast`, `cwe`, and `reversibility` above. Decided
against, recorded here so it is not silently re-proposed later:

Cisco's taxonomy is a single vendor's own framework backing a commercial product
line, not an institutionally neutral, multi-stakeholder standard the way
OWASP ASI, MCP Top 10, ATLAS, and CWE are. A schema field is a much stronger
commitment than the prose warning around it can offset: it is permanent, it
sits next to the genuinely neutral crosswalk fields, and it invites the
question "why Cisco and not Snyk, Endor Labs, Trend Micro, or any other vendor
in a crowded field," which has no principled answer once one vendor is
included. It would also have repeated, in a milder form, the exact mistake
`capability_mitigation` was removed from this schema to avoid (Section 0): a
standard embedding one vendor's artifact stops being a standard.

The genuinely useful output of the Cisco research does not require a schema
field: two new records (AVE-2026-00057, AVE-2026-00058, drafted in
`AVE_CISCO_SKILLSCANNER_CROSSWALK.md`) and one hygiene fix to AVE-2026-00029,
each citing skill-scanner as a normal `references` entry, exactly the same
treatment already given to the NDSS paper, PortSwigger, and other non-standards
sources cited elsewhere in the corpus. Citation in `references` is the correct
altitude for interoperating with a vendor's tool; a structured crosswalk field
is not.

## 8. Validation and CI

- `jsonschema` (draft 2020-12) validation of all 51 records against
  `ave-1.1.0.schema.json`, including the conditional draft-vs-active required
  sets (6.1).
- No record has both an old field name and its new name (catches partial
  migration).
- `aivss.owasp_mcp_mapping` is absent from every record.
- `example_patterns` and `behavioral_vector` are never both empty on the same
  record post-4.2.
- `mitigation`, where present, contains only schema enum values; a free-text or
  config-shaped value in `mitigation` fails CI. This check is the machine-
  enforced guarantee that no enforcement config leaks back into the standard.
- PiranhaDB schema negotiation serves both `1.0.0` (old field names, no new
  fields) and `1.1.0`; the `1.0.0` path maps renamed fields back to their old
  names, not merely omits the new ones, so existing scanner and IDE consumers are
  unaffected.

## 9. Task checklist

Status annotations added after live-corpus confirmation via AVE-2026-00028; see
the Status section at the top of this document for the evidence behind each.

1. **[DONE, confirmed]** Section 4.5 vendor-name boilerplate strip.
   AVE-2026-00028's `detection_methodology` carries no `bawbel-scanner`
   reference. Recommend the corpus-wide grep in the Status section above to
   confirm this holds for every record, not only this one.
2. **[DONE]** Confirm Section 4 findings against live repo state; superseded by
   this update.
3. **[DONE, confirmed]** Section 4.1-4.4 hygiene (artifact strip, owasp_mcp
   sync, renames, nested `aivss.owasp_mcp_mapping` deletion). Confirmed by
   AVE-2026-00028: renamed fields present, no `_mapping` suffix, no nested
   duplicate.
4. **[DONE, confirmed]** `behavioral_vector` retag (4.2). AVE-2026-00028 shows
   short tags, not raw payload content. `example_patterns` population not
   independently confirmed by this record (it has none, which may be correct
   for this record or may mean the field was skipped; check a record known to
   have needed one, e.g. AVE-2026-00041, before closing this item fully).
5. **[DONE, confirmed]** Section 3 schema diff live. Confirmed field-for-field
   against AVE-2026-00028: `provenance_vector.entry_class` and `.escalation`,
   `trifecta_profile.requires`, and every `mitigation` sub-field all match the
   Section 3 enums exactly.
6. **[DONE, confirmed]** Section 5 migration script ran. AVE-2026-00028 carries
   `schema_version: "1.1.0"`.
7. **[DONE, at least partially confirmed]** Section 6.2 draft pass. This
   record's `provenance_vector`/`trifecta_profile`/`mitigation` are populated
   with real values, not null, so drafting reached at least this record. Run
   the corpus-wide check in the Status section to confirm coverage across all
   records rather than assume from one.
8. **[LIKELY DONE, needs corpus-wide confirmation]** Section 6.2 review pass.
   AVE-2026-00028 was not in the original Priority 1 batch (41, 42, 45, 46, 50,
   51), so its enrichment being complete suggests review went wider than
   Priority 1 alone. Cannot confirm from one record whether every record has
   been reviewed versus only drafted; run the corpus-wide check before treating
   this as fully closed.
9. **[STATUS UNKNOWN, verify directly]** PiranhaDB schema negotiation for both
   `1.0.0` and `1.1.0`. Nothing in a single AVE record can confirm this; check
   PiranhaDB's own deployment directly.
10. **[STATUS UNKNOWN, verify directly]** Hand off `BAWBEL_GATE_MITIGATIONS_SPEC.md`
    to the bawbel-gate repo; file the DESIGN.md/ARCHITECTURE.md version-number
    correction. Neither is confirmable from an AVE record; check the bawbel-gate
    repo directly.
11. **[ONGOING BY DESIGN]** Section 6.2 review Priorities 2-4, not a blocker for
    bawbel-gate M0.
12. **[NO ACTION, unchanged]** Section 7's `reversibility`/`action_class` field
    remains unscheduled by design.
13. **[UNBLOCKED, ready to run]** Section 4.6, repoint the "AVE Registry"
    reference URL. AVE-2026-00028's reference pointed at
    `api.piranha.bawbel.io` as of its last check, before the gating condition
    was met. `AVE_ORG_MOVE_CHECKLIST.md` Sections 3 and 7 have since landed;
    the gate is open. Re-check a live record before assuming this has already
    run on its own.