# PRD — Critical/High attack class batch (5 new AVE records)

**Date:** 2026-07-10
**Status:** In progress — Decision 1 resolved, #32 (AVE-2026-00052) and #33
(AVE-2026-00053) implemented on `vendor-neutral`, not yet on `main`; #34/#35/#36 not
started
**Source:** `docs/agents/research/2026-07-10-benchmark.md` (research-new-attack-classes
skill, Phases 1-4), issues [#32](https://github.com/bawbel/ave/issues/32)-[#36](https://github.com/bawbel/ave/issues/36)
**Scanner coordination required: yes** — every record in this batch needs a coordinated
detection-rule PR in `bawbel/scanner` per CONTRIBUTING.md Step 4; none merges without one.
This AVE-side implementation used AVE's own `rules/pattern/` (this repo carries its own
reference rules alongside the standard, in addition to `bawbel/scanner`'s coordinated
copy) — the `bawbel/scanner` PR for AVE-2026-00052 is still outstanding.

---

## Why this is a PRD, not five add-ave-record runs

Individually each of these is a normal record addition. Together they share three
cross-cutting decisions that have to be made once, consistently, not five times
independently: what `detection_layer` value code-implementation vulnerabilities get,
how the `Tool Abuse` attack_class category should (or shouldn't) stretch to cover
code-level flaws instead of prompt-driven ones, and what order to ship them in given the
different rule-engine shapes they need. Treating this as a batch also matches the
skill's own framing in the benchmark report: 5 candidates from one research pass, not
five unrelated submissions.

---

## Problem

The 2026-07-10 benchmark (Phases 1-3) found 5 CRITICAL/HIGH-severity attack classes with
NVD-confirmed or named-trusted-vendor primary sources that AVE's current 51 records do
not cover, verified against the deletion test in ADR-0001's spirit (behavior, not
strings). All 5 were confirmed by the maintainer and have open GitHub issues
(#32-#36). This PRD is the implementation plan for turning those 5 issues into
published records with working detection.

## Goals

1. Five new AVE records, each schema-valid against `schema/ave-record-1.1.0.schema.json`.
2. Each record has at least one detection rule in `bawbel/scanner` (coordinated PR) with
   a positive and negative fixture, per the record → rule → fixture triangle
   (`ARCHITECTURE.md`).
3. Resolve the naming/taxonomy questions flagged as "open to discussion" in issues
   #32-#36 once, consistently, rather than ad hoc per record.
4. Keep the standard's existing boundary intact: behavioral fingerprints, not byte
   signatures; no enforcement-tool config in `mitigation` (Section 0 of the v1.1.0
   migration brief still governs).

## Non-goals

- Adding the `owasp_ast` field (flagged as future work in the v1.1.0 migration brief
  Section 7; not blocking this batch — issues #32-#36 already note "TBD" for it).
- Resolving the OAuth consent-hijack borderline candidate from the benchmark report. It
  was flagged, not confirmed, and stays a research note in `docs/agents/research/` until
  someone decides it clears AVE's component-behavior boundary.
- Independently re-verifying the NSA/CISA `CSI_MCP_SECURITY` PDF (direct fetch returned
  403 during research). It's corroborating context for issue #34, not the sole citation
  — #34 stands on the OX Security report and CSA research notes regardless.
- Any change to `add-ave-record` or `research-new-attack-classes` skill mechanics.

---

## Open decisions (need an answer before Phase 5 implementation starts)

### Decision 1 — `detection_layer` for code-implementation vulnerabilities

Issues #32 (`tool-implementation-command-injection`) and #33
(`mcp-resource-path-traversal`) both describe a flaw in a tool's **own server-side
handler code** (CWE-78, CWE-22) — not in a skill's natural-language content, which is
what every existing `content`-layer record describes. The schema's `detection_layer`
enum is fixed: `content | server_card | registry_metadata | runtime | transport`. None
of these precisely names "the vulnerable code is the tool's own implementation, found by
SAST/code review of source, not by scanning prompt text."

Both issues currently propose `content` as "closest existing enum value" with an
explicit flag that this stretches the taxonomy. Three options:

- **(a) Reuse `content`.** No schema change, ships immediately. Costs a small semantic
  overload: `content` now means both "natural-language instruction text" and "the tool's
  own source code," which a future reader of `docs/architecture/ave-architecture.md`'s
  five-layer table won't expect. Cheapest, and matches how AVE already tolerates
  `detection_layer` being a coarse five-bucket classification rather than a precise
  scanner-routing key (see `evidence_basis_engines` as the actual routing signal).
- **(b) Add a sixth enum value** (e.g. `implementation`). This is a structural schema
  change under CONTRIBUTING.md's "Schema changes" section — requires its own issue and a
  30-day comment period before merging, which blocks this entire batch on a slower
  track than the records themselves need.
- **(c) Leave `detection_layer` as `content` but make the distinction explicit in
  `behavioral_fingerprint` text only**, no schema change. Functionally identical to (a)
  with a documentation convention layered on top.

**Recommendation: (a)/(c) combined** — reuse `content`, and require
`behavioral_fingerprint` for these two records to state explicitly that the vulnerable
surface is the tool's *own implementation code*, not its declared instructions (both
draft fingerprints in #32/#33 already do this). Revisit as a real `(b)` schema-change
proposal only if a *third* code-implementation-vulnerability class shows up in a future
research pass — one overloaded bucket is a documentation note, three is a pattern that
earns its own enum value. This keeps the batch un-blocked and defers the schema question
until there's enough evidence to answer it well.

**RESOLVED 2026-07-10:** adopted as written — `detection_layer: content` for #32 and
#33, `behavioral_fingerprint` states the implementation-code surface explicitly, no
schema change opened. Applied starting with #32.

### Decision 2 — `attack_class` category for #32

#32 proposes `Tool Abuse - Implementation Command Injection`, flagged in the issue as
"may warrant its own category distinct from Tool Abuse" since every other `Tool Abuse -
*` record is prompt-driven. Recommend keeping it under `Tool Abuse` for this batch (least
taxonomy churn, and `attack_class` is free text, not an enum, so it costs nothing to
rename later without a schema change) rather than inventing a new top-level category for
one record. Revisit alongside Decision 1 if the pattern recurs.

### Decision 3 — severity presentation for #35

CVE-2025-32711 (EchoLeak) carries two different CVSS scores from two different assessors
(NIST 7.5 HIGH, Microsoft CNA 9.3 CRITICAL). The issue recommends the record state both
rather than picking one. Confirm: does AVE's `severity` field (single enum value) force a
choice, with the dual-score nuance living only in `references`/`description` prose? If
so, recommend `severity: HIGH` as the more conservative of the two (NIST's independent
assessment over the affected vendor's own CNA rating), with the AARF/`aivss.notes` field
carrying the Microsoft 9.3 figure as context. This is a real precedent-setting call for
the *next* multi-assessor CVE too, not just this record.

---

## Scope — the five records

| Issue | attack_class (draft) | detection_layer | Rule engine(s) | Sequencing rationale |
|---|---|---|---|---|
| [#32](https://github.com/bawbel/ave/issues/32) tool-implementation-command-injection | `Tool Abuse - Implementation Command Injection` | `content` (Decision 1) | semgrep, pattern | **Done: AVE-2026-00052.** AIVSS computed 7.5 HIGH (not the CRITICAL estimate); rationale in aivss.notes. `rules/pattern/` reference rule written in this repo (matches the corpus-wide convention — `rules/semgrep/`/`rules/yara/` are empty scaffolding for all 51 prior records too; the real semgrep implementation is the `bawbel/scanner` coordinated PR, still outstanding). |
| [#33](https://github.com/bawbel/ave/issues/33) mcp-resource-path-traversal | `Tool Abuse - Resource Path Traversal` | `content` (Decision 1) | semgrep, pattern | **Done: AVE-2026-00053.** AIVSS computed 6.3 MEDIUM (general-class score; notes explain a scanner may score an individual finding higher when the traversal target is known). `bawbel/scanner` PR outstanding, same as #32. |
| [#36](https://github.com/bawbel/ave/issues/36) code-execution-sandbox-escape | `Execution Hijack - Code Execution Sandbox Escape` | `runtime` | sandbox, llm | Single canonical CVE (2026-5752), but needs a runtime/sandbox fixture harness — more setup than #32/#33 |
| [#34](https://github.com/bawbel/ave/issues/34) mcp-stdio-launch-config-injection | `Supply Chain - MCP STDIO Launch Configuration Injection` | `registry_metadata` | pattern, llm | No single canonical CVE for the architecture pattern itself (per-platform instances); confidence_baseline drafted low (0.55) — needs the most detection-rule design work |
| [#35](https://github.com/bawbel/ave/issues/35) rendered-content-autofetch-exfiltration | `Data Exfiltration - Rendered Content Auto-Fetch` | `runtime` | pattern, llm, sandbox | Closest-call classification of the five (see benchmark report Phase 2 detail) — ship last, after the other four establish the batch's conventions, in case review pushes it toward VARIANT instead |

Per-record requirements (all five, per CONTRIBUTING.md Step 2):

- All 15 required fields present (`ave_id` assigned by maintainer per CONTRIBUTING.md
  Step 1 — not pre-assigned here; issues #32-#36 stay unassigned until each is picked up)
- AIVSS v0.8 score: AARF factors scored 0.0-1.0 with a one-line rationale per non-zero
  factor in the implementation PR description (per CONTRIBUTING.md's AIVSS section)
- `owasp_mcp` (required) + `mitre_atlas` where applicable — draft values already in each
  issue's "Proposed record skeleton," confirm during implementation
- `indicators_of_compromise` — draft IOCs already in each issue, minimum 1 required
- `references` — the NVD/vendor links already gathered in each issue's "Primary source"
  section
- `provenance_vector` / `trifecta_profile` / `mitigation` — populate at record-creation
  time (not deferred to a later null-then-enrich pass, since this batch starts from
  scratch, unlike the v1.1.0 migration's existing-corpus backfill)

---

## Scanner coordination

Every record needs a coordinated PR in `bawbel/scanner` before merge (CONTRIBUTING.md
Step 4 — "A record without a detection rule will not be merged"). Two rule-engine
shapes are needed across this batch, which is new territory for AVE's rule set:

- **SAST-style code-pattern rules** (#32, #33): scanning a tool/server's *own source
  code* for unsafe patterns (unsanitized shell-out, exact-string-match path blacklists)
  rather than scanning skill/prompt *content* for natural-language instructions. This is
  a different rule shape than every existing `content`-layer rule in `rules/pattern/`
  and `rules/semgrep/`, which all match instruction-like text. Flag for the scanner-side
  reviewer: confirm `PatternEngine`/`SemgrepEngine` can already target arbitrary source
  files the way they currently target skill/prompt files, or whether this needs a small
  scanner-side change too (would make this PRD's "scanner coordination" more than a
  rule-authoring exercise).
- **Runtime/sandbox-observed rules** (#34, #35, #36): all three have `confidence_baseline`
  drafted at 0.55-0.62, the lowest band in the corpus, reflecting genuine detection
  difficulty (distinguishing a malicious STDIO launch config from a legitimate one, or a
  markdown auto-fetch beacon from a normal image, needs more than a fixed pattern per the
  issues' own `evidence_basis_engines: [..., llm]` inclusion). Confirm with the scanner
  team whether `llm`-engine-basis rules have an established authoring pattern yet, or
  whether this batch is the first to need one.

---

## Rollout

1. Resolve Decisions 1-3 above (maintainer).
2. Implement in the sequencing order in the Scope table (#32, #33, #36, #34, #35),
   each via `add-ave-record`, each its own PR per CONTRIBUTING.md, each with a
   coordinated `bawbel/scanner` PR.
3. After all five merge: update `crosswalks/ave-to-owasp-mcp.md` (new rows),
   `README.md`'s records badge (51 → 56) and "Coverage by severity" table, and
   `PRODUCT.md`'s "Records published" count.
4. Close issues #32-#36 individually as each record + rule + fixtures merges and
   `pytest tests/ -x -q` is green (per the research-new-attack-classes skill's own
   closure criterion).

## Success criteria

- 5 new records, all valid against `schema/ave-record-1.1.0.schema.json`
  (`python scripts/validate_records.py` clean)
- 5 new detection rules in `bawbel/scanner`, each with a positive and negative fixture,
  `python scripts/check_fixtures.py` and `check_rule_coverage.py` clean
- `pytest tests/ -x -q` green in both repos
- Decisions 1-3 recorded somewhere durable (this PRD, or promoted into
  `ARCHITECTURE.md`/`LANGUAGE.md` if Decision 1 in particular recurs)

## Risks

- **Rule-engine gap**: if `bawbel/scanner`'s `PatternEngine`/`SemgrepEngine` genuinely
  can't target arbitrary source files yet (see Scanner coordination above), #32/#33 slip
  from "write a rule" to "extend the scanner," which changes this from a pure AVE-side
  PRD into a cross-repo one.
- **#35 reclassification risk**: benchmark report already flags this as the closest call
  of the five. If scanner-side review or the record write-up surfaces a cleaner fold into
  AVE-2026-00026 or 00039, drop it from this batch rather than force a weak new `ave_id`
  — matches the skill's own "no padding" hard rule.
- **Low confidence_baseline band (#34, #35, #36)**: three records in one batch landing at
  0.55-0.62 is a real shift from the corpus's typical 0.7-0.9 range for content-layer
  records. Worth a sanity check that this doesn't silently make bawbel-scanner noisier at
  these ave_ids than intended.
