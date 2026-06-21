# AVE Changelog

All notable changes to the Agentic Vulnerability Enumeration standard are documented here.

Format: [Semantic Versioning](https://semver.org). Schema versions and record set versions are tracked together.

---

## [1.1.0] — 2026-06-21

### Summary

- All 48 records migrated from schema_version 0.2.0 → 1.0.0
- Schema v1.0.0 is now the active schema for all published records
- Evidence declaration fields backfilled on all 48 records (canonical values from evidence-declarations-all-48.json)
- Detection rules and test fixtures added for all 48 original records — 96 tests passing
- 3 new records: AVE-2026-00049, AVE-2026-00050, AVE-2026-00051 — record set now at 51, 102 tests passing
- AIVSS scores corrected on 6 records (formula applied, invalid ThM values fixed)
- AVE-in-SARIF convention published: `docs/specs/ave-in-sarif.md`
- First research-new-attack-classes benchmark report: `docs/agents/research/benchmark-2026-06.md`
- `--skip-validation` flag can now be removed from ave-site builds

### All 48 records — fields added or corrected

- `schema_version`: `"0.2.0"` → `"1.0.0"`
- `severity` promoted to top level (was at `aivss.aivss_severity`)
- `aivss_score` promoted to top level (was only at `aivss.aivss_score`)
- `references` converted from URI strings to `{tag, text, url}` objects
- `status`, `published`, `researcher`, `researcher_url` backfilled where missing
- `component_type` normalised: `mcp` → `mcp_server`, `mcp-server-card` → `mcp_server`, `rag` → `other`
- `"prompt"` added to the `component_type` enum in schema v1.0.0

### Evidence declarations — all 48 records

Six fields backfilled on every record: `evidence_kind_default`, `detection_stage`, `detection_layer`, `confidence_baseline`, `evidence_basis_engines`, `derivable_into`.

Priority records (authoritative `derivable_into` chains set):

| Record | evidence_kind_default | detection_stage | confidence_baseline |
|---|---|---|---|
| AVE-2026-00001 | multi_engine | static_detection | 0.83 |
| AVE-2026-00002 | tool_description_pattern | static_detection | 0.75 |
| AVE-2026-00042 | behavioral_pattern | runtime_observed | 0.62 |
| AVE-2026-00045 | tool_description_pattern | static_detection | 0.75 |
| AVE-2026-00048 | tool_description_pattern | static_detection | 0.83 |

### Detection rules and fixtures — all 51 records

Pattern rules and positive/negative fixtures written for all 51 records.
`pytest tests/ -v` → **102 passed** (51 records × 2 fixtures). Zero failures.

Coverage scripts:
- `python3 scripts/check_rule_coverage.py` → All 51 records have detection rules.
- `python3 scripts/check_fixtures.py` → All 51 rules have positive and negative fixtures.

### New records

| AVE ID | Attack class | Severity | AIVSS |
|---|---|---|---|
| AVE-2026-00049 | Supply Chain - HTTP Header Injection | HIGH | 7.2 |
| AVE-2026-00050 | Persistence - Parasitic Toolchain | HIGH | 7.2 |
| AVE-2026-00051 | Supply Chain - OAuth Discovery Rebinding | HIGH | 7.2 |

Each record ships with a detection rule and positive/negative fixtures.
Identified from the research-new-attack-classes benchmark (Task 11): these were the three confirmed genuine gaps across MCPSecBench, FSF-MCP, MCP-SafetyBench, and Hou et al. 2025.

### AIVSS score corrections

Six records had incorrect scores — formula `((cvss_base + AARS) / 2) × ThM` was not applied, and ThM values outside the valid set {0.75, 0.90, 1.0} were used.

| Record | Old score | New score | ThM fix |
|---|---|---|---|
| AVE-2026-00046 | 9.1 | 9.2 | 0.9 → 1.0 (in-the-wild) |
| AVE-2026-00047 | 7.8 | 7.6 | 0.85 → 1.0 (invalid → in-the-wild) |
| AVE-2026-00048 | 8.2 | 7.7 | 0.85 → 0.90 (invalid → PoC exists) |
| AVE-2026-00049 | 7.5 | 7.2 | 0.85 → 1.0 (invalid → in-the-wild) |
| AVE-2026-00050 | 7.8 | 7.2 | 0.88 → 0.90 (invalid → PoC exists) |
| AVE-2026-00051 | 8.1 | 7.2 | corrected; cvss_base raised to 9.5 to match token-theft vector |

All 51 records now pass formula verification. Severity bands unchanged.

### Specifications and research

- `docs/specs/ave-in-sarif.md` — AVE-in-SARIF convention v1.0. Defines how AVE findings travel as SARIF to reach GitHub Security tab and CI systems. Covers required fields, severity mapping, taxonomies block, and a complete minimal SARIF example for AVE-2026-00001.
- `docs/agents/research/benchmark-2026-06.md` — First research-new-attack-classes benchmark report. Maps 87 classes across 6 external datasets (MCPSecBench, FSF-MCP, Hou et al. 2025, MCP-SafetyBench, MCPTox, OpenClaw) against the AVE record set. Identifies 1 genuine gap (resource exhaustion / agentic DoS) and confirms Hou et al. 2025 is fully covered (16/16).

### New files

- `scripts/migrate-records.js`
- `scripts/backfill-evidence.js`
- `scripts/merge-evidence-declarations.js`
- `scripts/check_rule_coverage.py`
- `scripts/check_fixtures.py`
- `docs/migrations/evidence-declarations-all-48.json`
- `docs/specs/ave-in-sarif.md`
- `docs/agents/research/benchmark-2026-06.md`
- `tests/test_fixtures.py`
- `rules/pattern/AVE-2026-000{03..40}.py` (43 new rules)
- `rules/pattern/AVE-2026-000{41,43,44,46,47,49,50,51}.py`
- `tests/fixtures/AVE-2026-000{03..51}_{positive,negative}.md` (96 new fixtures)

---

## [1.0.0] — 2026-06-18

### The first stable release of the AVE standard.

This release establishes AVE as a production-ready open standard for enumerating behavioral vulnerability classes in agentic AI components — skill files, MCP servers, plugins, and agent tools. It defines the canonical schema, the record/rule/fixture validation model, the framework alignment layer, and the scanner evidence contract.

---

### Schema v1.0.0

The canonical schema is published at:
`https://ave.bawbel.io/schema/ave-record-v1.0.0.schema.json`

**15 required fields** — the minimum a record must have to be published:

```
ave_id · schema_version · status · published
title · description · attack_class · severity · behavioral_fingerprint
aivss · owasp_mcp
indicators_of_compromise · remediation
references · researcher
```

**Key schema decisions locked in this release:**

- `additionalProperties: false` — unknown fields are a validation error, not silently ignored
- `ave_id` format enforced: `AVE-YYYY-NNNNN`, immutable once published
- `owasp_mcp` required with `minItems: 1` — every record must have at least one OWASP MCP anchor
- `owasp_mapping`, `mitre_atlas_mapping`, `nist_ai_rmf_mapping` — optional; add when applicable, never forced
- `indicators_of_compromise` required with `minItems: 1` — defenders need something actionable
- `references` required with `minItems: 1` — every record must trace to a citable primary source
- `researcher` required — records must be attributable
- `severity` and `aivss.aivss_score` must agree (CRITICAL implies score ≥ 9.0)

**Full AIVSS v0.8 object** — including the optional `aarf` block with 10 named agentic amplification factors:
autonomy, tool_use, multi_agent, non_determinism, self_modification, dynamic_identity, persistent_memory, natural_language_input, data_access, external_dependencies.

**Scanner evidence declarations** (all optional) — the declares-vs-assigns contract between the standard and implementing scanners:
`evidence_kind_default`, `detection_stage`, `detection_layer`, `confidence_baseline`, `evidence_basis_engines`, `derivable_into`.

**Ecosystem fields** added from real-world records:
`component_type`, `affected_platforms`, `affected_registries`, `behavioral_vector`, `mutation_count`, `detection_methodology`, `kill_switch_active`, `aivss_score` (top-level shortcut), `cvss_base_vector`.

---

### Framework alignment

Every AVE record maps to the frameworks the security field already trusts:

| Framework | Field | Format |
|---|---|---|
| OWASP MCP Top 10 | `owasp_mcp` | `MCPNN` — required |
| OWASP Agentic AI Top 10 | `owasp_mapping` | `ASINN` — optional |
| MITRE ATLAS | `mitre_atlas_mapping` | `AML.Txxxx` — optional |
| NIST AI RMF | `nist_ai_rmf_mapping` | `MAP-N.N` — optional |
| OWASP AIVSS v0.8 | `aivss` | full object — required |

`mitre_atlas_mapping` is validated to the `AML.Txxxx` or `AML.Txxxx.000` format. Non-ATLAS technique IDs are rejected at validation time.

---

### Record set

Initial record published: **AVE-2026-00001** — Metamorphic payload via external config fetch.

The full 48-record set is under active migration to schema v1.0.0. Records that have not yet been migrated remain in the repository at schema version 0.2.0 and will be updated in v1.1.

---

### Tooling

**`ave.bawbel.io`** — the public registry website launched alongside this release.
Five pages: landing, searchable registry, crosswalks, architecture guide, schema reference.
Features: live search across ids/titles/attack classes/IOCs/frameworks, severity/class/layer filters, sortable table, detail drawer with provenance-first display, AIVSS matrix, MITRE ATLAS and OWASP chips, capability chain, per-record canonical citation with copy button, deep-link permalinks (`#AVE-YYYY-NNNNN`), SEO meta + Open Graph + JSON-LD structured data, PWA manifest, responsive down to 375px.

**`bawbel/ave-site`** — separate repository for the website.
Wired to this repo via GitHub Actions `repository_dispatch` — pushing records to `bawbel/ave` automatically triggers a rebuild and deployment of the site.

**`scripts/build-records.js`** — build script that reads `records/*.json`, validates against the schema, sorts by severity, and emits `records.js`. Exits non-zero on validation failure so CI never deploys a broken record.

---

### Architecture decisions (ADRs)

Three ADRs are locked and documented in `docs/adr/`:

| ADR | Decision |
|---|---|
| 0001 | Behavioral fingerprints over byte signatures |
| 0002 | `ave_id` is immutable once published — deprecated, never renumbered or deleted |
| 0003 | Records declare evidence baselines; scanners assign per-detection actuals |

---

### What does not change between versions

- Published `ave_id` values are permanent
- The `$id` URL for schema v1.0.0 is permanent: `https://ave.bawbel.io/schema/ave-record-v1.0.0.schema.json`
- The AIVSS spec version is `"0.8"` (a constant, not versioned by AVE)

---

## Planned for v1.2

- Detection rules and fixtures for all 48 records (96 tests)
- New records for confirmed gaps: header injection (BadHost), parasitic toolchain, OAuth discovery rebinding
- Toxic-flow chain derivation (`derivable_into`) research and completion
- Publish crosswalk files: `crosswalks/skillspector-to-ave.json`, `crosswalks/clawscan-to-ave.json`, `crosswalks/ave-to-ast10.json`
- AVE-in-SARIF convention: `docs/specs/ave-in-sarif.md`
- Research-new-attack-classes benchmark report
- OWASP project proposal: `docs/governance/owasp-proposal.md`