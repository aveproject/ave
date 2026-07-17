# AVE Changelog

All notable changes to the Agentic Vulnerability Enumeration standard are documented here.

Format: [Semantic Versioning](https://semver.org). Schema versions and record set versions are tracked together.

---

## [1.3.0] - 2026-07-17

### Summary

- 3 new records: AVE-2026-00057 through AVE-2026-00059 — record set now at 59,
  118 tests passing.
  - AVE-2026-00057: obfuscated/encoded skill payload designed to evade static
    scanners (base64/hex/marshal decode fed directly into eval/exec)
  - AVE-2026-00058: deceptive skill trigger or activation-scope manipulation
    via misleading manifest description
  - AVE-2026-00059: fragmented cross-tool-description prompt injection
    reassembled at a planted trigger (ShareLock-class), citing the original
    research plus Microsoft's 2026 MCP security checkpoint
- `owasp_mcp` corrected against `crosswalks/ave-to-owasp-mcp.md` during review,
  not just pattern-validated against the schema: AVE-2026-00057 was missing
  `MCP03` (Tool Poisoning) alongside `MCP04`; AVE-2026-00058's draft `MCP09`
  (Shadow MCP Servers) was a flat mismatch, corrected to `MCP03` + `MCP06`
  (Tool Poisoning, Intent Flow Subversion). `mitre_atlas: AML.T0051` on
  AVE-2026-00059 verified against MITRE's own published technique name (LLM
  Prompt Injection), not assumed from existing corpus convention.

---

## [1.2.0] - 2026-07-12

### Summary

- Schema v1.1.0: 3 field renames, 1 field removal, 4 new optional fields, draft-vs-active
  conditional required set. `schema/ave-record-1.1.0.schema.json` is now canonical;
  `ave-record-1.0.0.schema.json` stays frozen permanently. Merged via PR #37.
- All 51 original records migrated to `schema_version: "1.1.0"` and enriched with the 3
  new classification objects
- 5 new records: AVE-2026-00052 through AVE-2026-00056 — record set now at 56, 112 tests
  passing. Merged via PR #37.
- Phase 0 repo hygiene: CI code/dependency/secret scanning, OpenSSF Scorecard, 8 new
  README badges, two pre-existing packaging bugs fixed. On PR #38 (open, pending review
  at time of writing).
- `crosswalks/ave-to-owasp-mcp.md` regenerated from source-of-truth record data (found
  pre-existing drift, not just missing rows). `crosswalks/ave-to-ast10.json`/`.md`
  extended for the 5 new records. `clawscan-to-ave.json` / `skillspector-to-ave.json`
  target metadata synced to v1.1.0/56 records; their rule-level mappings are unchanged,
  since re-checking them requires each external tool's own current rule catalog.

### Schema v1.1.0

Field renames (owasp_mapping -> owasp_asi, mitre_atlas_mapping -> mitre_atlas,
nist_ai_rmf_mapping -> nist_ai_rmf) and removal (`aivss.owasp_mcp_mapping`, redundant
with top-level `owasp_mcp` and had drifted out of sync on 5 records) applied across all
51 records. Four new optional fields added: `provenance_vector`, `trifecta_profile`,
`mitigation` (vendor-neutral only — no enforcement-tool config, per the standard-vs-tool
boundary in `AVE_V1.1.0_MIGRATION_BRIEF.md` Section 0), and `example_patterns`.
`status: "draft"` records now need only an 8-field submit-required core; the full
15-field set still applies once `status` is `active` or `deprecated`.

`behavioral_vector` misuse corrected: 12 records (AVE-2026-00004 through 00015) had it
empty and got fresh tags; 11 records (AVE-2026-00041 through 00051) had repurposed it to
hold full example payloads — moved to the new `example_patterns` field, fresh tags
drafted. (Corrected scope from the migration brief's original claim of records
00016-00051; verification found 00016-00040 already had correct tags.)

`provenance_vector`/`trifecta_profile`/`mitigation` drafted for all 51 records by an LLM
pass, per the migration brief's Section 6.2 workflow. Two drift bugs found via human
spot-check and fixed: AVE-2026-00041 and AVE-2026-00042 both had `mitigation.strategy`
values that didn't match what each record's own `remediation` field actually
recommended (missing `pin_integrity` and `deny_by_default` respectively, both explicitly
named in the prose remediation text). Priority-1 records 00045/00046/00050/00051 remain
unreviewed LLM drafts as of this release.

### New records

| AVE ID | Attack class | Severity | AIVSS |
|---|---|---|---|
| AVE-2026-00052 | Tool Abuse - Implementation Command Injection | HIGH | 7.5 |
| AVE-2026-00053 | Tool Abuse - Resource Path Traversal | MEDIUM | 6.3 |
| AVE-2026-00054 | Execution Hijack - Code Execution Sandbox Escape | MEDIUM | 6.7 |
| AVE-2026-00055 | Supply Chain - MCP STDIO Launch Configuration Injection | HIGH | 7.7 |
| AVE-2026-00056 | Data Exfiltration - Rendered Content Auto-Fetch | MEDIUM | 5.8 |

Identified from the 2026-07-10 research-new-attack-classes benchmark
(`docs/agents/research/2026-07-10-benchmark.md`); each traces to an NVD-confirmed CVE or
a named trusted-vendor disclosure (OX Security), verified by direct fetch against
nvd.nist.gov rather than search-summary text. Implementation plan and three
cross-cutting decisions (detection_layer for code-implementation vulnerabilities,
attack_class category, dual-CVSS-assessor handling) recorded in
`docs/agents/prds/2026-07-10-critical-high-attack-class-batch.md`. Four of the five
scored below their pre-implementation severity estimate once AIVSS was actually
computed — see each record's `aivss.notes` for why.

### Repo hygiene (Phase 0, `TRUST_STRATEGY.md`)

- `.github/workflows/tests.yml`, `codeql.yml`, `dependency-review.yml` (+
  `.github/dependabot.yml`), `secret-scan.yml` (+ `.gitleaks.toml`), `scorecard.yml` —
  none of this CI existed before this release
- Enabled natively via repo settings: secret scanning, secret scanning push protection,
  Dependabot security updates, dependency graph — all were disabled
- Two pre-existing `pyproject.toml` packaging bugs fixed, found while building the tests
  workflow and verified against a clean virtualenv: an invalid `build-backend`, and
  missing `[tool.setuptools] packages = []` (this repo isn't a Python library — nothing
  imports it as a package). Both meant `pip install -e ".[dev]"`, the exact command
  CONTRIBUTING.md and CLAUDE.md document, was already broken on a clean machine.
- `gitleaks/gitleaks-action@v2` requires a paid license for GitHub Organization accounts
  as of a breaking change in the wrapper action; switched to running the gitleaks Docker
  image directly (the underlying AGPL-3.0 tool has no such restriction)
- 8 new README badges: Tests, Coverage, CodeQL, Dependency Review, Secret Scan, OpenSSF
  Scorecard, Security Policy, Code of Conduct

### Crosswalks

- `ave-to-owasp-mcp.md` regenerated programmatically from every record's own `owasp_mcp`
  field rather than patched — found the previous hand-maintained version had drifted for
  several existing entries (e.g. AVE-2026-00004 was listed under the wrong categories),
  not just missing the newest records
- `ave-to-ast10.json`/`.md`: AVE-2026-00054 -> AST06, AVE-2026-00055 -> AST02.
  AVE-2026-00052/00053/00056 recorded as new gaps rather than forced into an existing
  category — see the crosswalk files for the reasoning
- `clawscan-to-ave.json`, `skillspector-to-ave.json`: `target.version`/`record_count`
  updated to 1.1.0/56; the rule-level mappings and gaps sections are unchanged, since
  updating them requires each external tool's current rule catalog, which this repo
  does not have

---

## [1.1.0] - 2026-06-21

### Summary

- All 48 original records migrated from schema_version 0.2.0 to 1.0.0
- Schema v1.0.0 is now the active schema for all published records
- Evidence declaration fields backfilled on all 48 records (canonical values from evidence-declarations-all-48.json)
- Detection rules and test fixtures added for all 48 original records — 96 tests passing
- 3 new records: AVE-2026-00049, AVE-2026-00050, AVE-2026-00051 — record set now at 51, 102 tests passing
- AIVSS scores corrected on 6 records (formula applied, invalid ThM values fixed)
- AVE-in-SARIF convention published: `docs/specs/ave-in-sarif.md`
- First research-new-attack-classes benchmark report: `docs/agents/research/benchmark-2026-06.md`
- `--skip-validation` flag can now be removed from ave-site builds

### All 48 original records — fields added or corrected

- `schema_version`: `"0.2.0"` to `"1.0.0"`
- `severity` promoted to top level (was at `aivss.aivss_severity`)
- `aivss_score` promoted to top level (was only at `aivss.aivss_score`)
- `references` converted from URI strings to `{tag, text, url}` objects
- `status`, `published`, `researcher`, `researcher_url` backfilled where missing
- `component_type` normalised: `mcp` to `mcp_server`, `mcp-server-card` to `mcp_server`, `rag` to `other`
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
`pytest tests/ -v` -> **102 passed** (51 records x 2 fixtures). Zero failures.

Coverage scripts:
- `python3 scripts/check_rule_coverage.py` -> All 51 records have detection rules.
- `python3 scripts/check_fixtures.py` -> All 51 rules have positive and negative fixtures.

### New records

| AVE ID | Attack class | Severity | AIVSS |
|---|---|---|---|
| AVE-2026-00049 | Supply Chain - HTTP Header Injection | HIGH | 7.2 |
| AVE-2026-00050 | Persistence - Parasitic Toolchain | HIGH | 7.2 |
| AVE-2026-00051 | Supply Chain - OAuth Discovery Rebinding | HIGH | 7.2 |

Each record ships with a detection rule and positive/negative fixtures.
Identified from the research-new-attack-classes benchmark (Task 11): these were the three confirmed genuine gaps across MCPSecBench, FSF-MCP, MCP-SafetyBench, and Hou et al. 2025.

### AIVSS score corrections

Six records had incorrect scores — formula `((cvss_base + AARS) / 2) x ThM` was not applied, and ThM values outside the valid set {0.75, 0.90, 1.0} were used.

| Record | Old score | New score | Change |
|---|---|---|---|
| AVE-2026-00046 | 9.1 | 9.2 | ThM 0.9 to 1.0 (in-the-wild) |
| AVE-2026-00047 | 7.8 | 7.6 | ThM 0.85 to 1.0 (invalid to in-the-wild) |
| AVE-2026-00048 | 8.2 | 7.7 | ThM 0.85 to 0.90 (invalid to PoC exists) |
| AVE-2026-00049 | 7.5 | 7.2 | ThM 0.85 to 1.0 (invalid to in-the-wild) |
| AVE-2026-00050 | 7.8 | 7.2 | ThM 0.88 to 0.90 (invalid to PoC exists) |
| AVE-2026-00051 | 8.1 | 7.2 | ThM corrected; cvss_base raised to 9.5 to match token-theft vector |

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

## [1.0.0] - 2026-06-18

### The first stable release of the AVE standard.

This release establishes AVE as a production-ready open standard for behavioral classification of agentic AI components — skill files, MCP servers, plugins, and agent tools. It defines the canonical schema, the record/rule/fixture validation model, the framework alignment layer, and the scanner evidence contract.

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
- `severity` and `aivss.aivss_score` must agree (CRITICAL implies score >= 9.0)

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

The full 48-record set shipped at schema version 0.2.0 and was migrated to v1.0.0 in v1.1.0.

---

### Tooling

**`ave.bawbel.io`** — the public registry website launched alongside this release.
Six pages: landing, searchable registry, crosswalks, architecture guide, scoring reference, schema reference.
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

## Done since the original "Planned for v1.2" list

- `GOVERNANCE.md` — shipped
- `CODE_OF_CONDUCT.md` — shipped (Contributor Covenant v2.1)
- `docs/specs/ave-implementer-guide.md` — shipped
- Offline release artifact — shipped as the `v1.1.0` GitHub Release
  (`ave-records-v1.1.0.json`); a `v1.2.0` release with the 56-record set has not been cut
  yet, see below

## Planned for v1.3

- Cut a `v1.2.0` GitHub Release with the 56-record offline artifact (`ave-records-v1.2.0.json`)
- AST10 crosswalk PR — submit `crosswalks/ave-to-ast10.json` as a contribution to the
  OWASP AST10 project repo; the crosswalk file itself is current, the external
  submission has not happened
- Re-check `clawscan-to-ave.json` / `skillspector-to-ave.json` rule-level mappings
  against each tool's current rule catalog for AVE-2026-00052 through 00056 — this
  release only updated their AVE-side target metadata (see 1.2.0 above)
- CWE AI Working Group outreach — open a contribution issue on
  `github.com/CWE-CAPEC/AI-Working-Group` with a gap-mapping document covering how AVE
  records address the agentic behavioral classes missing from CWE-1446
- Second implementer outreach — contact scanner maintainers with crosswalk packages to
  enable `ave_id` emission in their finding output
- Resource exhaustion / agentic DoS record — the one confirmed genuine gap from the
  benchmark-2026-06 research report
- Section 6.2 review priorities 2-4 from `AVE_V1.1.0_MIGRATION_BRIEF.md` — only 2 of the
  6 priority-1 records got a human spot-check in 1.2.0 (both had real bugs, since fixed);
  00045/00046/00050/00051 remain unreviewed LLM drafts, and priorities 2-4 haven't started