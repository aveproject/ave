# AVE Changelog

All notable changes to the Agentic Vulnerability Enumeration standard are documented here.

Format: [Semantic Versioning](https://semver.org). Schema versions and record set versions are tracked together.

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

## Planned for v1.1

- Migrate all 48 records from schema v0.2.0 to v1.0.0
- Backfill evidence declaration fields on priority records: AVE-2026-00001, 00002, 00042, 00045, 00048
- Publish crosswalk files: `crosswalks/skillspector-to-ave.json`, `crosswalks/clawscan-to-ave.json`, `crosswalks/ave-to-frameworks.md`
- Add AVE-in-SARIF convention: `docs/specs/ave-in-sarif.md`
- First `research-new-attack-classes` benchmark report committed to `docs/agents/research/`
- OWASP project proposal drafted: `docs/governance/owasp-proposal.md`
- New records for confirmed gaps: header injection (BadHost), parasitic toolchain, OAuth discovery rebinding