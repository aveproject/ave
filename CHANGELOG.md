# AVE Changelog

All notable changes to the Agentic Vulnerability Enumeration standard are documented here.

Format: [Semantic Versioning](https://semver.org). Schema versions and record set versions are tracked together.

---

## [Unreleased]

### Changed
- `scripts/check_confidence_signal.py` now reports two named findings
  rather than one warning. Running its engine-set cardinality test and
  the `verification_basis` derivation against each other over the same
  `evidence_basis_engines` field showed neither subsumes the other: two
  engines that both read artifact-produced content derive
  `artifact_intercepted` and cardinality stayed silent, while a single
  `sandbox` engine derives `substrate_intercepted` and cardinality
  flagged it. Cardinality measures corroboration, how many independent
  sources agreed; the derivation measures vantage, where the observation
  was made from. Both signals are real and they take different repairs,
  so the check emits `vantage_floor` and `independence_floor` separately
  and a record may carry both, one, or neither. The vantage arm imports
  the derivation from `scripts/write_verification_basis.py` rather than
  recomputing it, and derives even where a record carries a stamped
  `verification_basis`, since the stamp is the author's own copy. On the
  current corpus this turns 0 findings into 8 `vantage_floor` findings
  across 8 records — all of them records that declare a high
  `confidence_baseline` and no `evidence_vantage` at all. Still a soft
  warning; the exit code is untouched. `--json` gains a `finding` key per
  entry and a `records` count alongside `count`. Consumer guidance in
  `docs/guides/confidence-baseline-consumer-guide.md`.
- AVE-2026-00070: `researcher`/`researcher_url` correction — was
  listed as "Saray Chak" / bawbel.io despite the record's own
  `references` entry already citing the actual external source (Zhu,
  Li, Lyu, Sun, Su, Shao, "Collaborative Shadows: Distributed Backdoor
  Attacks in LLM-Based Multi-Agent Systems," arXiv:2510.11246); the
  exact misattribution pattern `docs/specs/researcher-process.md`
  documents as previously caught and fixed on two other records
  (see the AVE-2026-00060 worked example), recurring here uncaught
  until now. Corrected to the paper's real six authors and the actual
  arXiv abstract page. No score, severity, or mechanism-description
  change.
- `mitre_atlas` corrections on 43 records, per issue #127's audit of
  `AML.T0043`/`T0048`/`T0051`/`T0054`: those four IDs were largely
  applied by template rather than per-record verification against
  ATLAS.yaml (a default "agentic-abuse record → tag T0043+T0048" pair
  on 11 unrelated records; textbook `T0051` prompt-injection records
  tagged only the broader `T0054` with no `T0051` citation at all). No
  score, severity, or mechanism-description changes — this is a
  citation-accuracy correction only. 9 records got a source-verified
  replacement technique found via fresh ATLAS.yaml research (e.g.
  AVE-2026-00019 Memory Poisoning → `AML.T0080.000` "Memory", an exact
  mechanism match; AVE-2026-00029 Unicode Homoglyph → `AML.T0068` "LLM
  Prompt Obfuscation"). 5 records (00008, 00021, 00030, 00035, 00038)
  had their mismatched citation dropped with no replacement added —
  genuinely no ATLAS technique covers those mechanisms, confirmed by
  research rather than left in place by default. 8 "defensible either
  way" judgment calls defaulted to dropping the stretch citation rather
  than keeping it, per this project's own verify-don't-infer framework-
  mapping standard. Full per-record reasoning in issue #127.
- AVE-2026-00073: scope clarification, no score change — payload_surface,
  behavioral_fingerprint, example_patterns, and detection_methodology
  now name MCP server URLs and A2A agent_card_url explicitly (rather
  than leaving them implicit under "an equivalent traffic-destination
  value"), after a related candidate surfaced from predictor2718's PR
  #123 turned out to already be in scope here rather than warranting a
  new record.

### Added
- AVE-2026-00082: local skill name collision (deterministic router
  shadowing across discovery roots) -- two skill files already present
  on the local filesystem resolve to an identical effective name
  (declared or filename-derived); an agent's router silently invokes
  whichever discovery root's file resolution order picks, with no
  operator-visible signal a collision occurred. Distinct from
  AVE-2026-00066 (requires LLM hallucination + public registry) and
  AVE-2026-00074 (requires external reference decay): neither a
  registry nor a hallucination nor decay is involved here, both files
  already exist locally and deterministic resolution order decides the
  winner. Sourced from highflame-ai/ramparts' SkillNameCollision
  detector (issue #150) (MEDIUM, AIVSS 4.4)
- AVE-2026-00078, 00079, 00080: three genuinely distinct multi-agent
  pipeline mechanisms extracted from Bappy et al., "Adversarial Attacks
  in Multi-Agent LLM Pipelines: Unveiling Structural Vulnerabilities in
  Agentic AI Architectures" (arXiv:2608.00718, accepted IEEE GLOBECOM
  2026), empirically derived from 147 annotated TRAIL-benchmark
  production traces (GAIA + SWE-Bench Lite) plus a controlled
  cross-model evaluation (GPT-5-mini, Claude Sonnet 4.5, Kimi K2.5).
  The paper's own fourth mechanism (prompt injection via retrieved
  content, its A1/content-boundary class) was confirmed already covered
  by AVE-2026-00016 and related records — not drafted as new. All three
  scored MEDIUM: AARF rewards amplification breadth, not raw impact,
  and each of these is architectural rather than broad-vector.
  - AVE-2026-00078: consensus poisoning — an orchestrator accepts a
    single sub-agent's result as authoritative with no quorum or
    cross-verification across redundant sources, so one compromised
    sub-agent unilaterally determines the pipeline's output (delegation
    boundary). Distinct from AVE-2026-00020 (injection direction is
    orchestrator→sub-agent, not this record's sub-agent→orchestrator
    aggregation-layer flaw) and AVE-2026-00018 (fabricating one result,
    not failing to cross-check redundant ones). Id confirmed via issue
    #174 (MEDIUM, AIVSS 6.4)
  - AVE-2026-00079: plan hijacking via false completion signal — a
    self-reported "task already completed" claim causes forced early
    termination of a declared multi-step plan with no plan-to-execution
    binding check (delegation boundary). Distinct from AVE-2026-00021
    (bypasses human confirmation; this bypasses no human, it bypasses
    the agent's own remaining planned steps) and AVE-2026-00063 (static
    config flag, not a runtime natural-language claim). Id confirmed via
    issue #175 (MEDIUM, AIVSS 6.2)
  - AVE-2026-00080: silent agent substitution (Sybil) — during a
    tool-call retry, an unverified process responding at an agent's
    routing position is accepted as that agent with no credential or
    attestation check (identity boundary). Distinct from AVE-2026-00017
    (a registry/manifest identity claim at initial connection, not a
    mid-session retry-window substitution asserting no claim at all)
    and AVE-2026-00030 (requires an explicit role claim; this requires
    none). Id confirmed via issue #176 (MEDIUM, AIVSS 6.8)
- AVE-2026-00077: cross-origin tool and resource declaration within a
  single MCP server manifest — a server's own manifest declares tools
  and/or resources spanning multiple unrelated root domains (or mixed
  http/https schemes), so a minority-domain tool can inject, override,
  or hijack context intended for the trusted majority origin within
  the same session, with no false identity claim involved. Distinct
  from AVE-2026-00001 (fetched content changing at read time) and
  AVE-2026-00017 (false identity claim); here every origin is honestly
  declared, the risk is structural domain diversity. Sourced from
  Ramparts' cross_origin_scanner.rs / cross_origin_escalation.yar,
  surfaced via the ramparts-to-ave crosswalk (issue #149) (MEDIUM,
  AIVSS 4.8)
- AVE-2026-00076: natural-language steering of an approval classifier
  subagent — Cursor's Auto-review mode gates unattended shell/MCP/Fetch
  calls behind a separate classifier subagent that a committed
  per-repo permissions.json can steer via free-form natural-language
  allow_instructions/block_instructions text ("steering, not
  enforcement" per Cursor's own docs); confirmed distinct from
  AVE-2026-00021 (instruction read by the primary agent itself) and
  AVE-2026-00063 (a deterministic boolean flag, no NL involved).
  Flagged by predictor2718 in PR #123 (MEDIUM, AIVSS 4.5)
- AVE-2026-00075: bytecode poisoning (compiled .pyc cache diverges from
  its own reviewed .py source) — CPython prefers a valid cached .pyc
  over its own source, so a compiled artifact can contain dangerous
  primitives (process execution, network calls, credential-path access)
  present nowhere in the visible source text a scanner or reviewer
  reads; distinct from AVE-2026-00057, a single-artifact encoding class,
  this is a two-artifact divergence. Sourced from repo-forensics'
  scan_bytecode.py and the 2026-06-10 CSA/Trail of Bits scanner-bypass
  research note (MEDIUM, AIVSS 4.4)
- AVE-2026-00074: reclaimable dead external anchor (SkillJacking) — a
  skill references a GitHub owner, package, domain, or cloud subdomain
  that was live when authored and has since been deleted or expired,
  making it re-registerable by an attacker with no change to the
  skill's own content; distinct from AVE-2026-00062 (absence of pinning
  at declaration time), this is a previously-valid reference decaying
  after the fact. Sourced from repo-forensics' scan_dead_anchors.py and
  AIR's SkillJacking disclosure (925 skills / ~134,000 agents on
  hijackable dependencies) (HIGH, AIVSS 7.1)
- AVE-2026-00073: telemetry/endpoint redirect via static configuration —
  a committed config value (OTEL_EXPORTER_OTLP_ENDPOINT,
  ANTHROPIC_BASE_URL/CVE-2026-21852, or a cleartext model/provider base
  URL) redirects where a process sends traffic, no content injected
  into the model's context at all; confirmed distinct from
  AVE-2026-00002 by predictor2718. Third and final record drafted from
  the cfgaudit gap breakdown on issue #68 for this pass (MEDIUM, AIVSS
  4.1)
- AVE-2026-00072: MCP server bound to all interfaces with no
  authentication (NeighborJack) — a wildcard bind address (0.0.0.0 or
  [::]) makes an MCP server reachable by anyone on the local network
  with no credential required; the config difference from a safe
  deployment is a single token. Second of three records drafted from
  predictor2718's detailed cfgaudit gap breakdown on issue #68 (MEDIUM,
  AIVSS 5.0)
- AVE-2026-00071: MCP daemon redirect (container posture) — DOCKER_HOST
  or a -H/--host flag pointing the container daemon at remote
  infrastructure, so every build/run/pull silently targets an
  attacker-controlled host with nothing in the compose file or image
  reference looking unusual. First of three records drafted from
  predictor2718's detailed cfgaudit gap breakdown on issue #68 (MEDIUM,
  AIVSS 5.6)
- AVE-2026-00070: distributed cross-agent backdoor fragments
  (Collaborative Shadows) — a poisoned tool spreads encrypted, dormant
  attack primitives across multiple distinct agents' own memories
  during a collaborative task; an attacker reassembles them externally,
  offline, after execution. Fifth and final record of the eight-
  candidate audit's genuine gaps (MEDIUM, AIVSS 6.4)
- AVE-2026-00069: multimodal image-hidden instructions (SkillCamo) —
  malicious instructions concealed in an image bundled with a skill
  package, invisible to text-only scanners, recovered by a multimodal
  agent at deployment; distinct from user-supplied image injection at
  chat time (MEDIUM, AIVSS 4.8)
- AVE-2026-00068: CLI command composition risk (MOSAIC) — individually
  benign CLI commands compose through shared OS/shell state (env vars,
  file descriptors, working directory, temp files) into an
  unauthorized capability; no single command in the sequence is
  independently dangerous (MEDIUM, AIVSS 5.1)
- AVE-2026-00067: skill composition trust transfer (SCR-TrustLift) — a
  downstream skill accepts an upstream skill's benign output (an
  endorsement, audit finding, validation result) as sufficient
  authorization without independently re-verifying the claim; neither
  skill is dangerous in isolation (MEDIUM, AIVSS 5.0)
- AVE-2026-00066: hallucinated skill-name squatting (HalluSquatting) —
  agent hallucinates a plausible-but-nonexistent package/repo/skill
  name, attacker pre-registers it with malicious content, no injected
  instruction anywhere in the chain (MEDIUM, AIVSS 6.2)
- `docs/specs/scaling-and-governance.md`: record-growth discipline
  (citing MITRE CWE 4.19 as a documented cautionary precedent), schema
  versioning policy (formalizing the existing alias/frozen-snapshot
  pattern), and deprecation policy (modeled on CVE's rejected-but-permanent
  approach). The deprecation policy's schema implementation
  (`merged_into`, `rejection_reason` fields) is tracked separately for a
  future version bump, not yet implemented.
- 5 new records: AVE-2026-00060 through AVE-2026-00064 — record set now at 64,
  256 tests passing. Coordinated batch from one policy/config-surface audit
  pass, not five independent additions.
  - AVE-2026-00060: STDIO transport shell injection via unsanitized tool call
    parameters (HIGH, AIVSS 7.2)
  - AVE-2026-00061: TLS certificate verification disabled in agent component
    configuration (MEDIUM, AIVSS 4.1)
  - AVE-2026-00062: unpinned dependency version allowing supply chain
    substitution (MEDIUM, AIVSS 4.4)
  - AVE-2026-00063: human approval gate bypassed via declarative
    configuration, kept distinct from AVE-2026-00048's instruction-driven
    delegation mechanism after applying the record-growth discipline's
    mechanical test (MEDIUM, AIVSS 4.8)
  - AVE-2026-00064: zero-click code execution via project-load auto-run
    configuration (MEDIUM, AIVSS 5.2)
- AVE-2026-00065: A2A agent card poisoning via embedded adversarial
  instructions (HIGH, AIVSS 7.1). Sixth and final record of the same
  config/protocol-surface audit as AVE-2026-00060 through 00064, the
  only one involving a genuinely multi-agent mechanism. Confirmed
  distinct from AVE-2026-00041 (MCP server-card injection) by direct
  comparison: different protocol (A2A, not MCP), no `.well-known` path
  or `tool.description` field, payload surface is the agent's own
  self-declared identity/capabilities in a peer discovery exchange.

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

**[CORRECTED 2026-09-02, see #249]** The sourcing claim in the line above
does not hold: `docs/agents/research/benchmark-2026-06.md`'s per-dataset
class tables that this attribution rests on were found to be substantially
fabricated (72 of 102 checkable claims wrong, see #249/#241) — the "planned"
rows these three records were drafted against were never checked against
each paper's real, published taxonomy. This does not implicate the three
records themselves: each carries its own independent, verified primary
sourcing in its own `references` field (RFC 8414/7636 and CWE-601 for
AVE-2026-00051, CWE-114/284 and the OWASP MCP Top 10 for AVE-2026-00050,
OWASP Host Header Testing and CWE-644/20 for AVE-2026-00049), none of which
depend on the retracted benchmark analysis. Kept, not edited away, per this
project's practice of publishing negative results rather than quietly
correcting them out of the historical record.

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
  **[CORRECTED 2026-09-02, see #249/#241]** This roadmap item does not hold: neither
  MCPSecBench nor MCP-SafetyBench contains a resource-exhaustion or denial-of-service
  class in their real, published taxonomies — the "genuine gap" this item names never
  existed. Dropped rather than carried forward; not implemented in any shipped version.
  Kept here, corrected in place, rather than removed, so the original stale roadmap
  item stays visible alongside its correction.
- Section 6.2 review priorities 2-4 from `AVE_V1.1.0_MIGRATION_BRIEF.md` — only 2 of the
  6 priority-1 records got a human spot-check in 1.2.0 (both had real bugs, since fixed);
  00045/00046/00050/00051 remain unreviewed LLM drafts, and priorities 2-4 haven't started