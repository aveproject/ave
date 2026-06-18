# LANGUAGE.md — bawbel/ave Domain Language

All names in this repo must come from this file.
Terms shared with bawbel/scanner are marked (shared).

Banned: vulnerability_type (use attack_class), signature (use
behavioral_fingerprint), rule_definition (use rule), CVE record
(AVE is not CVE), confidence in a record (use confidence_baseline).

---

## Architecture terms (Matt Pocock)

**Module** — anything with interface + implementation.
**Interface** — everything a caller must know: types, invariants, error modes.
**Depth** — leverage: lot of behavior behind a small interface.
**Seam** — where an interface lives; place behavior can be altered.
**Deletion test** — would deleting this module concentrate complexity elsewhere?

The "modules" in this repo are validation scripts and rule loaders.

---

## AVE record fields

**AVERecord** — the static definition of one vulnerability class.
Authored once. Immutable ave_id. Lives in records/AVE-YYYY-NNNNN.json.

**ave_id** — unique identifier. Format AVE-YYYY-NNNNN. Never renumbered.
Immutable once published. Deprecated via status, never deleted.

**attack_class** — the behavioral category. NOT "vulnerability type".
Examples: external_instruction_fetch, tool_description_injection,
rug_pull, cross_app_escalation. Use snake_case.

**behavioral_fingerprint** — what the component DOES that is dangerous.
Behavioral, not a byte signature. Describes the action, not the bytes.
One or two sentences. A second implementer should be able to write a
detection rule from this alone.

**behavioral_vector** — short tags summarising the attack path.
Optional. Examples: supply-chain, external-fetch, self-modification.

**severity** — CRITICAL | HIGH | MEDIUM | LOW. Must agree with
aivss.aivss_score. CRITICAL implies score >= 9.0.

**AIVSS** (shared) — OWASP AI Vulnerability Severity Score v0.8.
The record carries the full breakdown: cvss_base, aarf, aars, thm,
mitigation_factor, aivss_score, spec_version.

**AARF** — Agentic Amplification and Risk Factors. 10 sub-scores (0.0–1.0)
inside the aivss object: autonomy, tool_use, multi_agent, non_determinism,
self_modification, dynamic_identity, persistent_memory,
natural_language_input, data_access, external_dependencies.

**component_type** — skill | mcp_server | plugin | agent | tool | other.
Optional. The kind of agent component this class primarily affects.

---

## Rules and fixtures

**Rule** — a detection implementation for an AVE class. One class may have
rules across multiple engines. Lives in rules/pattern/, rules/yara/,
rules/semgrep/.

**PositiveFixture** — a test file that MUST trigger the rule.
Lives in tests/fixtures/.

**NegativeFixture** — a benign test file that MUST NOT trigger the rule.
The false-positive guard. A rule without a negative fixture is incomplete.

---

## Evidence declaration fields

These fields declare DEFAULTS the scanner uses to assign per-finding values.
The record never carries the actual per-detection value — only the baseline.

**evidence_kind_default** — default evidence_kind for findings of this class.
Values: tool_description_pattern | config_schema | file_type_mismatch |
behavioral_pattern | semantic_inference | multi_engine.

**detection_stage** — earliest lifecycle stage where this class is detectable.
Values: static_detection | runtime_observed | runtime_drift_detected.

**detection_layer** — where in the ecosystem this class surfaces.
Values: content | server_card | registry_metadata | runtime | transport.

**confidence_baseline** — base confidence for a single-engine match before
FP pipeline adjustment. High-signal: 0.85–0.95. Low-signal: 0.40–0.55.

**evidence_basis_engines** — which engines can detect this class.
Values: pattern | yara | semgrep | llm | sandbox | magika.

**derivable_into** — toxic-flow chain IDs this class can participate in.

---

## Provenance fields

**researcher** — name of the person or team who authored the record.
Required. Use "Bawbel Security Research Team" for internal records.

**references** — primary sources: CVEs, papers, disclosures.
Required, at least one. Each item is a URI string or {tag, text, url} object.

---

## Terms that belong to the SCANNER, never the record

These are per-detection runtime values. They NEVER appear in an AVE record:
confidence, confidence_band, evidence_stage (actual), confidence_reason,
derived, line, match, suppressed, engine (actual).

The record declares baselines and defaults. The scanner assigns actuals.

---

## Shared terms (from bawbel/scanner LANGUAGE.md)

Finding, ScanResult, ToxicFlow, SuppressedFinding, AcceptedFinding,
PiranhaDB, confidence, evidence_stage — defined in scanner LANGUAGE.md.

---

## Banned terms

| Banned | Use instead |
|---|---|
| vulnerability_type | attack_class |
| signature | behavioral_fingerprint |
| rule_definition | rule |
| CVE record | AVE record — AVE is not CVE |
| confidence (in a record) | confidence_baseline |
| owasp (field name) | owasp_mapping |
| mitre_atlas (field name) | mitre_atlas_mapping |