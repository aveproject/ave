# AVE schema terms

Per-field definitions below are generated directly from schema/ave-record-1.1.0.schema.json and are never hand-edited. Run scripts/generate_terms.py after any schema change.

## Relationships between similar-sounding fields

**confidence_baseline vs. verification_basis**: confidence_baseline is a
float a record's author assigns as a scanner hint (a starting-point
confidence for a single-engine match, before false-positive adjustment)
— the same shape whether the underlying evidence is a formally disclosed
CVE or a speculative pattern match. verification_basis is computed, never
authored, derived from a record's own evidence_vantage and evidence_method,
each taken by weakest input together with the vantage its
evidence_basis_engines set can reach. A declared verification_basis is
checked against this derivation by validate_records.py and rejected if
they disagree; confidence_baseline has no equivalent check — it stays a
self-report by design. See issue #98 for why the distinction exists,
raised independently from two unrelated angles (a supply-chain
attestation engineer and a compliance/governance reader) that converged
on the same underlying gap.

**evidence_vantage vs. evidence_method**: two independent axes, not a
single scale. evidence_vantage says where an observation was obtained
(substrate: somewhere the artifact could neither forge nor suppress it,
versus artifact: derived from something the artifact itself produced).
evidence_method says how it was established (intercepted: captured live
as events occurred, versus reconstructed: examined after the fact).
Absence on either axis reads as its floor value (artifact, reconstructed
respectively) rather than a stronger claim by default. A record can be
`substrate_reconstructed` — evidence externally verifiable but assembled
after the fact — which is a real, legitimate combination the schema's own
verification_basis enum names explicitly, not a contradiction.

**entry_class vs. detection_layer vs. detection_stage**: entry_class
(inside provenance_vector) names where in a component's context supply
chain a behavior enters — a closed vocabulary of content, server_card,
registry_metadata, runtime, transport, tool_response, tool_schema,
server_card_document, model_generated, memory, retrieved_document,
user_input, operator_config, or skill_file. detection_stage names when a
scanning approach caught it: static_detection or runtime_observed.
detection_layer names what layer of the agent ecosystem the detection
mechanism inspected (content, server_card, registry_metadata, runtime, or
transport) — and entry_class's own schema description says to reuse the
record's detection_layer value directly when the class is layer-scoped,
falling back to a more precise session-scoped token from its own broader
vocabulary only when detection_layer isn't precise enough. The three
fields answer different questions about the same finding (where it
enters, what layer catches it, when in the lifecycle it's catchable) and
are easy to conflate because all three sound like "where/when did this
happen" — but entry_class and detection_layer are deliberately designed
to share values in the common case, not to always diverge.

**security_boundary vs. missing_control**: security_boundary names the
trust boundary crossed (untrusted content to instruction context, agent
to agent, human approval to autonomous action, and so on) — it answers
audit question Q2, the question this project's own capability-vulnerability
audit treats as the sharpest single check distinguishing a real
vulnerability from a bare capability or technique description.
missing_control names the specific absent check that makes crossing that
boundary possible (no explicit tool allowlist, no provenance label, no
approval gate). A record can state the boundary without stating the
control, or vice versa, but a record with neither is a candidate for
capability-only or technique-only conflation per that same audit (#224).

**owasp_mcp / owasp_asi / mitre_atlas / nist_ai_rmf vs.
framework_sources**: the first four are the mapping itself — which
category a record corresponds to in an external framework.
framework_sources is provenance for that mapping — which version or
commit of the referenced framework the mapping was made against. A
record can carry the mapping without the provenance; as of the last
corpus-wide backfill pass, `owasp_mcp` (required on every record) and
`owasp_asi` have full coverage (80 of 80, and 69 of 69 tagged records
respectively), `mitre_atlas` is partially backfilled (40 of 50 tagged
records, covering exactly the ones a dated, citable audit event actually
verified), and `nist_ai_rmf` has none yet — no audit trail for it was
ever found in this project's history. framework_sources exists
specifically because an unversioned or unratified framework's category
meaning can shift under an unpinned mapping: see
OWASP/www-project-mcp-top-10#52, the live case (not a hypothetical) that
prompted the field, where two independent projects assigned the same MCP
category number to genuinely unrelated categories because each read the
spec at a different point while it was still moving.

<!-- GENERATED FROM schema/ave-record-1.1.0.schema.json, DO NOT HAND-EDIT BELOW THIS LINE -->

### `affected_platforms`

Agent platforms known to be affected, e.g. claude-code, cursor, windsurf. Optional — fill as evidence accumulates. Do not speculate.

### `affected_registries`

Skill or tool registries where this class has been observed. Optional.

### `aivss`

OWASP AIVSS v0.8 full scoring breakdown.

### `aivss_score`

Top-level shortcut mirroring aivss.aivss_score. Optional.

### `attack_class`

Behavioral category, e.g. external_instruction_fetch, tool_description_injection, rug_pull. Use snake_case. Not a vulnerability_type string.

### `ave_id`

Unique identifier. Format: AVE-YYYY-NNNNN. Immutable once published. Wrong or obsolete records are deprecated, never renumbered or deleted.

### `behavioral_fingerprint`

One or two sentences describing what the component DOES that is dangerous. Behavioral, not a byte signature. A second implementer should be able to write a detection rule from this alone.

### `behavioral_vector`

Short tags summarising the attack path. Optional. e.g. supply-chain, external-fetch, self-modification. Distinct from example_patterns (illustrative payloads) — keep these short.

### `component_type`

The kind of agent component this class primarily affects. skill: a skill file (SKILL.md, .skill, etc). prompt: a system prompt or instruction file. mcp_server: an MCP server or its server-card manifest. plugin: a plugin in an agent framework. agent: the agent runtime itself. tool: a tool definition. other: none of the above or cross-cutting. Optional — omit if the class spans multiple types.

### `confidence_baseline`

Scanner hint — base confidence for a single-engine match before FP adjustment. Optional. High-signal (e.g. hardcoded credential): 0.85-0.95. Low-signal (vague phrase): 0.40-0.55.

### `cvss_base_vector`

CVSS 4.0 base vector string. Optional.

### `derivable_into`

Scanner hint — toxic-flow chain IDs this class can participate in, e.g. credential-exfiltration, rug-pull-chain. Optional.

### `description`

Full narrative description. Explain the mechanism, why conventional tools miss it, and the worst-case impact.

### `detection_layer`

Where in the agent ecosystem this vulnerability class surfaces. Determines what kind of scanner or monitoring is needed to detect it. content: evidence is in the text body of the skill file, prompt file, or tool description — detectable by a static scanner before the agent runs. server_card: evidence is in the MCP server manifest (.well-known/mcp.json, tool schemas, parameter descriptions) — detectable when the server-card is fetched, before any tool call. registry_metadata: evidence is in the registry listing (server name, publisher description) — detectable by auditing the registry. runtime: evidence only appears during live agent execution (injected via tool results, memory writes, A2A messages, image pixels, async task payloads) — requires behavioral sandbox or runtime monitoring. transport: evidence is in the network layer (HTTP headers, OAuth discovery endpoints, webhook destinations) — requires a proxy or network monitor.

### `detection_methodology`

Step-by-step detection approach: static scan, semantic analysis, behavioral sandbox, network monitoring. Optional.

### `detection_stage`

Scanner hint — earliest lifecycle stage this class is reliably detectable. Optional. static_detection: pre-scan or CI suffices. runtime_observed: live agent session required.

### `evidence_basis_engines`

Scanner hint — engines capable of detecting this class. Optional. Used to populate evidence_basis on findings. external_authority means a party outside the observed artifact was queried and returned a determinate answer (a package registry, RDAP, a forge's user API); it names the observation rung, not whether the answer was right.

### `evidence_kind_default`

Scanner hint — default evidence_kind stamped on findings. Optional. Scanner may override per detection.

### `evidence_method`

Producer statement — how the evidence for this class is established, taken from the weakest input. intercepted: from events captured as they occurred. reconstructed: from state examined after the fact. reconstructed is a floor a producer may always truthfully state. Optional; absent reads as reconstructed.

### `evidence_vantage`

Producer statement — the vantage every input this class's evidence depends on was obtained at, taken from the weakest input. substrate: obtained where the observed artifact could neither forge nor suppress it. artifact: at least one input derives from output the artifact itself produced. artifact is a floor a producer may always truthfully state; a consumer learns from it only that the evidence lacks the stronger binding. Optional.

### `example_patterns`

Illustrative attack payload strings or code fragments demonstrating this class. Distinct from behavioral_vector (short tags) and indicators_of_compromise (defender observables). Researcher-facing examples for detection-rule authoring, not verbatim signatures. Optional.

### `framework_sources`

Which version of each referenced framework this record's mappings (owasp_mcp, owasp_asi, mitre_atlas, nist_ai_rmf) were made against. Optional. A mapping to an unratified or moving framework is undecidable without this: a consumer holding owasp_mcp: ["MCP03"] cannot tell which reading of the numbering produced it — confirmed as a live, present-tense divergence, not a hypothetical, in crosswalks/ramparts-to-ave.json, where AVE's own MCP03 and Ramparts' MCP03 are unrelated categories that happen to share a number. Mirrors the commit/pin_status pinning already used on crosswalk endpoints (schema/crosswalk-1.0.0.schema.json), one layer down: a crosswalk endpoint pins the tree a record count was read from, this pins the framework reading a record's own tag was read from. Keyed by the mapping field it describes, e.g. framework_sources.owasp_mcp, not four parallel sibling fields, because frameworks version differently (MCP Top 10 has no release, MITRE ATLAS versions discretely, NIST AI RMF is a dated publication) and a single container shape has to accommodate all of them. See OWASP/www-project-mcp-top-10#52 for the case that prompted this.

### `indicators_of_compromise`

Observable IOC strings. REQUIRED once a record is active or deprecated — at least one. These are what defenders search for. Each entry is a specific observable: a phrase pattern, a behavioral indicator, or a network signal.

### `kill_switch_active`

Whether a registry-level kill switch is currently active in the Bawbel registry. Optional — defaults to false.

### `last_updated`

ISO 8601 datetime of most recent update. Optional.

### `missing_control`

The specific control whose absence makes exploitation possible, e.g. 'no explicit tool allowlist', 'no provenance label', 'no approval gate'. Optional, but a record without this and without security_boundary is a candidate for capability-only or technique-only conflation. See docs/audits/capability-vulnerability-audit.md.

### `mitigation`

Abstract, vendor-neutral description of what class of defense neutralizes this class. Names the strategy, not a runnable control. Any enforcement tool can build a concrete control from these values; no tool's config syntax appears here. The prose remediation field remains the required human-readable form; this object is the structured, machine-consumable companion. Optional; absent or null means not yet classified.

### `mitre_atlas`

MITRE ATLAS technique IDs. Format: AML.Txxxx or AML.Txxxx.000. Optional — add when a technique applies. Do not force a mapping; omit if no current ATLAS technique covers this class.

### `mutation_count`

Number of distinct real-world textual mutations observed in the wild. Optional.

### `nist_ai_rmf`

NIST AI RMF function and category mappings, e.g. MAP-1.5, MEASURE-2.5. Optional.

### `owasp_asi`

OWASP Agentic Security Initiative (ASI) Top 10 categories. Format: ASINN. Optional — add when the class maps to the Agentic Top 10. Omit rather than force a poor fit.

### `owasp_mcp`

OWASP MCP Top 10 categories. Format: MCPNN. REQUIRED once a record is active or deprecated — at least one. Provides the core OWASP grounding every published record must have.

### `provenance_vector`

Where in the agent context supply chain this class enters and what authority escalation it performs. A descriptive property of the vulnerability, independent of any defense. Optional; absent or null means not yet classified, not 'does not apply'.

### `published`

ISO 8601 datetime of first publication, e.g. 2026-04-01T09:00:00Z. Required once status is active or deprecated.

### `references`

Primary sources: CVEs, papers, disclosures, scan reports. REQUIRED — at least one citable source, even for a draft record. This is the provenance signal a skeptic checks first.

### `remediation`

How to mitigate or prevent this class. REQUIRED once a record is active or deprecated — must be actionable.

### `researcher`

Name of the researcher or team who authored this record. REQUIRED once a record is active or deprecated — records must be attributable. Use 'Bawbel Security Research Team' for internally authored records.

### `researcher_url`

URL for the researcher or team. Optional.

### `schema_version`

AVE schema version this record was authored against, e.g. 1.1.0.

### `security_boundary`

The trust boundary this record's vulnerability crosses, e.g. 'untrusted content to instruction context', 'agent to agent', 'human approval to autonomous action'. Optional. Answers audit question Q2: the most important question for distinguishing a real vulnerability from a bare capability or technique description.

### `severity`

Severity. Must agree with aivss.aivss_score. CRITICAL requires >= 9.0. HIGH: 7.0-8.9. MEDIUM: 4.0-6.9. LOW: < 4.0.

### `status`

Lifecycle status. active: published and current, full field set required. deprecated: superseded or withdrawn — record stays for reference, full field set required. draft: not yet peer-reviewed — only the core submit-required fields apply, everything else is enrichment added before promotion to active.

### `title`

Human-readable title. Max 120 characters.

### `trifecta_profile`

Which lethal-trifecta conditions make this class exploitable (Simon Willison / Palo Alto; cited in OWASP Agentic Skills Top 10). A deployment-applicability filter. Does not affect severity or aivss_score. Optional; absent or null means not yet classified.

### `verification_basis`

Derived, not authored — the composition of evidence_vantage and evidence_method with the vantage implied by evidence_basis_engines, each taken by weakest input. scripts/write_verification_basis.py computes it. A record may carry a declared value, which validate_records.py then checks against the derivation and fails on a mismatch, so the declaration is falsifiable rather than self-reported. Optional.

### `vulnerability_rationale`

The explicit three-line artifact from audit question Q7: what the component can do, what specific condition makes that dangerous, and what results. Optional. This is the sharpest single check against capability/vulnerability conflation, a record that can't fill this in honestly is probably miscategorized.
