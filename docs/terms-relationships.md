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
record can carry the mapping without the provenance; as of the
2026-10-15 backfill, `owasp_mcp` and `owasp_asi` have full, real-pin
coverage (87 of 87, and 74 of 74 tagged records respectively, every
entry a real version or commit). `mitre_atlas` has a real, citable
version/commit pin on 4 of its 54 tagged records (AVE-2026-00082,
-00084, -00086, -00087, all pinned against ATLAS v5.6.0); the other 50
carry an `unknown` declaration dated 2026-08-09, from the original
backfill pass. Correcting this document's own prior claim here rather
than carrying it forward: that prior sentence said those 50 covered
"the ones a dated, citable audit event actually verified," which,
checked directly against the live records, is not what they are --
every one of them has `pin_status: "unknown"`, not a verified pin.
`nist_ai_rmf` now carries an `unknown` declaration on all 56 tagged
records, added in the same 2026-10-15 pass; it previously had none,
and no dated verification event for it was ever found anywhere in
this project's history, confirmed again before this backfill. An
`unknown` entry means the mapping predates framework_sources tracking
and the version it was actually read against is not recoverable; it
records an honest gap, not a lower-confidence pin. framework_sources exists
specifically because an unversioned or unratified framework's category
meaning can shift under an unpinned mapping: see
OWASP/www-project-mcp-top-10#52, the live case (not a hypothetical) that
prompted the field, where two independent projects assigned the same MCP
category number to genuinely unrelated categories because each read the
spec at a different point while it was still moving.
`framework_sources.*.source_url` was added afterward, once an unrelated
project facing the same #52 gap converged on the same shape:
BerkantACUN/guardmcp PR #3 ("Pin the OWASP spec commit the mapping was
drafted against") pins its SARIF taxonomy to the OWASP MCP Top 10 with a
`specCommit`/`specSource` pair -- not a comment posted in #52 itself, a
separate repo's independent fix for the versioning gap #52 describes --
and its `specCommit` happens to be the exact same commit sha AVE's own
`owasp_mcp` backfill pinned, `165fe0f78ef104459237b4a8e0f6e78db9b02391`.
`source_url` mirrors `specSource`: the resolved tree URL at `commit`, so
a reader can check the mapping without reconstructing it from repo and
sha by hand. Optional even when `commit` is present.
