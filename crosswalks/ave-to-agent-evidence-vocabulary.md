# AVE to agent-evidence-vocabulary

A field-level crosswalk between AVE's evidence-provenance properties and the
agent-evidence-vocabulary registry, which names the axes an execution-evidence
claim is read on: who observed the execution, how directly, what the claim
leaves out, and why a published record's derived value changed. Machine-readable
form in
[`ave-to-agent-evidence-vocabulary.json`](ave-to-agent-evidence-vocabulary.json),
against
[`schema/crosswalk-1.0.0.schema.json`](../schema/crosswalk-1.0.0.schema.json).

| | |
|---|---|
| Source | AVE 1.1.0, 89 records, commit `4032785b67d35fed2e542b23577e8c601c61e145` |
| Target | [agent-evidence-vocabulary](https://github.com/probityai/agent-evidence/tree/agent-evidence-vocabulary-v0.8.0/packages/vocabulary) 0.8.0, 37 terms, CC0-1.0, commit `5fe04d8ffe98710d68ee958c8595d0de6179a3bf` |
| Generated | 2026-10-27 |
| Unit | one schema property, not one category |

Previous revision (2026-09-15): AVE 1.1.0 with 80 records at `1e29789e`, against
vocabulary 0.2.0 with 8 terms at `66177d65`. The registry has since moved into
the `agent-evidence` repository, and the old repository is archived.

## Read this first

At the pinned commit, 16 of the 89 records carry at least one of
`evidence_vantage` and `verification_basis`, and none carries `evidence_method`.
Nine records carry `evidence_vantage` (eight `artifact`, and AVE-2026-00074 with
`substrate`), and seven carry `verification_basis` (all `artifact_reconstructed`).
That was checked by reading every record file in the pinned tree, not by reading
the schema. One record, AVE-2026-00074, carries a `revisions` entry, with
`reason_code` `declaration_added`.

So the `evidence_vantage`, `verification_basis` and `revisions[].reason_code`
rows carry an evidence state of emitted, and the `evidence_method` and
`evidence_basis_engines` rows stay inferred, established by comparing two schema
definitions. AVE records are unsigned JSON files in a git repository, so emitted
here means a record carries the field and a reviewer can fetch it at the pinned
commit, which is the rule this file set in September. The registry's own
definition of emitted names a signed statement, and whether a row meets the
registry's promotion rule is for the registry to decide.

## The mapping

| AVE field | Registry term | Match | Evidence | Why |
|---|---|---|---|---|
| `evidence_vantage` | `observation_vantage` | exact | emitted, 9 records | `substrate` and `artifact` on both sides, same two values, same weakest-input composition |
| `evidence_method` | `observation_directness` | exact | inferred, 0 records | `intercepted` and `reconstructed` on both sides, same composition, same floor |
| `verification_basis` | `observation_vantage` + `observation_directness` | structural | emitted, 7 records | AVE's four values are the product of the two registry axes; either side converts without loss |
| `evidence_basis_engines` | `observation_vantage` | partial | inferred | `external_authority` and `sandbox` sit on the substrate side; the five artifact-reading engines sit on the other |
| `revisions[].reason_code` | `revision_reason` | exact | emitted, 1 record | the same four codes and the same entry shape; AVE copied the codes when it added the array in #360 |

The two axis rows are unusual and worth a sentence. The definitions were
written independently, on different sides, and reached the same two-value split
with the same composition rule. That is the case for calling them exact rather
than approximate: there is nothing to reconcile. Both value sets and the
composition rule are unchanged at registry 0.8.0.

The `revisions` row is the newest. The four codes in AVE's schema enum were
compared with `revision_reason` at 0.8.0 and are identical. AVE states that its
enum stands on its own and does not follow later changes in the registry. One
code, `declaration_added`, is used by one record, and the other three are valid
in the schema and unused.

## What does not map

Thirty-four registry terms have no AVE counterpart, because an AVE record
classifies a component's behavior while the registry describes one observed
execution, the admission of a change to a harness, or the decision that a task
is done. The JSON lists each term with its own reason. By section:

| Registry section | Terms with no AVE counterpart |
|---|---|
| `evidence_dimensions` | `witness_scope`, `field_evidence_partition`, `issuance_time_basis`, `commitment_anchor`, `anchor_time_rule`, `attestation_tier`, `intent_binding`, `origin_kind`, `independence_basis`, `party_role`, `control_relation`, `evidence_origin_class` |
| `posture_and_coverage` | `containment_posture`, `coverage_denominator`, `does_not_assert`, `claim_subject`, `base_state_resolution`, `set_sufficiency`, `material_change_trigger` |
| `outcome_lattice` | `result` |
| `change_admission` | `admission_decision`, `admission_gate`, `evaluation_mode`, `replay_coverage`, `replay_snapshot`, `authority_change` |
| `done_verification` | `done_contract`, `done_receipt`, `acceptance_observed`, `protected_path`, `claimed_tool_output`, `observed_tool_output`, `stop_decision`, `inconclusive_verdict` |

Five AVE fields have no registry counterpart: `confidence_baseline`,
`detection_stage`, `detection_layer`, `evidence_kind_default` and
`detection_methodology`. The first will never get one. The registry's own
out-of-scope block excludes scored assessment of an actor, so a confidence prior
sits outside it by design and not by omission.

## Offered as a basis for collaboration

The registry is CC0-1.0 and all 37 of its terms carry the status proposed and
none carries canonical. Its promotion rule is that a term becomes canonical only
when an independently maintained system emits it in a running artifact and files
a crosswalk with a source path a reviewer can fetch. The `revisions` row above
carries that source path, `records/AVE-2026-00074.json`, and the registry's
promotion trigger for `revision_reason` asks for exactly that shape. If more
records carry `evidence_method` or more revisions, the coverage numbers in the
JSON move without the mapping changing.
