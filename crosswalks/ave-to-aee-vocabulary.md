# AVE to aee-vocabulary

A field-level crosswalk between AVE's evidence-provenance properties and the
aee-vocabulary registry, which names the axes an execution-evidence claim is
read on: who observed the execution, how directly, and what the claim leaves
out. Machine-readable form in
[`ave-to-aee-vocabulary.json`](ave-to-aee-vocabulary.json), against
[`schema/crosswalk-1.0.0.schema.json`](../schema/crosswalk-1.0.0.schema.json).

| | |
|---|---|
| Source | AVE 1.1.0, 80 records, commit `1e29789e4941b6c1c2435508dbf3c245eedc8d04` |
| Target | [aee-vocabulary](https://github.com/astrogilda/aee-vocabulary) 0.2.0, 8 terms, CC0-1.0, commit `66177d65690e9d7eb7e4ff59df8f91792a90735b` |
| Generated | 2026-09-15 |
| Unit | one schema property, not one category |

## Read this first

None of the 80 records carries `evidence_vantage`, `evidence_method` or
`verification_basis`. All three are optional in schema v1.1.0, and all three
read absent on every record file at the pinned commit. That was checked by
fetching each of the 80 files, not by reading the schema.

So every row below carries an evidence state of inferred, established by
comparing two schema definitions. None carries emitted, and a reviewer should
not read one that way. A row moves to emitted when a record carries the field
and the reviewer can fetch it. The script that writes verification_basis has
nothing to derive over until that happens.

## The mapping

| AVE field | Registry term | Match | Why |
|---|---|---|---|
| `evidence_vantage` | `observation_vantage` | exact | `substrate` and `artifact` on both sides, same two values, same weakest-input composition |
| `evidence_method` | `observation_directness` | exact | `intercepted` and `reconstructed` on both sides, same composition, same floor |
| `verification_basis` | `observation_vantage` + `observation_directness` | structural | AVE's four values are the product of the two registry axes; either side converts without loss |
| `evidence_basis_engines` | `observation_vantage` | partial | `external_authority` and `sandbox` sit on the substrate side; the five artifact-reading engines sit on the other |

The two exact rows are unusual and worth a sentence. The definitions were
written independently, on different sides, and reached the same two-value split
with the same composition rule. That is the case for calling them exact rather
than approximate: there is nothing to reconcile.

## What does not map

Six registry terms have no AVE counterpart, because an AVE record classifies a
component's behavior while the registry describes one observed execution.

| Registry term with no AVE counterpart | AVE field with no registry counterpart |
|---|---|
| `field_evidence_partition` | `confidence_baseline` |
| `issuance_time_basis` | `detection_stage` |
| `containment_posture` | `detection_layer` |
| `coverage_denominator` | `evidence_kind_default` |
| `does_not_assert` | |
| `result` | |

The first field in the right-hand column will never get a counterpart. The
registry's own out-of-scope block excludes scored assessment of an actor, so a
confidence prior sits outside it by design and not by omission.

The per-field reasons are in the gaps array of the JSON.

## Offered as a basis for collaboration

The registry is CC0-1.0 and its eight terms all carry the status proposed and none carries canonical. Its
promotion rule is that a term becomes canonical only when an independently
maintained system emits it in a running artifact and files a crosswalk with a
source path a reviewer can fetch. AVE already declares two of those fields in
its schema. If records start carrying them, the two exact rows above become the
evidence that rule asks for, and the coverage number in the JSON moves without
the mapping changing.
