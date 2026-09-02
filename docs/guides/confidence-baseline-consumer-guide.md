# confidence_baseline: consumer handling guide

This guide answers issue #98's first shape ("document the handling, don't
change the field") and the compliance angle raised independently on
r/ai_governance. It is the consumer-side companion to
`scripts/check_confidence_signal.py`.

## What `confidence_baseline` is

A float, 0.0 to 1.0, assigned by the record's author. Today it is
self-reported: nothing external verifies it, and the same value appears
whether the underlying evidence is a formally disclosed CVE or a
speculative pattern match. That asymmetry is the gap this issue names.

## How to read it (bands)

- `>= 0.85` — "high-signal" band. Only act on this band when the record's
  evidence is both observed from a vantage the artifact does not control
  and corroborated by more than one source.
- `0.55 to 0.84` — "mid-signal" band. Consistent with a floor basis; treat
  as an unverified declaration unless the basis is strong.
- `< 0.55` — "low-signal" band. Consistent with a floor basis; safe to
  treat as low-confidence regardless of basis.

## When to distrust the number: two findings, not one

A record whose `confidence_baseline` is `>= 0.85` can be resting on either
of two weaknesses, and they are independent. Neither implies the other, so
a consumer is told which:

- **`vantage_floor`** — the observation was made from a place the observed
  artifact controls. Either the record's derived `verification_basis` puts
  it at the `artifact` rung, or its `evidence_kind_default` is
  `semantic_inference`, which is an inference over content the artifact
  produced however good the inference. Remedied by observing from a vantage
  the artifact can neither forge nor suppress — a sandbox watching
  execution from outside, an external authority answering about it — and
  declaring that on `evidence_vantage`.
- **`independence_floor`** — the evidence rests on a single source:
  `evidence_basis_engines` names at most one legible member. Remedied by
  corroborating with a second, independent engine.

A record can carry both, one, or neither.

These were one check until the two predicates were run against each other
over the same field. Engine-set cardinality was the check's original floor
test, chosen when no measure of vantage existed, and it turns out not to
approximate vantage at all: a record with two engines that both read
artifact-produced content derives `artifact_intercepted` and cardinality
stays silent, while a record with a single `sandbox` engine derives
`substrate_intercepted` and cardinality flags it. Cardinality measures
**corroboration**, how many independent sources agreed. The derivation
measures **vantage**, where the observation was made from. Both are worth
knowing and they are fixed by different work, so they are reported
separately rather than collapsed into one warning a consumer cannot act
on.

`scripts/check_confidence_signal.py` computes both for every record in
`records/`. It is a soft warning: it prints findings and leaves the exit
code alone (the same shape as `check_researcher_matches_disclosure` in
`validate_records.py`), so it fits next to the existing validator machinery
without changing gate behaviour. `--json` emits
`{"findings": [{"ave_id", "finding", "signal"}], "count", "records"}`,
where `finding` is `vantage_floor` or `independence_floor`, `count` is
findings and `records` is the records they fall on.

The vantage arm asks `scripts/write_verification_basis.py` for the derived
vantage rather than recomputing it, and derives even where a record carries
a stamped `verification_basis`. Two reasons: a second predicate over the
same field is what produced the disagreement above, and the stamp is what
an author typed, so a consumer-side check reading it would be reading a
self-report. A record that declares no `evidence_vantage` derives the
floor — silence is never credited as a claim — so this arm does fire on
records that simply have not said. Stating the floor is free; stating it
alongside a 0.9 is the combination this check exists to surface.

## The disagreement rule

The check flags disagreement; it does not certify truth. A record flagged
as floor-basis with high confidence has not been proven wrong. It has been
proven unsupported: the author's number carries no structural backing a
consumer can re-derive. Do not describe the check as auditability. It
closes a self-certification gap; it does not create an audit trail on its
own.

## Known false-positive shape

AVE-2026-00074 is deliberately shipped as the fixture for this check. Its
`confidence_baseline` (0.85) sits at the high band while its own
`detection_methodology` says the finding came from querying external
authorities (GitHub's users API, package registries, RDAP, provider
fingerprints). Before issue #218 the floor there was an enum gap:
`evidence_basis_engines` had no member for "an external authority was
queried and returned a determinate answer", so the honest author wrote the
nearest available value and the derived basis came out at the floor.

The check prints a note on this shape so it reads as an enum gap rather
than an overclaim, and the note has two forms because the gap can now be
closed. A record whose engine set still cannot reach `substrate` gets the
original sentence: add the `external_authority` member. A record that has
already adopted the member — AVE-2026-00074 since #218 — is told the
opposite: its ceiling permits `substrate` and what holds it at the floor is
that it has never declared `evidence_vantage`. Sending that author looking
for a missing enum member would be sending them after a bug that is not
there.

## Escalation condition

Per the issue thread: when `evidence_basis_engines` carries a member for an
external-authority query (the thread's agreed name: `external_authority`),
and a re-run of this check emits the enum-gap form of the note on no record
at all, the field has earned its version bump. Both halves of that
condition are read off the schema and the data, so it needs no date,
constant, curation queue, or outcome tracking.

Note what that condition is now careful not to say. A record naming an
authority probe can still carry a `vantage_floor` finding after adopting
the member, because adopting it raises the ceiling and the record must
still declare the vantage it reached. That is a producer's remaining step,
not evidence of a vocabulary gap, and it is the enum-gap note rather than
the finding that has to fall silent.

## Normalisation

The 80 records carry 13 distinct basis sets written 18 different ways
(five sets appear in two orders each). The check compares engine sets
(set-normalised), not raw lists, so consumers see 13 bases, not 18.
Canonicalising the files themselves is worth doing separately.
