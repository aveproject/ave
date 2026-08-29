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
  derived evidence basis is structurally strong (multiple engines, or a
  non-inferred evidence kind).
- `0.55 to 0.84` — "mid-signal" band. Consistent with a floor basis; treat
  as an unverified declaration unless the basis is strong.
- `< 0.55` — "low-signal" band. Consistent with a floor basis; safe to
  treat as low-confidence regardless of basis.

## When to distrust the number

A record whose `confidence_baseline` is `>= 0.85` while its derived basis
is at the floor is a "declared, not structurally verified" signal. The
floor is defined as:

- `evidence_basis_engines` has one member (regardless of which engine), or
- `evidence_kind_default` is `semantic_inference`.

`scripts/check_confidence_signal.py` computes this for every record in
`records/`. It is a soft warning: it prints findings and leaves the exit
code alone (the same shape as `check_researcher_matches_disclosure` in
`validate_records.py`), so it fits next to the existing validator machinery
without changing gate behaviour.

## The disagreement rule

The check flags disagreement; it does not certify truth. A record flagged
as floor-basis with high confidence has not been proven wrong. It has been
proven unsupported: the author's number carries no structural backing a
consumer can re-derive. Do not describe the check as auditability. It
closes a self-certification gap; it does not create an audit trail on its
own.

## Known false-positive shape

AVE-2026-00074 is deliberately shipped as the fixture for this check. Its
`confidence_baseline` (0.85) sits at the high band while its basis reads as
a floor, but its own `detection_methodology` says the finding came from
querying external authorities (GitHub's users API, package registries,
RDAP, provider fingerprints). The floor there is an enum gap:
`evidence_basis_engines` has no member for "an external authority was
queried and returned a determinate answer." The honest author wrote the
nearest available value and the derived basis came out at the floor.

The check prints a note on this shape so it reads as an enum gap, not an
overclaim.

## Escalation condition

Per the issue thread: when `evidence_basis_engines` carries a member for an
external-authority query (the thread's agreed name: `external_authority`),
and a re-run of this check fires zero times on any record whose
`detection_methodology` names an authority probe, the field has earned its
version bump. Both halves of that condition are read off the schema and the
data, so it needs no date, constant, curation queue, or outcome tracking.

## Normalisation

The 80 records carry 13 distinct basis sets written 18 different ways
(five sets appear in two orders each). The check compares engine sets
(set-normalised), not raw lists, so consumers see 13 bases, not 18.
Canonicalising the files themselves is worth doing separately.
