# Evidence vantage: producer guide

This is the producer half of issue #98. A consumer-side check can read what
a record says about its own confidence, but everything it reads was typed by
the record's author, so it is reading a self-report however carefully it
reads it. What changes that is the record stating structurally where its
evidence came from. That is what `evidence_vantage` and `evidence_method`
are for, and `verification_basis` is what the validator computes from them.

## The two axes

`evidence_vantage` says where every input this class's evidence depends on
was obtained.

- `substrate` -- obtained at a vantage the observed artifact could neither
  forge nor suppress: a registry answering about a package, RDAP answering
  about a domain, a sandbox watching execution from outside.
- `artifact` -- at least one input derives from output the artifact itself
  produced: its own text, its own manifest, its own logs.

`evidence_method` says how the evidence was established.

- `intercepted` -- from events captured as they occurred.
- `reconstructed` -- from state examined after the fact.

Both are taken from the **weakest input**. A determination computed by
trusted machinery over content the artifact wrote is `artifact`, however
trusted the machinery, because the artifact could have written that content
without doing the thing the record describes. A claim that fuses a live
capture with an after-the-fact examination is `reconstructed`.

## The floor is always available

`artifact` and `reconstructed` are the weaker value of each axis, and each
is a claim a producer may always truthfully make. Stating either is not an
admission and carries no penalty. A consumer learns from it only that the
record lacks the stronger binding. This matters more than it looks: if the
weaker value reads as a confession, honest authors avoid it, values drift
upward, and the axis stops meaning anything within a year.

Both axes are optional, and **absence reads as the floor**. Silence is never
credited as the stronger claim.

## verification_basis is computed, never written

`verification_basis` is the composition of the two axes with the vantage the
record's `evidence_basis_engines` set can reach. Compute it with:

```bash
python scripts/write_verification_basis.py            # report disagreements
python scripts/write_verification_basis.py --write    # stamp the derived value
```

The engine set is a **ceiling** and the declared vantage is the **claim**,
and the derived value is the weaker of the two. `pattern`, `yara`,
`semgrep`, `llm` and `magika` all read content the artifact produced, so a
record detected only by those cannot reach `substrate` whatever it declares.
`sandbox` and `external_authority` can.

A record may carry a declared `verification_basis`, and
`scripts/validate_records.py` then recomputes it and **fails** on a
mismatch. That is the point of allowing the declaration at all: it is
falsifiable, unlike a number an author simply assigns. Understating fails
too, because the field states what the derivation computes.

`--write` refuses any record whose file is not already in the script's own
serialisation, rather than reformatting it. Most of the corpus is not, so
canonicalising the record files is separate work, done deliberately and
reviewed on its own.

## external_authority

The `evidence_basis_engines` enum gained `external_authority` for the case
where a party outside the observed artifact was queried and returned a
determinate answer: a package registry, RDAP, a forge's user API. The six
existing members all run over content, and none of them can say an outside
party was asked and answered, so before this member existed a record of that
shape had no value to write and its author wrote the nearest one.

The name states the observation rung and nothing about whether the answer
was right. A determinate answer from an authority is still an answer that
can be wrong, and reading it as verification is exactly the overclaim this
issue exists to prevent.

`AVE-2026-00074` is the record that made the gap visible: its
`detection_methodology` probes GitHub's users API, package registries, RDAP
and provider fingerprints, and its `evidence_basis_engines` reads
`["pattern"]` because that was the closest available value. Adding the new
member to that record is a deliberate follow-up, not part of adding the
member to the enum, because it is also the record
`scripts/check_confidence_signal.py` ships as its fixture.

## What this does not do

It does not certify that a record is right. It says where an observation was
made from and how, so a consumer can tell a determination resting on an
outside answer from one resting on a phrase match. That closes a
self-certification gap. It does not create an audit trail on its own.
