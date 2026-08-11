# Contributors

This describes what people actually contributed, specifically, not a
flat list of names. Some of the most substantial work here lives in
issue-thread design discussion, not merged code, and wouldn't appear in
a commit-based contributor graph at all. This file exists so that work
is credited honestly, at the same level of detail as everything else
this project tries to get right.

## Standard design and governance

**[astrogilda (Sankalp Gilda)](https://github.com/astrogilda)**: the crosswalk schema itself
(`schema/crosswalk-1.0.0.schema.json`, #121), including the commit-pin
mechanism and its three-outcome design (pinned, declared unpinnable
with a falsifiable exemption, or neither), refined across #160 and
#171. Caught two staleness bugs in his own already-merged work by going
back to verify it rather than assuming a merge meant it was done,
including a field he had written himself and later, incorrectly,
described as absent. First proposed the `confidence_baseline` design
question independently corroborated in #98. An open crosswalk proposal
(#94, AEE, an in-toto attestation predicate) remains paused pending an
external spec clearing its own vetting process, not on anything AVE
needs to resolve.

## Crosswalk contributions

**[predictor2718 (Nicolai)](https://github.com/predictor2718)**: the cfgaudit crosswalk
(`crosswalks/cfgaudit-to-ave.json`), built independently and
unprompted after AVE's initial launch, including a from-scratch
comparison against the reference scanner that produced the strongest
independent validation this project has had that its ID scheme is
interoperable, not just internally consistent. Provided detailed,
mechanism-level breakdowns (issue #68) that directly enabled several
new records, correcting AVE's own request for clarity on multi-part
attack surfaces it had initially treated as single classes.

## Fixes and corrections

**[mmaxjr](https://github.com/mmaxjr)**: fixed a real, previously uncaught gap in
`validate_records.py` (#130), where date-time format validation was
silently not enforced, as a first-time contributor. Also corrected an
incorrect assumption in the issue that described the fix, rather than
implementing the wrong assumption as written.

**[Alex Greenshpun (alexgreensh)](https://github.com/alexgreensh)**, maintainer of repo-forensics: not
an AVE code contributor, but caught a real, substantive attribution
error: two published records credited an AVE maintainer as researcher
when the underlying vulnerability research was actually done by
external disclosing parties. The correction changed how this project
now sources the `researcher` field going forward, documented in
`docs/specs/researcher-process.md`, not just fixed on the two affected
records.
