# ADR-0001: Behavioral fingerprints over signatures

Status: Accepted
Date: 2026-04-20

## Decision

AVE records describe what a component DOES (behavioral_fingerprint), not
what it looks like (byte signature). OSV.dev maps to package+version. CVE
maps to CPE. AVE maps to behavior because agent components have no version
and the same malicious behavior appears in infinitely many textual forms.

## Consequences

Positive: one AVE catches many textual variants of the same attack.
Positive: resistant to trivial obfuscation that defeats string signatures.
Negative: harder to author — requires describing intent, not matching bytes.
