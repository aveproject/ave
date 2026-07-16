---
name: New AVE record
about: Propose a new Agentic Vulnerability Enumeration record
title: "[AVE] New class: <attack_class>"
labels: ave-record, new-class
assignees: ''
---

## Before you open this issue

- [ ] I have searched the registry at aveproject.org and the `records/` directory
- [ ] This is a genuinely distinct behavioral class, not a variant of an existing record
- [ ] I have a citable primary source (CVE, paper, disclosure, or working PoC)

---

## Behavioral fingerprint

<!-- One or two sentences: what does the vulnerable component DO that is dangerous?
     Behavioral, not a byte signature. A second implementer should be able to write
     a detection rule from this alone. -->

## Why this is a new class, not a variant

<!-- Which existing records did you check? Why does none of them cover this behavior? -->

## Primary source

<!-- CVE id, arXiv link, vendor disclosure URL, or PoC reference. Required. -->

## Proposed record skeleton

```
attack_class:
severity:           (estimate — CRITICAL / HIGH / MEDIUM / LOW)
owasp_mcp:          [MCPxx]
owasp_asi:          [ASIxx]   (if applicable)
mitre_atlas:        [AML.Txxxx]  (if applicable)
detection_layer:    content | server_card | registry_metadata | runtime | transport
detection_stage:    static_detection | runtime_observed
evidence_basis_engines: [pattern | yara | semgrep | llm | sandbox]
```

## Real-world evidence

<!-- CVE id, in-the-wild observation, or "theoretical only" — affects THM in AIVSS scoring -->

## Indicators of compromise

<!-- At least one observable string or pattern a defender can search for in a real file -->

## Researcher

<!-- Your name or handle — will appear in the published record's researcher field -->