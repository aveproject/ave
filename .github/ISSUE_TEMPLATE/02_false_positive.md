---
name: "False Positive Report"
about: Report an AVE record or detection rule that fires incorrectly on legitimate content
title: "[False Positive] AVE-2026-"
labels: false-positive, needs-review
assignees: ''
---

## AVE Record

**AVE ID:** <!-- e.g. AVE-2026-00002 -->
**Record title:** <!-- copy the title from the record -->

---

## Why is this a false positive?

<!-- Explain clearly why this record is incorrect, overly broad, or misclassified. -->

---

## Technical Evidence

<!-- Provide specific technical evidence. Show the content that triggered the finding
     and explain why it is not actually dangerous. -->

---

## Context

**Tool version:** <!-- bawbel-scanner version that produced the finding -->
**Detection engine:** <!-- pattern / yara / semgrep / llm / magika -->
**Component type:** <!-- skill / mcp / prompt / plugin / etc. -->

---

## Suggested Resolution

- [ ] Narrow the behavioral fingerprint in the AVE record
- [ ] Update the detection methodology to add an exclusion
- [ ] Update the detection rule in bawbel-scanner
- [ ] Mark this specific case as accepted risk (not a record change)
- [ ] Other: <!-- describe -->

---

## Your Details (optional)

**Name:**
**Organisation:**