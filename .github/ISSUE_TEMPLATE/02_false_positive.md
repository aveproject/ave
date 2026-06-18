---
name: False positive report
about: A detection rule fires incorrectly on a benign file
title: "[FP] <rule_id> fires on <description>"
labels: false-positive
assignees: ''
---

## Rule ID

<!-- The bawbel rule id, e.g. bawbel-tool-description-injection -->

## AVE ID

<!-- The AVE record the rule implements, e.g. AVE-2026-00002 -->

## Description of the false positive

<!-- What benign file or pattern triggers the rule? Why is it not malicious? -->

## Reproduction

```
# Minimal file content or pattern that triggers the false positive
```

## Suggested fix

<!-- Optional: how would you tighten the rule to avoid this false positive
     without losing the true positive? Include a negative fixture suggestion. -->