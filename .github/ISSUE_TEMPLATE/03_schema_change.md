---
name: "Schema Change Proposal"
about: Propose a change to the AVE record schema (v0.2.0)
title: "[Schema] "
labels: schema-change
assignees: ''
---

## Change Type

- [ ] **Breaking change** - removing or renaming a field (requires 30-day comment period before merge)
- [ ] **Additive change** - new optional field (standard PR review, no waiting period)

---

## Proposed Change

**Field name:**
**Current definition (if existing):**
**Proposed definition:**
**Type:** <!-- string / integer / float / boolean / enum / array / object -->
**Required:** <!-- yes / no -->
**Allowed values (if enum):**

---

## Rationale

<!-- Why is this change needed?
     What attack class or detection capability does it enable that the current schema cannot express?
     Why can the same goal not be achieved with existing fields? -->

---

## Impact on Existing Records

<!-- How many of the 45 published records would be affected?
     Would they need updating? Are you willing to update them in the same PR? -->

---

## Example

```json
{
  "ave_id": "AVE-2026-00001",
  "new_field_name": "example value showing the field in use"
}
```

---

## Backwards Compatibility

<!-- If this is an additive change: can parsers that do not know this field
     safely ignore it without breaking? -->