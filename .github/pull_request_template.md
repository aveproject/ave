## Type of change

- [ ] New AVE record submission
- [ ] Update to existing AVE record
- [ ] Schema change (v0.2.0)
- [ ] New detection rule (YARA / Semgrep)
- [ ] Documentation improvement
- [ ] Other:

---

## Description

<!-- What does this PR do?
     For AVE submissions: summarise the vulnerability in 2-3 sentences. -->

---

## AVE Record(s)

<!-- List AVE IDs. Use AVE-PENDING for new submissions not yet assigned a number. -->

---

## Checklist

### For new AVE record submissions

- [ ] Record follows schema v0.2.0 (see SPEC.md Section 6)
- [ ] All required fields are present and non-empty
- [ ] `attack_class` uses "Category - Subcategory" format with no em dashes
- [ ] `behavioral_fingerprint` is one clear sentence
- [ ] `detection_methodology` is step-by-step and reproducible
- [ ] `indicators_of_compromise` has at least 2 entries
- [ ] `owasp_mapping` (ASI codes) is correct
- [ ] `owasp_mcp` (MCP codes) is correct
- [ ] `aivss` block is complete with all 10 AARF scores and written rationale in `notes`
- [ ] `aivss_score` at top level matches `aivss.aivss_score`
- [ ] `cvss_base_vector` is a valid CVSSv4.0 vector string
- [ ] `mutation_count` is an integer >= 0
- [ ] Responsible disclosure process followed (see CONTRIBUTING.md)
- [ ] Researcher name is accurate and has been verified with them

### For updates to existing records

- [ ] `last_updated` is set to today in ISO 8601 format
- [ ] Change is explained in PR description
- [ ] If AIVSS score changes: new AARF rationale is in `aivss.notes`

### For schema changes

- [ ] Issue opened first with 30-day comment period completed (breaking changes only)
- [ ] SPEC.md updated to reflect the change
- [ ] `records/template.json` updated
- [ ] Existing records updated if required (or PR description explains why not)
- [ ] Schema version bumped if breaking

### For all PRs

- [ ] I have read CONTRIBUTING.md
- [ ] No em dashes in any field values (use hyphens instead)
- [ ] No CVSS-AI references (use AIVSS)
- [ ] No bawbel/bawbel-ave URLs (use bawbel/ave)
- [ ] I agree my contribution is licensed under Apache 2.0