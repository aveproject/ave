## Type of change

- [ ] New AVE record submission
- [ ] Update to existing AVE record
- [ ] Schema change (v1.0.0)
- [ ] New detection rule (YARA / Semgrep / pattern)
- [ ] Crosswalk addition or update
- [ ] Documentation improvement
- [ ] Other:

---

## Description

<!-- What does this PR do?
     For AVE submissions: summarise the vulnerability in 2-3 sentences. -->

---

## AVE record(s)

<!-- List AVE IDs. Use AVE-PENDING for new submissions not yet assigned a number. -->

---

## Checklist

### For new AVE record submissions

- [ ] Linked issue confirms the id and that this is a new class, not a variant
- [ ] Record validates against `schema/ave-record-1.1.0.schema.json`
- [ ] All 15 required fields are present and non-empty
- [ ] `behavioral_fingerprint` is one clear sentence describing what the component DOES
- [ ] `indicators_of_compromise` has at least one entry a defender can actually search for
- [ ] `owasp_mcp` is present with at least one entry
- [ ] `aivss` block is complete — required sub-fields: cvss_base, aars, thm, mitigation_factor, aivss_score, spec_version
- [ ] `aivss.aivss_score` agrees with `severity` (CRITICAL >= 9.0, HIGH 7.0–8.9, MEDIUM 4.0–6.9, LOW < 4.0)
- [ ] Top-level `aivss_score` matches `aivss.aivss_score` if both are present
- [ ] `references` has at least one citable primary source
- [ ] `researcher` is set
- [ ] AARF rationale for each non-zero factor is in the PR description
- [ ] Coordinated scanner PR in bawbel/scanner is linked (rule + positive and negative fixtures)
- [ ] Responsible disclosure followed if this involves a specific component or publisher

### For updates to existing records

- [ ] `last_updated` is set to today in ISO 8601 format
- [ ] Change is explained in the PR description
- [ ] If `aivss_score` changes: AARF rationale for each changed factor is in the PR description

### For schema changes

- [ ] Issue opened first with 30-day comment period completed (structural changes only)
- [ ] `schema/ave-record.schema.json` (alias) updated to mirror the new canonical
- [ ] New versioned schema file added (e.g. `schema/ave-record-1.2.0.schema.json`) — prior versioned files stay frozen, never edited
- [ ] CHANGELOG.md updated
- [ ] Migration path for existing records documented

### For all PRs

- [ ] I have read CONTRIBUTING.md
- [ ] `ave_id` values are immutable — no renumbering
- [ ] Schema version string is `1.0.0`
- [ ] No references to SPEC.md (removed), template.json (removed), or bawbel/bawbel-ave (wrong path)
- [ ] I agree my contribution is licensed under Apache 2.0