# Contributing to AVE

The AVE (Agentic Vulnerability Enumeration) standard is open. Every
contribution makes AI agents safer for everyone.

---

## Ways to Contribute

| Type | Description |
|---|---|
| New AVE record | Research and document a new agentic vulnerability class |
| Schema improvement | Propose field additions or clarifications |
| Detection rule | Add a YARA, Semgrep, or pattern rule to bawbel-scanner |
| AIVSS scoring review | Review or improve AARF scores on existing records |
| Framework mapping | Add OWASP, NIST, or MITRE mappings to existing records |
| Bug report | An existing record has an error |
| Documentation | Fix a typo, add an example, improve clarity |
| Translation | Translate records or documentation |

---

## Before You Start

1. **Check PiranhaDB** at [api.piranha.bawbel.io/records](https://api.piranha.bawbel.io/records)
   for existing coverage of the attack class you have in mind
2. **Open an issue first** for new records or schema changes to get alignment
   before writing
3. **Read the spec** in [SPEC.md](./SPEC.md) for field definitions and requirements

---

## Submitting a New AVE Record

### Step 1: Copy the template

```bash
git clone https://github.com/bawbel/ave
cd ave
cp records/template.json records/AVE-2026-DRAFT.json
```

### Step 2: Fill every required field

See [SPEC.md Section 5](./SPEC.md#5-record-schema) for field definitions.

Key requirements:
- A real-world occurrence or working proof of concept
- CVSS base vector (CVSSv4.0)
- AIVSS AARF scores with written rationale for each factor
- At least two indicators of compromise
- Step-by-step remediation

### Step 3: Validate

```bash
pip install bawbel-scanner
bawbel ave-validate ./records/AVE-2026-DRAFT.json
```

The validator checks schema compliance, required fields, and AIVSS score
calculation.

### Step 4: Open a pull request

Target `main`. Title format:

```
AVE: [Attack class] - [brief title]
```

Example: `AVE: Tool Poisoning - MCP description behavioral injection`

Fill the PR description with:
- Real-world occurrence or PoC link
- Affected platforms and registries
- AARF score rationale

---

## Schema Changes

**Additive changes** (new optional fields): standard PR review.

**Breaking changes** (removing or renaming fields): open an issue first,
30-day comment period before merging, schema version bump required.

Current schema: v0.2.0. See [SPEC.md](./SPEC.md) for the full schema.

---

## Improving Existing Records

To update an existing record:
- Fork and branch from `main`
- Make changes to the JSON or MD file
- Update `last_updated` to today in ISO 8601 format
- Open a PR with a clear description of what changed and why

AIVSS score changes require written rationale for each AARF value that changes.

---

## Code of Conduct

All contributors are expected to treat each other with respect. Security
research involves difficult topics. Disagree on technical grounds, not
personal ones. We are all trying to make AI agents safer.

---

## Researcher Recognition

Every accepted AVE record permanently credits the researcher by name.

---

## Questions

Open a [GitHub Discussion](https://github.com/bawbel/ave/discussions) or
email bawbel.io@gmail.com.