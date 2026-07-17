# CONTEXT.md - aveproject/ave

Internal context for anyone working on this repo, including Claude Code
sessions. Not a strategy document; that content lives with whoever operates a
given implementation, not with the standard. See the note at the end.

---

## What AVE is

The behavioral classification standard for agentic AI components: stable IDs,
behavioral fingerprints, AIVSS scoring, framework crosswalks, and detection
guidance for a class of vulnerability that package-oriented standards cannot
describe.

Relates to existing frameworks the way CWE relates to OWASP Top 10: a Top 10
names the categories that matter; AVE supplies the individually scored,
individually detectable records underneath them.

**Framing discipline.** Do not describe AVE as "the CVE for AI agents" or "the
CWE for AI agents." Use AVE's own terms: "the behavioral classification
standard for agentic AI components." The comparison to CWE is useful as an
explanation of the shape of the artifact, not as a claim of identity or
inherited authority.

AVE is implemented by more than one tool. Any implementer, Bawbel's own tools
included, is a consumer of this standard, not its owner. If a sentence in this
repo could be read as asserting that AVE exists to serve one implementer's
product strategy, it is wrong and should be rewritten, regardless of who wrote
it or how internal the document is.

---

## Why it exists

Existing vulnerability standards were built for conventional software. CVE
maps to CPE. OSV maps to package and version range. Neither can describe a
prompt injection hidden in an MCP tool description: there is no package, no
version, no vulnerable dependency. The threat is behavioral, and the same
malicious behavior appears in effectively unlimited textual forms.

AVE fills that gap: stable IDs, behavioral fingerprints, AIVSS scoring,
framework mappings, and detection guidance for the attack surface the
package-oriented world cannot see.

---

## Relationship to OSV.dev

Complementary, not competing. OSV answers "does this package version have a
known vulnerability?" AVE answers "does this agent component behave
dangerously?" A full scan runs both: OSV for dependencies, AVE for agent
components. AVE originates net-new behavioral classes; OSV aggregates
existing package-level findings.

Do not describe AVE as "OSV for AI agents." OSV is an aggregator. AVE is a
classification standard. Different problem, different mechanism.

---

## Current status

| | |
|---|---|
| Records published | 59 (schema_version 1.1.0) |
| Schema version | 1.1.0 |
| Registry and docs | aveproject.org |
| Repo | github.com/aveproject/ave |

Third-party services that consume AVE, including any Bawbel-operated ones, are
implementations of the standard, not part of it, and are documented in their
own repos, not here. If a new resource needs listing in this table, confirm
first whether it is the standard itself or something built on top of it; only
the former belongs in this table.

---

## Standards alignment

| Standard | Field | Status |
|---|---|---|
| OWASP AIVSS v0.8 | `aivss` object | required once a record is active or deprecated |
| OWASP MCP Top 10 | `owasp_mcp` | required once active or deprecated, MCP01-MCP10 |
| OWASP Agentic Security Initiative Top 10 | `owasp_asi` | optional, ASI01-ASI10 |
| MITRE ATLAS | `mitre_atlas` | optional, AML.Txxxx |
| NIST AI RMF | `nist_ai_rmf` | optional |

---

## Record count discipline

Growth is bounded by distinct behavioral classes, not by any external target
or event. Do not pad the count. If a proposed record is a variant of an
existing class rather than a genuinely distinct one, it should be merged into
that record's `example_patterns` or `mutation_count`, not published separately.

---

## How to work on AVE

See CLAUDE.md for session rules and the current task queue.
See ARCHITECTURE.md for the record/rule/fixture model.
See CONTRIBUTING.md for the contributor-facing process.
See GOVERNANCE.md for decision process and the record proposal workflow.

**Roadmap, launch planning, adoption tactics, and anything with a marketing or
fundraising deadline attached does not belong in this repo, including as an
internal-only file.** That content lives with whoever operates a given
implementation and tracks their own trust-building strategy; for the current
maintainer, that is `TRUST_STRATEGY.md`, kept outside this repo. This
separation is deliberate, not an oversight: this repo is what a second
implementer, an OWASP reviewer, or a future co-maintainer will read directly,
and it should contain only what is true of the standard itself.