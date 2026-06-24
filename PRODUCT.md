# PRODUCT.md — bawbel/ave

Internal product context for Claude Code sessions. Not published.

---

## What AVE is

The behavioral classification standard for agentic AI components.
Relates to AST10/ASI the way CWE relates to OWASP Top 10 — a Top 10 names the
categories that matter; AVE supplies the individually-scored, individually-
detectable records underneath them. An open standard that bawbel-scanner
implements as its reference implementation. Not a feature of the scanner; an
independent asset with its own schema, registry, and community.

AVE is Layer 1 of the Bawbel five-layer architecture. The open layers
(AVE standard + scanner) drive adoption and community trust. The proprietary
layers (PiranhaDB, registry, web platform) are the commercial moat.

---

## Why it exists

Existing vulnerability standards were built for conventional software.
CVE maps to CPE. OSV maps to package and version range. Neither can describe
a prompt injection hidden in an MCP tool description — there is no package,
no version, no vulnerable dependency. The threat is behavioral. The same
malicious behavior appears in infinitely many textual forms.

AVE fills that gap: stable IDs, behavioral fingerprints, AIVSS scoring,
framework mappings, and detection rules — for the attack surface that the
package world cannot see.

Do not frame AVE as "the CVE for AI agents" or "the CWE for AI agents."
Use own-terms framing: "the behavioral classification standard for agentic
AI components." The comparison to CWE is useful as an explanation, not as
an identity.

---

## Current status

| | |
|---|---|
| Records published | 51 (schema_version 1.0.0) |
| Schema version | 1.0.0 (canonical, published) |
| Registry | ave.bawbel.io (live) |
| Threat intel API | api.piranha.bawbel.io |
| Site repo | github.com/bawbel/ave-site |
| Latest release | v1.1.0 |

---

## Standards alignment

| Standard | Field | Status |
|---|---|---|
| OWASP AIVSS v0.8 | `aivss` object | required in every record |
| OWASP MCP Top 10 | `owasp_mcp` | required, MCP01-MCP10 |
| OWASP Agentic AI Top 10 | `owasp_mapping` | optional, ASI01-ASI10 |
| MITRE ATLAS | `mitre_atlas_mapping` | optional, AML.Txxxx |
| NIST AI RMF | `nist_ai_rmf_mapping` | optional |
| OWASP AIBOM | planned via `bawbel abom` CycloneDX command | future |

---

## Relationship to OSV.dev

Complementary, not competing. OSV answers "does this package version have
a known vulnerability?" AVE answers "does this agent component behave
dangerously?" A full scan runs both: OSV for dependencies, AVE for agent
components. AVE originates net-new behavioral classes; OSV aggregates
existing package-level findings.

Do not frame AVE as "OSV for AI agents" — OSV is an aggregator. AVE
is a classification standard. Different problem, different mechanism.

---

## Adoption strategy

The field has many scanners and no shared vocabulary. Independent studies
find different tools barely agree on what they flag — no pair overlaps more
than 10.4%, only 0.69% of skills are flagged by all three in the OpenClaw
study. That fragmentation is the AVE adoption argument: the field needs a
common reference, and AVE is it.

The adoption path:
1. Crosswalks — map SkillSpector and ClawScan finding types to AVE ids
   (unilateral, no ask required, positions AVE as neutral reference)
2. AVE-in-SARIF — AVE ids travel inside SARIF into GitHub Security tab
   and CI for free (docs/specs/ave-in-sarif.md, shipped in v1.1.0)
3. Open data dump — full record set downloadable as one JSON file
   (ave-records-v1.1.0.json, attached to the v1.1.0 GitHub release)
4. Second implementer — a non-Bawbel tool emitting or mapping AVE ids
   (this is the most urgent gate; pursue before OWASP proposal)
5. Institutional backing — MITRE CWE AI Working Group contribution,
   OWASP AST10 crosswalk PR, OWASP project proposal
   (proposal only after second implementer is confirmed)

---

## Roadmap

**v1.2 (next)**
- GOVERNANCE.md — decision process, record proposal workflow, governance path
- CODE_OF_CONDUCT.md — Contributor Covenant v2.1
- docs/specs/ave-implementer-guide.md — three consumption patterns:
  runtime API, bundled offline (air-gapped), ID-only emission
- Offline release artifact: ave-records-v1.1.0.json attached to v1.1.0 release
- AST10 crosswalk PR — contribute crosswalks/ave-to-ast10.json to OWASP AST10 repo
- CWE AI Working Group outreach — gap-mapping issue on CWE-CAPEC/AI-Working-Group
- Second implementer outreach — contact scanner maintainers with crosswalk packages
- Resource exhaustion / agentic DoS record — one confirmed gap from benchmark-2026-06

**Trust-building (parallel)**
- Technical write-ups on priority records: 00001, 00002, 00042, 00045, 00048
- Target 10 write-ups before Product Hunt
- Respond to the Reddit framing discussion — acknowledge behavioral classification
  framing, link to updated docs

**Later**
- OWASP project proposal — after second implementer is confirmed and
  a second project leader candidate is identified
- OWASP AIBOM integration via `bawbel abom` CycloneDX command
- Advisory board (only when real reviewers exist — not decoration)

---

## Record count discipline

Target: ~60-65 high-quality records by Product Hunt, reached deliberately.
Do not push to 100. Research shows ~25-35 genuinely distinct behavioral
classes exist (MCPSecBench 17, Formal Security Framework 23, Hou et al 16,
MCP-SafetyBench 20, MCPTox 11 — heavy overlap). At 51 records we are likely
past the count of distinct classes already.

Growth path: audit and merge variants, fill genuine gaps from the
research-new-attack-classes skill. Record count = distinct behavioral
classes, no padding.

---

## How to work on AVE

See CLAUDE.md for session rules and the current task queue.
<!-- See HOW-TO-USE.md for the session start/end sequence. -->
See ARCHITECTURE.md for the record/rule/fixture model.
See CONTRIBUTING.md for the contributor-facing process.