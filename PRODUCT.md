# PRODUCT.md — bawbel/ave

Internal product context for Claude Code sessions. Not published.

---

## What AVE is

The behavioral vulnerability enumeration standard for agentic AI components.
Relates to AST10/ASI the way CVE relates to OWASP Top 10 — a Top 10 names the
categories that matter; AVE supplies the individually-scored, individually-
detectable records underneath them. An open standard that bawbel-scanner
implements as its reference implementation. Not a feature of the scanner; an
independent asset with its own schema, registry, and community.

AVE is Layer 1 of the Bawbel five-layer architecture. The open layers
(AVE standard + scanner) drive adoption and community trust. The proprietary
layers (PiranhaDB, registry, web platform) are the commercial moat.

---

## Why it exists

CVE maps to CPE. OSV maps to package and version range. Neither can describe
a prompt injection hidden in an MCP tool description — there is no package,
no version, no vulnerable dependency. The threat is behavioral. The same
malicious behavior appears in infinitely many textual forms.

AVE fills that gap: stable IDs, behavioral fingerprints, AIVSS scoring,
framework mappings, and detection rules — for the attack surface that the
package world cannot see.

---

## Current status

| | |
|---|---|
| Records published | 48 (schema_version 0.2.0, migrating to 1.0.0 in v1.1) |
| Schema version | 1.0.0 (canonical, published) |
| Registry | ave.bawbel.io (live) |
| Threat intel API | api.piranha.bawbel.io |
| Site repo | github.com/bawbel/ave-site |
| Release | v1.0.0 tagged |

---

## Standards alignment

| Standard | Field | Status |
|---|---|---|
| OWASP AIVSS v0.8 | `aivss` object | required in every record |
| OWASP MCP Top 10 | `owasp_mcp` | required, MCP01–MCP10 |
| OWASP Agentic AI Top 10 | `owasp_mapping` | optional, ASI01–ASI10 |
| MITRE ATLAS | `mitre_atlas_mapping` | optional, AML.Txxxx |
| NIST AI RMF | `nist_ai_rmf_mapping` | optional |
| OWASP AIBOM | planned via `bawbel abom` CycloneDX command | future |

---

## Relationship to OSV.dev

Complementary, not competing. OSV answers "does this package version have
a known CVE?" AVE answers "does this agent component behave dangerously?"
A full scan runs both: OSV for dependencies, AVE for agent components.
AVE originates net-new vulnerability classes; OSV aggregates existing ones.

Do not frame AVE as "OSV for AI agents" — OSV is an aggregator. AVE
originates. Different problem, different mechanism.

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
   and CI for free
3. Open data dump — full record set downloadable as one JSON file
4. OWASP project proposal — neutral governance kills the lock-in objection
5. Second implementer — a non-Bawbel tool emitting or mapping AVE ids

---

## Roadmap

**v1.1 (next)**
- Migrate all 48 records from schema 0.2.0 → 1.0.0 (one-line batch script)
- Backfill evidence declaration fields on 5 priority records:
  00001, 00002, 00042, 00045, 00048
- Publish crosswalk files: skillspector-to-ave.json, clawscan-to-ave.json,
  ave-to-frameworks.md
- AVE-in-SARIF convention: docs/specs/ave-in-sarif.md
- First research-new-attack-classes benchmark report
- OWASP project proposal: docs/governance/owasp-proposal.md
- New records: header injection (BadHost), parasitic toolchain,
  OAuth discovery rebinding (CVE-2025-6514 class)

**Trust-building (parallel)**
- CVE-vs-AVE showdown post on one real MCP CVE (dev.to, seeds Reddit threads)
- 10 technical write-ups before Product Hunt
- Priority records for content: 00042 (rug-pull), 00045 (cross-app),
  00048 (unsafe delegation), 00002 (tool description injection),
  00001 (external instruction fetch)

**Later**
- OWASP AIBOM integration via `bawbel abom` CycloneDX command
- Advisory board (only when real reviewers exist — not decoration)
- Second implementer outreach (after OWASP governance, not before)

---

## Record count discipline

Target: ~60–65 high-quality records by Product Hunt, reached deliberately.
Do not push to 100. Research shows ~25–35 genuinely distinct behavioral
classes exist (MCPSecBench 17, Formal Security Framework 23, Hou et al 16,
MCP-SafetyBench 20, MCPTox 11 — heavy overlap). At 48 records we are likely
past the count of distinct classes already.

Growth path: audit and merge variants, fill genuine gaps from the
research-new-attack-classes skill. Record count = distinct behavioral
classes, no padding.

---

## How to work on AVE

See CLAUDE.md for session rules and the current task queue.
See HOW-TO-USE.md for the session start/end sequence.
See ARCHITECTURE.md for the record/rule/fixture model.
See CONTRIBUTING.md for the contributor-facing process.