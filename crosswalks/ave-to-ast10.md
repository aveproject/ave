# AVE → OWASP AST10 crosswalk

**Source:** AVE v1.0.0 — 48 records
**Target:** OWASP Agentic Skills Top 10 (AST10) — incubated at OWASP Project Summit, Oslo 2026
**Target lead:** Ken Huang (also OWASP AIVSS lead)
**Verified against live AST10 site:** 2026-06-19

This crosswalk maps AVE's 48 behavioral vulnerability records to the 10 risk categories
in OWASP's AST10. It is offered as a basis for collaboration — AVE is not a competing
taxonomy. AST10 documents risk at the principle level, each with a Critical/High/Medium
severity rating; AVE adds individual behavioral classes with AIVSS v0.8 scores, detection
layers, and indicators of compromise underneath each principle.

> **Revision note:** AST05 was retitled from "Prompt Injection" to "Unsafe Deserialization"
> between drafting and verification. Prompt-injection-as-mechanism is now distributed across
> AST01 ("prose instructions that hijack the agent") and AST03 ("weaponisable by prompt
> injection"). This version reflects the corrected, current structure.

---

## Mapping

| AST | Title | Severity | AVE record count | AVE ids |
|---|---|---|---|---|
| AST01 | Malicious Skills | Critical | 9 | AVE-2026-00004, AVE-2026-00005, AVE-2026-00006, AVE-2026-00007, AVE-2026-00008, AVE-2026-00009, AVE-2026-00010, AVE-2026-00032, AVE-2026-00047 |
| AST02 | Supply Chain Compromise | Critical | 4 | AVE-2026-00001, AVE-2026-00017, AVE-2026-00024, AVE-2026-00034 |
| AST03 | Over-Privileged Skills | High | 9 | AVE-2026-00012, AVE-2026-00016, AVE-2026-00020, AVE-2026-00021, AVE-2026-00022, AVE-2026-00038, AVE-2026-00044, AVE-2026-00045, AVE-2026-00048 |
| AST04 | Insecure Metadata | High | 3 | AVE-2026-00002, AVE-2026-00029, AVE-2026-00041 |
| AST05 | Unsafe Deserialization | High | 2 | AVE-2026-00033, AVE-2026-00042 |
| AST06 | Weak Isolation | High | 2 | AVE-2026-00036, AVE-2026-00046 |
| AST07 | Update Drift | Medium | 1 | AVE-2026-00001 |
| AST08 | Poor Scanning | Medium | 0 | — (not an AVE behavioral class) |
| AST09 | No Governance | Medium | 3 | AVE-2026-00019, AVE-2026-00027, AVE-2026-00031 |
| AST10 | Cross-Platform Reuse | Medium | 0 | — (not an AVE behavioral class) |

---

## Where AVE adds the most granularity

**AST01 — Malicious Skills** and **AST03 — Over-Privileged Skills** each map to 9 distinct
AVE records — the two largest mappings, and together they account for over half of the
8 mapped categories.

AST01 spans both code-level malice (shell injection, destructive commands, crypto drain,
credential theft) and prose-level malice (goal hijack, jailbreak, hidden instructions) —
AVE provides a separately scored, separately fingerprinted record for each rather than one
umbrella category.

AST03's own description identifies prompt injection as the exploit mechanism for excess
access. AVE-2026-00016 (RAG injection), AVE-2026-00020 (A2A injection), and AVE-2026-00044
(async task poisoning) are each a distinct injection technique that specifically exploits
over-broad access — distinguishable from AST01's direct-hijack records by what capability
they abuse, not just how the injection is delivered.

**AST05 — Unsafe Deserialization**, under its corrected definition, maps to only 2 AVE
records: AVE-2026-00033 (the exact match — unsafe eval/deserialization) and AVE-2026-00042
(a runtime variant via REPL code-mode payload injection, worth confirming scope on).

---

## What AVE has that AST10 does not yet have

| Topic | AVE record | Why it matters |
|---|---|---|
| MCP server-card injection | AVE-2026-00041 | AST04 covers metadata mismatch generally; AVE-2026-00041 isolates the specific case of injection via the .well-known/mcp.json server-card, which fires before any tool call and is invisible to runtime monitoring. |
| Cross-App-Access escalation | AVE-2026-00045 | AST03 covers over-privileged access generally; AVE-2026-00045 isolates the MCP-2026 multi-server-session confused-deputy pattern specifically, a protocol-level capability AST03 predates. |
| Tool hook hijacking | AVE-2026-00046 | AST06 covers weak isolation generally; AVE-2026-00046 isolates interception/redirection of tool execution via a registered hook. This is AVE's only CRITICAL-severity record. |
| AIVSS v0.8 quantitative scoring | all 48 records | AST10 risks carry a qualitative severity label (Critical/High/Medium) per category. Every AVE record carries a full AIVSS v0.8 score (cvss_base, AARF ten-factor breakdown, aars, thm, mitigation_factor) at the individual-class level — a finer-grained quantitative layer AST10 does not currently have per-record. |

---

## What AST10 has that AVE does not yet have

| AST | Why |
|---|---|
| AST07 | No AVE record for update drift via direct version republish on a registry, as opposed to drift via external runtime fetch (AVE-2026-00001 covers only the latter). |
| AST10 | No dedicated AVE record class for cross-platform metadata loss during skill porting; affected_platforms field provides supporting data only. |

---

## Coverage summary

| | |
|---|---|
| AST categories with an AVE mapping | 8 of 10 |
| AVE records referenced | 32 of 48 |
| AVE records unmapped to AST10 | 16 |

The 16 unmapped AVE records are mostly data-exfiltration, information-disclosure, and standalone prompt-injection classes (PII theft, covert channels, credential theft via instruction, system prompt leak, vision injection, MCP App UI injection) that sit closer to OWASP LLM Top 10 / Agentic AI Top 10 territory, or that AST10's current 10 categories do not yet have a dedicated slot for.

---

*Machine-readable version: [ave-to-ast10.json](ave-to-ast10.json)*