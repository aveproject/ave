# AVE → OWASP AST10 crosswalk

**Source:** AVE v1.0.0 — 51 records
**Target:** OWASP Agentic Skills Top 10 (AST10) — incubated at OWASP Project Summit, Oslo 2026
**Target lead:** Ken Huang (also OWASP AIVSS lead)
**Verified against live AST10 site:** 2026-06-21

This crosswalk maps AVE's 51 behavioral vulnerability records to the 10 risk categories
in OWASP's AST10. It is offered as a basis for collaboration — AVE is not a competing
taxonomy. AST10 documents risk at the principle level, each with a Critical/High/Medium
severity rating; AVE adds individual behavioral classes with AIVSS v0.8 scores, detection
layers, and indicators of compromise underneath each principle.

> **Revision history**
> - AST05 was retitled from "Prompt Injection" to "Unsafe Deserialization" between drafting
> and verification. Prompt-injection-as-mechanism is distributed across AST01 ("prose
> instructions that hijack the agent") and AST03 ("weaponisable by prompt injection").
> - 2026-06-21: updated for the 51-record set. The v1.1 migration added three records —
> AVE-2026-00049 (HTTP Host Header Injection / BadHost), AVE-2026-00050 (Parasitic
> Toolchain), and AVE-2026-00051 (OAuth Discovery Rebinding) — each placed below with
> reasoning, not by default.

---

## Mapping

| AST | Title | Severity | AVE record count | AVE ids |
|---|---|---|---|---|
| AST01 | Malicious Skills | Critical | 10 | AVE-2026-00004, AVE-2026-00005, AVE-2026-00006, AVE-2026-00007, AVE-2026-00008, AVE-2026-00009, AVE-2026-00010, AVE-2026-00032, AVE-2026-00047, AVE-2026-00049 |
| AST02 | Supply Chain Compromise | Critical | 4 | AVE-2026-00001, AVE-2026-00017, AVE-2026-00024, AVE-2026-00034 |
| AST03 | Over-Privileged Skills | High | 9 | AVE-2026-00012, AVE-2026-00016, AVE-2026-00020, AVE-2026-00021, AVE-2026-00022, AVE-2026-00038, AVE-2026-00044, AVE-2026-00045, AVE-2026-00048 |
| AST04 | Insecure Metadata | High | 4 | AVE-2026-00002, AVE-2026-00029, AVE-2026-00041, AVE-2026-00051 |
| AST05 | Unsafe Deserialization | High | 2 | AVE-2026-00033, AVE-2026-00042 |
| AST06 | Weak Isolation | High | 3 | AVE-2026-00036, AVE-2026-00046, AVE-2026-00050 |
| AST07 | Update Drift | Medium | 1 | AVE-2026-00001 |
| AST08 | Poor Scanning | Medium | 0 | — (not an AVE behavioral class) |
| AST09 | No Governance | Medium | 3 | AVE-2026-00019, AVE-2026-00027, AVE-2026-00031 |
| AST10 | Cross-Platform Reuse | Medium | 0 | — (not an AVE behavioral class) |

---

## The 3 new records — where they landed and why

### AVE-2026-00049 — HTTP Host Header Injection (BadHost) → AST01

A component manipulates outbound request headers (Host, X-Forwarded-Host, X-Original-URL)
to redirect agent-initiated traffic — and any credentials it carries — to an attacker server.
This is not a metadata-declaration problem; it is code behavior tampering with request
construction. AST01's framing — "skills that look legitimate but hide credential
stealers" — is the closer fit than AST04's metadata-validation framing, since the
vulnerable surface is the request itself, not a declared field. Secondary relevance to
AST06 (Weak Isolation): nothing constrains a component's ability to construct arbitrary
outbound headers.

### AVE-2026-00050 — Parasitic Toolchain → AST06

This record explicitly extends AVE-2026-00046 (Tool Hook Hijacking, already mapped to
AST06). The record's own description distinguishes the two by registration mechanism —
local runtime registration vs. an external callback URL — but both share the same root
cause: the agent's tool dispatch layer has no boundary preventing a component from
registering capabilities beyond its declared manifest. `detection_layer: runtime` and
`detection_stage: runtime_observed` match AST06's "no sandbox, full security context"
framing precisely.

### AVE-2026-00051 — OAuth Discovery Rebinding → AST04

`detection_layer: registry_metadata` is the deciding signal here. The vulnerability is in
the server's own OAuth discovery document (`authorization_endpoint`, `token_endpoint`,
`jwks_uri`) — metadata the agent fetches and trusts before any credential exchange. This
is the cleanest match to AST04's "unvalidated, unsigned metadata" framing of the three
new records.

---

## Where AVE adds the most granularity

**AST01 — Malicious Skills** now maps to 10 distinct AVE records, the largest single
mapping. It spans code-level malice (shell injection, destructive commands, crypto drain,
credential theft, header injection) and prose-level malice (goal hijack, jailbreak, hidden
instructions) — AVE provides a separately scored, separately fingerprinted record for each
rather than one umbrella category.

**AST03 — Over-Privileged Skills** maps to 9 records. AST03's own description identifies
prompt injection as the exploit mechanism for excess access — AVE-2026-00016 (RAG
injection), AVE-2026-00020 (A2A injection), and AVE-2026-00044 (async task poisoning) are
each a distinct injection technique that specifically exploits over-broad access.

**AST06 — Weak Isolation** now maps to 3 records including AVE's only CRITICAL-severity
record (AVE-2026-00046, AIVSS 9.2).

**AST05 — Unsafe Deserialization**, under its corrected definition, maps to only 2 AVE
records — a narrow, exact-fit category rather than a catch-all.

---

## What AVE has that AST10 does not yet have

| Topic | AVE record | Why it matters |
|---|---|---|
| MCP server-card injection | AVE-2026-00041 | AST04 covers metadata mismatch generally; AVE-2026-00041 isolates the specific case of injection via the .well-known/mcp.json server-card, which fires before any tool call and is invisible to runtime monitoring. |
| Cross-App-Access escalation | AVE-2026-00045 | AST03 covers over-privileged access generally; AVE-2026-00045 isolates the MCP-2026 multi-server-session confused-deputy pattern specifically, a protocol-level capability AST03 predates. |
| Tool hook hijacking | AVE-2026-00046 | AST06 covers weak isolation generally; AVE-2026-00046 isolates interception/redirection of tool execution via a registered hook. This is AVE's only CRITICAL-severity record. |
| HTTP Host header injection (BadHost) | AVE-2026-00049 | No AST category specifically names header-level request tampering as a distinct mechanism. AST01's general 'hidden capability' framing covers it but doesn't name the transport-layer vector. |
| Parasitic toolchain / silent tool registration | AVE-2026-00050 | AST06 covers the general isolation failure; AVE-2026-00050 isolates the specific mechanism of runtime tool registration outside the declared manifest, distinct from AVE-2026-00046's external-callback hijacking. |
| OAuth discovery rebinding | AVE-2026-00051 | AST04 covers metadata validation generally; AVE-2026-00051 isolates the specific RFC 8414 / OIDC discovery document poisoning pattern, which is protocol-specific and not named in AST04's description. |
| AIVSS v0.8 quantitative scoring | all 51 records | AST10 risks carry a qualitative severity label (Critical/High/Medium) per category. Every AVE record carries a full AIVSS v0.8 score (cvss_base, AARF ten-factor breakdown, aars, thm, mitigation_factor) at the individual-class level -- a finer-grained quantitative layer AST10 does not currently have per-record. |

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
| AVE records referenced | 35 of 51 |
| AVE records unmapped to AST10 | 16 |

The 16 unmapped AVE records are mostly data-exfiltration, information-disclosure, and standalone prompt-injection classes (PII theft, covert channels, credential theft via instruction, system prompt leak, vision injection, MCP App UI injection) that sit closer to OWASP LLM Top 10 / Agentic AI Top 10 territory, or that AST10's current 10 categories do not yet have a dedicated slot for.

---

*Machine-readable version: [ave-to-ast10.json](ave-to-ast10.json)*