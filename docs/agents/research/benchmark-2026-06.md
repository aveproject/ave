# Research-New-Attack-Classes Benchmark Report — 2026-06

**Date:** 2026-06-21
**Scope:** Current 48-record AVE set (schema v1.0.0)
**Method:** Map published external research datasets against existing AVE records, identify genuine gaps, recommend new record candidates that meet AVE's bar (distinct behavioral class + citable primary source)

---

## Datasets reviewed

| Dataset | Classes enumerated | Publication / source |
|---|---|---|
| MCPSecBench | 17 | Benchmark suite for evaluating MCP server security (2025) |
| Formal Security Framework for MCP | 23 | Academic threat model for the MCP protocol (2025) |
| Hou et al. 2025 | 16 | "Security Risks of MCP: A Taxonomy and Empirical Study" |
| MCP-SafetyBench | 20 | Safety benchmark for MCP-connected agents (2025) |
| MCPTox | 11 | Toxicity-focused evaluation for MCP tools (2025) |
| OpenClaw study | overlap analysis | Scanner concordance study across SkillSpector, ClawScan, and one unnamed scanner |

---

## Dataset 1 — MCPSecBench (17 classes)

MCPSecBench defines 17 attack classes against MCP servers evaluated as automated test cases.

| MCPSecBench class | AVE coverage | AVE record(s) | Gap type |
|---|---|---|---|
| Tool Poisoning | Full | AVE-2026-00002, AVE-2026-00041 | — |
| Prompt Injection | Full | AVE-2026-00007, AVE-2026-00010, AVE-2026-00016 | — |
| Credential Theft | Full | AVE-2026-00003, AVE-2026-00047 | — |
| Remote Code Execution | Full | AVE-2026-00004, AVE-2026-00033 | — |
| Privilege Escalation | Full | AVE-2026-00012, AVE-2026-00022, AVE-2026-00030, AVE-2026-00048 | — |
| Data Exfiltration | Full | AVE-2026-00003, AVE-2026-00013, AVE-2026-00026, AVE-2026-00039 | — |
| Server Impersonation | Full | AVE-2026-00017 | — |
| Cross-Server Contamination | Full | AVE-2026-00020, AVE-2026-00036 | — |
| Memory Manipulation | Full | AVE-2026-00019, AVE-2026-00027 | — |
| Tool Interception | Full | AVE-2026-00046 | — |
| Unauthorized Tool Registration | Planned | — | AVE-2026-00050 (parasitic toolchain) planned for v1.1 |
| Parameter Injection | Full | AVE-2026-00011 | — |
| Resource Exhaustion | **None** | — | **Genuine gap** |
| Authentication Bypass | Full | AVE-2026-00030 | — |
| Output Manipulation | Full | AVE-2026-00018, AVE-2026-00040 | — |
| Lateral Movement | Full | AVE-2026-00036 | — |
| Rug Pull / External Fetch | Full | AVE-2026-00001 | — |

MCPSecBench coverage: **15/17 full, 1 planned, 1 gap** (resource exhaustion).

---

## Dataset 2 — Formal Security Framework for MCP (23 classes)

Academic formal model treating the MCP protocol surface as a security boundary.

| FSF-MCP class | AVE coverage | AVE record(s) | Gap type |
|---|---|---|---|
| Tool Description Poisoning | Full | AVE-2026-00002, AVE-2026-00041 | — |
| External Instruction Fetch | Full | AVE-2026-00001 | — |
| Cross-Session State Leakage | **None** | — | **See analysis below** |
| Access Control Bypass | Full | AVE-2026-00030 | — |
| Multi-Agent Propagation | Full | AVE-2026-00020, AVE-2026-00036 | — |
| Persistent Memory Injection | Full | AVE-2026-00019, AVE-2026-00027 | — |
| Capability Escalation | Full | AVE-2026-00012, AVE-2026-00022, AVE-2026-00048 | — |
| Tool Chain Hijacking | Full | AVE-2026-00046 | — |
| Data Leakage | Full | AVE-2026-00003, AVE-2026-00013 | — |
| Covert Channel | Full | AVE-2026-00039 | — |
| OAuth Flow Manipulation | Planned | — | AVE-2026-00051 planned for v1.1 |
| Header Injection | Planned | — | AVE-2026-00049 planned for v1.1 |
| Session Hijacking (token theft) | Partial | AVE-2026-00047 | Credential-focused; token replay distinct |
| UI Injection | Full | AVE-2026-00043 | — |
| Deserialization Attack | Full | AVE-2026-00033 | — |
| Dynamic Plugin Loading | Full | AVE-2026-00034 | — |
| RLHF / Feedback Poisoning | Full | AVE-2026-00031 | — |
| Sensor Data Manipulation | Full | AVE-2026-00035 | — |
| Context Window Flooding | Full | AVE-2026-00023 | — |
| File Content Injection | Full | AVE-2026-00028 | — |
| Vision / Multimodal Injection | Full | AVE-2026-00037 | — |
| Jailbreak | Full | AVE-2026-00009 | — |
| Parasitic Tool Registration | Planned | — | AVE-2026-00050 planned for v1.1 |

FSF-MCP coverage: **19/23 full, 2 planned, 1 partial (session hijacking), 1 gap** (cross-session state leakage — see analysis).

**Cross-session state leakage analysis:** FSF-MCP defines this as a shared MCP server leaking one user's session data (context, credentials, history) to a different user's session due to insufficient session isolation at the server implementation layer. AVE-2026-00019 (memory poisoning) is deliberate injection; this is inadvertent multi-tenant leakage. However, this class manifests as a **server implementation defect** (missing session scope enforcement), not as a behavioral pattern detectable in a skill file or tool description. AVE scope is agentic component behavior, not server runtime isolation bugs — which fall under conventional web application vulnerabilities (CWE-362, CWE-200). **Verdict: out of AVE scope; appropriate for CVE/CWE.**

---

## Dataset 3 — Hou et al. 2025 (16 classes)

Hou et al. "Security Risks of MCP: A Taxonomy and Empirical Study" categorizes risks observed across real MCP server deployments.

| Hou et al. class | AVE coverage | AVE record(s) | Gap type |
|---|---|---|---|
| Tool Poisoning | Full | AVE-2026-00002, AVE-2026-00041 | — |
| Rug Pull / External Fetch | Full | AVE-2026-00001 | — |
| Credential Exfiltration | Full | AVE-2026-00003, AVE-2026-00047 | — |
| Permission Escalation | Full | AVE-2026-00012, AVE-2026-00022 | — |
| Memory Poisoning | Full | AVE-2026-00019 | — |
| Cross-Agent Injection | Full | AVE-2026-00020 | — |
| Jailbreak | Full | AVE-2026-00009 | — |
| Hidden Instructions | Full | AVE-2026-00010 | — |
| Output Encoding Exfiltration | Full | AVE-2026-00026 | — |
| Goal Hijacking | Full | AVE-2026-00007 | — |
| Scope Expansion | Full | AVE-2026-00022, AVE-2026-00038 | — |
| History Fabrication | Full | AVE-2026-00025 | — |
| Server Impersonation | Full | AVE-2026-00017 | — |
| Self-Replication / Persistence | Full | AVE-2026-00008 | — |
| Dynamic Import | Full | AVE-2026-00034 | — |
| Cross-App Escalation | Full | AVE-2026-00045 | — |

Hou et al. coverage: **16/16 full**. Complete coverage.

---

## Dataset 4 — MCP-SafetyBench (20 classes)

Safety-focused benchmark evaluating 20 attack categories against MCP-connected agent systems.

| MCP-SafetyBench class | AVE coverage | AVE record(s) | Gap type |
|---|---|---|---|
| Prompt Injection | Full | AVE-2026-00002, 00007, 00010, 00016, 00020, 00021, 00023, 00025, 00027, 00028, 00037, 00041, 00043, 00044 | — |
| Data Exfiltration | Full | AVE-2026-00003, 00013, 00026, 00039 | — |
| Code Injection | Full | AVE-2026-00004, AVE-2026-00033 | — |
| Privilege Escalation | Full | AVE-2026-00012, 00022, 00030, 00045, 00048 | — |
| Authentication Bypass | Full | AVE-2026-00030 | — |
| Denial of Service (resource exhaustion) | **None** | — | **Genuine gap** |
| Tool Misuse | Full | AVE-2026-00005, 00006, 00011, 00018, 00038 | — |
| Information Disclosure | Full | AVE-2026-00015 | — |
| Memory Manipulation | Full | AVE-2026-00019, AVE-2026-00027 | — |
| Cross-Agent Contamination | Full | AVE-2026-00020, AVE-2026-00036 | — |
| Supply Chain | Full | AVE-2026-00001, 00017, 00024, 00034 | — |
| Output Manipulation | Full | AVE-2026-00018, AVE-2026-00040 | — |
| Social Engineering | Full | AVE-2026-00014 | — |
| Jailbreak | Full | AVE-2026-00009 | — |
| Covert Channel | Full | AVE-2026-00039 | — |
| Lateral Movement | Full | AVE-2026-00036 | — |
| UI Injection | Full | AVE-2026-00043 | — |
| File Content Injection | Full | AVE-2026-00028 | — |
| Vision / Multimodal Injection | Full | AVE-2026-00037 | — |
| Credential Theft | Full | AVE-2026-00003, AVE-2026-00047 | — |

MCP-SafetyBench coverage: **19/20 full, 1 gap** (denial of service / resource exhaustion).

---

## Dataset 5 — MCPTox (11 classes)

MCPTox focuses on toxicity and content-safety violations produced via MCP tool abuse.

| MCPTox class | AVE coverage | Notes |
|---|---|---|
| Toxic Content Generation | Out of scope | Content safety violation, not agentic behavioral attack. AVE covers the delivery mechanism, not the harmful output category. |
| Harmful Instruction Following | Partial | AVE-2026-00007 covers the goal-hijack injection that causes this; the class itself is a content outcome. |
| Bias Amplification | Out of scope | Model alignment issue, not agentic behavioral attack pattern. |
| Misinformation Propagation | Partial | AVE-2026-00035 (sensor data poisoning) and AVE-2026-00018 (result manipulation) cover specific mechanisms; the class is broader. |
| Privacy Violation | Full | AVE-2026-00013 (PII theft), AVE-2026-00003 (credential theft) |
| Discrimination | Out of scope | Model alignment issue. |
| Violence Promotion | Out of scope | Content safety issue. |
| Self-Harm Facilitation | Out of scope | Content safety issue. |
| Illegal Activity Facilitation | Partial | Multiple AVE records cover the delivery mechanisms (injection, exfiltration, escalation); the class is an outcome category. |
| Deception | Full | AVE-2026-00014 (trust escalation), AVE-2026-00017 (server impersonation), AVE-2026-00025 (history fabrication) |
| Manipulation | Full | AVE-2026-00018 (result manipulation), AVE-2026-00019 (memory poisoning), AVE-2026-00031 (feedback poisoning) |

MCPTox coverage: **3/11 full, 3 partial, 5 out of scope.** MCPTox largely addresses model alignment and content safety — a different problem domain from AVE's behavioral attack surface. No new AVE records are warranted from MCPTox. AVE covers the injection and exfiltration mechanisms that enable harmful outputs; the outputs themselves are content-safety territory.

---

## Dataset 6 — OpenClaw study (overlap analysis)

The OpenClaw study measured concordance among three commercial skill-file scanners — SkillSpector (NVIDIA), ClawScan (community), and one unnamed — across a corpus of real-world MCP skill files.

Key findings:
- **Pairwise overlap < 10.4%** — no two scanners agree on more than ~1 in 10 flagged skills
- **All-three agreement: 0.69%** — fewer than 1 in 140 flagged skills is flagged by all three tools
- No shared finding vocabulary; each scanner uses proprietary class names

This study does not enumerate attack classes and contributes no new gap candidates. It does confirm the adoption argument for AVE: the field urgently needs a shared reference vocabulary. The 10.4% concordance ceiling is what AVE exists to solve.

---

## Consolidated gap analysis

| Class | Source(s) | Closest AVE record | Gap type |
|---|---|---|---|
| Resource Exhaustion / Agentic DoS | MCPSecBench, MCP-SafetyBench | AVE-2026-00023 (context flooding — different mechanism) | **Genuine gap** |
| Parasitic Tool Registration | MCPSecBench, FSF-MCP | — | Planned → AVE-2026-00050 |
| OAuth Discovery Rebinding | FSF-MCP | — | Planned → AVE-2026-00051 |
| Header Injection (BadHost) | FSF-MCP | — | Planned → AVE-2026-00049 |
| Cross-Session State Leakage | FSF-MCP | AVE-2026-00019 (different mechanism) | Out of AVE scope (server implementation defect) |
| Toxic content / harmful output categories | MCPTox | Multiple (delivery mechanisms only) | Out of AVE scope (content safety domain) |

---

## New record candidates

### Candidate 1 — Agentic Resource Exhaustion (recommended)

**attack_class:** `resource_exhaustion_agentic_loop`

**Behavioral class:** A skill or MCP tool triggers unbounded resource consumption in the agent runtime — recursive tool-call loops, excessive parallel sub-agent spawning, or intentionally large output generation — causing denial of availability to the agent, the user, or downstream systems.

**Why it is distinct from existing records:**
- AVE-2026-00023 (context window manipulation) uses content padding to displace instructions from context — the goal is injection, not availability disruption
- AVE-2026-00038 (unbounded tool use) describes tools that invoke any available tool without limits — the goal is privilege, not exhaustion
- This candidate is the first class where **availability denial is the primary goal**, not a side effect

**Primary source:** MCPSecBench class 13 "Resource Exhaustion"; MCP-SafetyBench class 6 "Denial of Service". Both independently enumerate this as a distinct class with concrete test cases.

**Suggested severity:** HIGH
**Suggested owasp_mcp:** ["MCP06", "MCP08"]
**Suggested mitre_atlas_mapping:** ["AML.T0029"]
**Suggested detection_layer:** runtime
**Suggested detection_stage:** runtime_observed

**Recommendation:** Add as **AVE-2026-00052** after the three planned v1.1 records (00049–00051). Requires a runtime-observed rule (pattern rule can detect IOCs like explicit loop constructs or `while True` + tool-call patterns in skill files; runtime rule confirms execution behavior).

---

### Classes not recommended

The following classes appeared in at least one dataset but do not meet AVE's bar for a new record:

| Class | Source | Reason not recommended |
|---|---|---|
| Cross-session state leakage | FSF-MCP | Server implementation defect, not detectable behavioral pattern in skill/tool content. Belongs in CVE/CWE. |
| Token replay / session hijacking | FSF-MCP (partial) | Variant of credential theft (AVE-2026-00047) and auth bypass (AVE-2026-00030). Not behaviorally distinct enough. |
| Bias amplification | MCPTox | Model alignment issue, not agentic behavioral attack class. Out of AVE scope. |
| All MCPTox content-safety classes | MCPTox | AVE covers delivery mechanisms; toxic output categories are content-safety domain, not behavioral vulnerability enumeration. |
| Illegal activity facilitation | MCPTox | Outcome category, not a distinct behavioral class. Covered by constituent delivery mechanisms already in AVE. |

---

## Coverage summary

| Dataset | Classes | Full | Planned | Partial | Gap | Out of scope |
|---|---|---|---|---|---|---|
| MCPSecBench | 17 | 15 | 1 | 0 | 1 | 0 |
| FSF-MCP | 23 | 19 | 2 | 1 | 0 | 1 |
| Hou et al. 2025 | 16 | 16 | 0 | 0 | 0 | 0 |
| MCP-SafetyBench | 20 | 19 | 0 | 0 | 1 | 0 |
| MCPTox | 11 | 3 | 0 | 3 | 0 | 5 |

**Genuine gaps across all datasets:** 1 (resource exhaustion / agentic DoS — present in both MCPSecBench and MCP-SafetyBench)

---

## Recommended target count

**Current:** 48 records published
**Planned for v1.1:** +3 (00049 header injection, 00050 parasitic toolchain, 00051 OAuth rebinding) → **51**
**Recommended from this benchmark:** +1 (00052 resource exhaustion) → **52**

PRODUCT.md sets the target at ~60–65 high-quality records by Product Hunt, reached deliberately. Research across all five datasets finds roughly 25–35 genuinely distinct behavioral classes; at 48 records AVE has already exceeded the distinct-class count of any single dataset. The overlap between datasets confirms the same ~20 core classes appear everywhere; the remaining records in AVE cover real but rarer variants.

**Do not add records to close the count gap.** The one genuine gap found (resource exhaustion) warrants a new record. Every other candidate is either a variant of an existing record, a server implementation defect outside AVE scope, or a content-safety class in a different problem domain.

The three planned records (header injection, parasitic toolchain, OAuth rebinding) already account for the most-cited missing classes. Adding AVE-2026-00052 (resource exhaustion) would close the only true behavioral gap found in this benchmark.

**Next benchmark:** Schedule for 2026-09 or when a new dataset is published with >10 classes not previously mapped.
