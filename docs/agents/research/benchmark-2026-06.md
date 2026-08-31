# Research-New-Attack-Classes Benchmark Report — 2026-06

**Date:** 2026-06-21
**Scope:** Current 48-record AVE set (schema v1.0.0)
**Method:** Map published external research datasets against existing AVE records, identify genuine gaps, recommend new record candidates that meet AVE's bar (distinct behavioral class + citable primary source)

---

## Citation audit (2026-08-31)

**Every claim in this document that names an external source's specific class,
category, title, or coverage number was independently checked against that
source's actual, current primary text.** Triggered by issue #241, which found
two of this file's citations (MCPSecBench class 13, MCP-SafetyBench class 6)
did not exist. Two wrong was treated as a sample, not the finding, so the
full file was audited rather than patching those two lines.

**Result: 102 checkable claims, 30 confirmed correct, 72 confirmed wrong, 0
unverifiable.** Every cited paper is real and exists. The dataset-level facts
(class *counts*, mostly) are largely accurate. The specific per-class names
this document attributes to each dataset are wrong in the large majority of
cases, for four of five numbered datasets and the entirety of the fifth
(MCPTox), which this file misdescribes at the level of the paper's actual
subject: the real MCPTox benchmark is about tool-poisoning attack detection,
not content toxicity or safety-alignment categories, and none of the 11
categories listed for it below are attested anywhere in the real paper.

Because the "AVE coverage" analysis for each dataset was performed against
these largely fabricated class lists, that analysis cannot be trusted either.
**All per-dataset coverage tables below are marked retracted.** They are kept,
not deleted, so the original claims stay visible and checkable, following
this project's own standing practice of publishing negative results rather
than quietly editing them away. Each dataset section below is replaced with:
the paper's real identity (verified), its real published taxonomy (verified,
where obtainable), and an explicit statement that AVE's coverage against that
real taxonomy has **not** been re-derived — that is a fresh research task,
not something this citation audit did or could respectably improvise.

**One consequence worth stating plainly, not softened:** the "genuine gap"
this document's own conclusion rested on — resource exhaustion / agentic
DoS — does not exist in either cited source. That item was already dropped
from the roadmap in issue #241 before this audit ran; this file's own
recommendation section is corrected to match below rather than left standing
alongside the correction.

Everything in the sections below that predates this audit note is kept as
originally written except where an inline `[AUDITED 2026-08-31: ...]` marker
says otherwise. Do not treat an unmarked claim elsewhere in this file (e.g.
prose framing, methodology description) as verified by this pass; only the
specific citation claims covered by the audit tables were checked.

---

## Datasets reviewed

| Dataset | Classes enumerated | Publication / source | Audit status |
|---|---|---|---|
| MCPSecBench | 17 (verified) | arXiv:2508.13220 — "MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols" | 4/17 class names confirmed correct |
| "Formal Security Framework for MCP" | 23 (verified) | arXiv:2604.05969 — "A Formal Security Framework for MCP-Based AI Agents" (MCPSHIELD) | 5/23 class names confirmed correct |
| Hou et al. 2025 | 16 (verified) | arXiv:2503.23278 — **[AUDITED: title as originally cited here, "Security Risks of MCP: A Taxonomy and Empirical Study," is wrong. The real title is "Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions," Hou, Zhao, Wang, Wang, 2025.]** | 5/16 class names confirmed correct |
| MCP-SafetyBench | 20 (verified) | arXiv:2512.15163 — "MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models with Real-World MCP Servers" (published ICLR 2026) — **[AUDITED: originally dated "(2025)" here; the paper is ICLR 2026, arXiv submission March 2026.]** | 5/20 class names confirmed correct |
| MCPTox | 11 (per the paper's own introduction; its abstract says 10 — a real inconsistency in the source, not this document's error) | arXiv:2508.14925 — "MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers" | **[AUDITED: the description below, "toxicity-focused evaluation," is wrong. The real paper is entirely about Tool Poisoning Attacks — malicious instructions embedded in a tool's own metadata, evaluated against 45 real MCP servers and 353 real tools. It has no content-safety, bias, or toxicity dimension. None of the 11 class names listed in this file's original table are attested in the real paper.]** |
| OpenClaw study (ClawHub Security Signals) | overlap analysis | arXiv:2606.01494 — "ClawHub Security Signals: When VirusTotal, Static Analysis, and SkillSpector Disagree" | Numeric claims confirmed correct; scanner identification corrected below |

---

## Dataset 1 — MCPSecBench (17 classes)

MCPSecBench defines 17 attack types against MCP, evaluated across four
attack surfaces (client, protocol, server, host).

**[AUDITED 2026-08-31] The table originally here claimed 17 "MCPSecBench
classes," of which 4 match the real paper's own Table 1 taxonomy: Tool
Poisoning, Prompt Injection, Data Exfiltration, and Rug Pull Attack. The
other 13 rows — Credential Theft, Remote Code Execution, Privilege
Escalation, Server Impersonation, Cross-Server Contamination, Memory
Manipulation, Tool Interception, Unauthorized Tool Registration, Parameter
Injection, Resource Exhaustion, Authentication Bypass, Output Manipulation,
Lateral Movement — do not correspond to any class in the real paper. The
"AVE coverage" claims attached to those 13 rows in the original table are
retracted along with them; they described AVE's relationship to classes that
were never real.**

MCPSecBench's real 17 attack types (verbatim from the paper's own Table 1
footnote, arXiv:2508.13220): Prompt Injection, Tool/Service Misuse via
"Confused AI," Schema Inconsistencies, Slash Command Overlap, MCP Rebinding,
Man-in-the-Middle, Tool Shadowing Attack, Data Exfiltration, Package Name
Squatting (tool name), Indirect Prompt Injection, Package Name Squatting
(server name), Tool Poisoning, Rug Pull Attack, Vulnerable Client,
Configuration Drift, Sandbox Escape, Vulnerable Server.

**AVE coverage against this real list has not been re-derived in this
audit.** That is a fresh mechanism-level comparison task, not a citation
check, and doing it casually here would risk repeating the exact failure
this audit exists to correct. `[RETRACTED, ORIGINAL] MCPSecBench coverage:
15/17 full, 1 planned, 1 gap (resource exhaustion).` — the resource
exhaustion class this line refers to does not exist in the real paper; the
15/17 figure was computed against the fabricated table above and cannot be
trusted.

---

## Dataset 2 — "Formal Security Framework for MCP" (23 classes)

**[AUDITED 2026-08-31] The real paper is "A Formal Security Framework for
MCP-Based AI Agents: Threat Taxonomy, Verification Models, and Defense
Mechanisms" (MCPSHIELD), arXiv:2604.05969 — Acharya & Gupta, 2026. It
organizes 23 attack vectors (TV1–TV23) into 7 threat categories (TC1–TC7).
Of the 23 classes originally claimed for it in this document, 5 match
(allowing a reasonable paraphrase, not requiring verbatim wording): "Tool
Description Poisoning" ≈ TV1 Description Injection, "Persistent Memory
Injection" ≈ TV19 Memory Poisoning, "Capability Escalation" = TV7 exactly,
"Tool Chain Hijacking" ≈ TV12 Capability Chaining, "Session Hijacking (token
theft)" ≈ TV21 Session Hijacking. The other 18 rows — External Instruction
Fetch, Cross-Session State Leakage, Access Control Bypass, Multi-Agent
Propagation, Data Leakage, Covert Channel, OAuth Flow Manipulation, Header
Injection, UI Injection, Deserialization Attack, Dynamic Plugin Loading,
RLHF / Feedback Poisoning, Sensor Data Manipulation, Context Window
Flooding, File Content Injection, Vision / Multimodal Injection, Jailbreak,
Parasitic Tool Registration — do not correspond to any of the real paper's
23 attack vectors. Their attached "AVE coverage" claims, including the two
"Planned → AVE-2026-00050/00051" rows and the two "See analysis below"
cross-session-state-leakage rows, are retracted along with them.**

The real 23 attack vectors, by threat category (verbatim names,
arXiv:2604.05969 Table I): **TC1 Tool Poisoning** — Description Injection,
Schema Manipulation, Return Value Poisoning, Tool Shadowing. **TC2 Rug Pull &
Mutation** — Post-Approval Mutation, Version Rollback, Capability Escalation.
**TC3 Cross-Server Data Leakage** — Exfiltration via Logging, Context Bleed,
Channel Coercion, Sampling Abuse. **TC4 Privilege Escalation** — Capability
Chaining, Consent Bypass, Role Confusion. **TC5 Server Trust Violations** —
Impersonation, Supply Chain Compromise, Dependency Hijacking. **TC6 Context
Manipulation** — Prompt Injection via Tool, Memory Poisoning, Resource
Injection. **TC7 Protocol-Level Vulnerabilities** — Session Hijacking, Replay
Attacks, Cross-Protocol Confusion.

**AVE coverage against this real list has not been re-derived in this
audit.** `[RETRACTED, ORIGINAL] FSF-MCP coverage: 19/23 full, 2 planned, 1
partial (session hijacking), 1 gap (cross-session state leakage).` — computed
against the fabricated table; not trustworthy. The "cross-session state
leakage analysis" paragraph that followed this line in the original document
is also retracted: it analyzed a class this document invented, attributing
the invented analysis to FSF-MCP as if the paper itself made this
distinction. It did not.

---

## Dataset 3 — Hou et al. 2025 (16 classes)

**[AUDITED 2026-08-31] Real paper: Hou, Zhao, Wang, Wang. "Model Context
Protocol (MCP): Landscape, Security Threats, and Future Research
Directions." arXiv:2503.23278, 2025 (the title originally cited in this
file was fabricated — see the dataset table above). It defines 16 threat
scenarios across 4 attacker types. Of the 16 classes originally claimed here,
5 match: Tool Poisoning (exact), "Rug Pull / External Fetch" ≈ Rug Pulls,
"Credential Exfiltration" ≈ Credential Theft, "Permission Escalation" ≈
Privilege Escalation, "Server Impersonation" ≈ Namespace Typosquatting. The
other 11 — Memory Poisoning, Cross-Agent Injection, Jailbreak, Hidden
Instructions, Output Encoding Exfiltration, Goal Hijacking, Scope Expansion,
History Fabrication, Self-Replication / Persistence, Dynamic Import,
Cross-App Escalation — do not correspond to any of the paper's real 16
scenarios. Their attached AVE-coverage claims are retracted with them.**

The real 16 threat scenarios, by attacker type (verbatim, arXiv:2503.23278
Table 3): **Malicious Developer** — Namespace Typosquatting, Tool Name
Conflict, Preference Manipulation, Tool Poisoning, Rug Pulls, Cross-Server
Shadowing, Command Injection. **External Attacker** — Installer Spoofing,
Indirect Prompt Injection. **Malicious User** — Credential Theft, Sandbox
Escape, Tool Chaining Abuse, Unauthorized Access. **Security Flaws** —
Vulnerable Versions, Privilege Escalation, Configuration Drift.

**AVE coverage against this real list has not been re-derived in this
audit.** `[RETRACTED, ORIGINAL] Hou et al. coverage: 16/16 full. Complete
coverage.` — this claim, that AVE fully covers every real Hou et al. class,
was never actually checked against the real 16 scenarios above (the table it
was computed from listed 11 different, non-existent classes). It may or may
not hold; it has not been verified either way and should not be repeated as
settled.

---

## Dataset 4 — MCP-SafetyBench (20 classes)

**[AUDITED 2026-08-31] Real paper: Zong, Shen, Wang, Lan, Yang.
"MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models
with Real-World MCP Servers." arXiv:2512.15163, published ICLR 2026 (dated
"(2025)" in this file's original dataset table — wrong by roughly a year).
It defines 20 attack types across MCP Server, Host, and User sides. Of the
20 classes originally claimed here, at most 5 correspond, and only one is an
exact match: "Credential Theft" (exact). The other four are generous
paraphrases at best: "Code Injection" ≈ Malicious Code Execution,
"Privilege Escalation" ≈ Excessive Privileges Misuse, "Output Manipulation"
≈ Function Return Injection, "Supply Chain" ≈ Rug Pull Attack. The remaining
15 — Prompt Injection, Data Exfiltration, Authentication Bypass, Denial of
Service (resource exhaustion), Tool Misuse, Information Disclosure, Memory
Manipulation, Cross-Agent Contamination, Output Manipulation as a distinct
row, Social Engineering, Jailbreak, Covert Channel, Lateral Movement, UI
Injection, File Content Injection, Vision / Multimodal Injection — do not
correspond to any of the paper's real 20 classes. This is the dataset where
issue #241's original finding (Denial of Service / "class 6" not existing)
came from; that single row turned out to be one of 15 wrong rows in this
table, not an isolated error.**

The real 20 attack types, by side (verbatim, arXiv:2512.15163 Table 2):
**MCP Server** — Tool Poisoning-Parameter Poisoning, Tool
Poisoning-Command Injection, Tool Poisoning-FileSystem Poisoning, Tool
Poisoning-Tool Redirection, Tool Poisoning-Network Request Poisoning, Tool
Poisoning-Function Dependency Injection, Function Overlapping, Preference
Manipulation, Tool Shadowing, Function Return Injection, Rug Pull Attack.
**MCP Host** — Intent Injection, Data Tampering, Identity Spoofing, Replay
Injection. **User** — Malicious Code Execution, Credential Theft, Remote
Access Control, Retrieval-Agent Deception, Excessive Privileges Misuse.

**AVE coverage against this real list has not been re-derived in this
audit.** `[RETRACTED, ORIGINAL] MCP-SafetyBench coverage: 19/20 full, 1 gap
(denial of service / resource exhaustion).` — the "gap" both never existed
(no such class in the real paper) and the 19/20 "full coverage" figure was
never checked against the real 20 classes above.

---

## Dataset 5 — MCPTox (theme misidentified; class list retracted in full)

**[AUDITED 2026-08-31] This section's original framing — "MCPTox focuses on
toxicity and content-safety violations produced via MCP tool abuse" — is
wrong at the level of the paper's actual subject, not just its class names.
The real MCPTox (Wang et al., arXiv:2508.14925, "A Benchmark for Tool
Poisoning Attack on Real-World MCP Servers") is entirely about Tool
Poisoning: malicious instructions embedded in a tool's own description,
evaluated against 45 real-world MCP servers and 353 real tools, with 3
distinct attack paradigms (Explicit Trigger–Function Hijacking, Implicit
Trigger–Function Hijacking, Implicit Trigger–Parameter Tampering) and 10-11
risk categories describing the resulting malicious action (the paper's own
abstract and introduction disagree on whether it's 10 or 11 — a real
inconsistency in the source itself). It has no content-toxicity, bias,
misinformation, discrimination, or self-harm dimension whatsoever. None of
the 11 classes originally listed here — Toxic Content Generation, Harmful
Instruction Following, Bias Amplification, Misinformation Propagation,
Privacy Violation, Discrimination, Violence Promotion, Self-Harm
Facilitation, Illegal Activity Facilitation, Deception, Manipulation — are
attested anywhere in the real paper. All 11 rows and their AVE-coverage
claims are retracted in full.**

The real paper's specific risk-category names (the malicious-action
taxonomy referenced in its Dataset Format section, §3.3) were not fully
enumerated in this audit pass — the paper's own attack-paradigm and
methodology sections were read directly and confirm the theme mismatch
conclusively, but the exact category list would need a further, separate
read to state completely and correctly. Marking that specific list as
**unverified** rather than guessing it, consistent with this audit treating
"unverifiable" as a real, distinct outcome rather than a soft pass — though
in this case the reason for not completing it is time, not unavailability;
a future pass could finish this cleanly.

`[RETRACTED, ORIGINAL] MCPTox coverage: 3/11 full, 3 partial, 5 out of
scope. MCPTox largely addresses model alignment and content safety — a
different problem domain from AVE's behavioral attack surface.` — this
entire conclusion rests on a mischaracterization of what MCPTox is. No
claim about AVE's relationship to MCPTox's real content should be drawn from
this document until a fresh read of the real risk-category list is done.

---

## Dataset 6 — OpenClaw study (ClawHub Security Signals)

**[AUDITED 2026-08-31] Real source: "ClawHub Security Signals: When
VirusTotal, Static Analysis, and SkillSpector Disagree," arXiv:2606.01494.
The two headline numbers this document originally cited are confirmed
correct against the real study: pairwise overlap tops out at 10.4% between
any two of the three compared systems, and all-three agreement is 0.69%.
One detail is wrong and corrected here: the three systems compared in the
real study are VirusTotal (malware reputation), static analysis, and NVIDIA
SkillSpector — not "SkillSpector, ClawScan, and one unnamed scanner" as
originally stated. ClawScan is the OpenClaw registry's own baseline/final
verdict system that the three scanners' signals are compared against,
not one of the three peer scanners being compared to each other.**

Key findings, corrected:
- **Pairwise overlap ≤ 10.4%** between any two of VirusTotal, static
  analysis, and NVIDIA SkillSpector — confirmed correct.
- **All-three agreement: 0.69%** — confirmed correct.
- 81.9% of flagged skills were identified by only one of the three systems
  (a real figure from the same study, not in this file's original text —
  added here since it directly supports the same point the original two
  numbers were making).

This study does not enumerate attack classes and contributes no new gap
candidates. It does confirm the adoption argument for AVE: the field
urgently needs a shared reference vocabulary. The 10.4% concordance ceiling
is what AVE exists to solve. This paragraph's conclusion is unaffected by
the scanner-identity correction above.

---

## Consolidated gap analysis

`[RETRACTED IN FULL, ORIGINAL]` The table originally here listed
"Resource Exhaustion / Agentic DoS" as a genuine gap "present in both
MCPSecBench and MCP-SafetyBench." Neither source contains this class (see
Datasets 1 and 4 above, and issue #241, which is what triggered this
audit). The other rows in the original table — Parasitic Tool Registration,
OAuth Discovery Rebinding, Header Injection (BadHost), Cross-Session State
Leakage, and the MCPTox out-of-scope row — rested on the same fabricated
per-dataset tables and are not re-asserted here as either confirmed or
refuted. A real consolidated gap analysis requires the AVE-coverage
re-derivation noted as outstanding in each dataset section above; it has
not been redone in this audit pass.

---

## New record candidates

`[RETRACTED, already actioned via issue #241]` **Candidate 1 — Agentic
Resource Exhaustion** is removed. Its sole primary-source justification
("MCPSecBench class 13 'Resource Exhaustion'; MCP-SafetyBench class 6
'Denial of Service'. Both independently enumerate this as a distinct class
with concrete test cases") does not hold: neither class exists in either
paper's real, published taxonomy. `AVE-2026-00052` was not reserved for
this candidate (that ID has since been used for an unrelated, genuinely
verified record — see the live corpus). No replacement candidate is
proposed here; if a resource-exhaustion-shaped behavioral class is worth
adding to AVE later, it needs its own fresh, independently verified
primary-source justification, not a revival of this one.

---

## Classes not recommended

`[STATUS: not re-verified in this audit]` The original table here — Cross-
session state leakage, Token replay / session hijacking, Bias amplification,
All MCPTox content-safety classes, Illegal activity facilitation — rested on
the same fabricated per-dataset tables audited above. Several of these
named classes (e.g. every MCPTox row, Bias amplification) do not exist in
the real sources at all, making "not recommended" a moot verdict on a
nonexistent premise rather than a wrong one. Not re-asserting or re-deriving
this table in this audit pass; it needs the same fresh coverage work noted
above.

---

## Coverage summary

`[RETRACTED IN FULL, ORIGINAL]` Every number in the original table here
(MCPSecBench 15/17, FSF-MCP 19/23, Hou et al. 16/16, MCP-SafetyBench 19/20,
MCPTox 3/11) was computed against a fabricated per-class table for that
dataset and does not reflect a real comparison against the dataset's actual
taxonomy. The "genuine gaps across all datasets: 1" conclusion drawn from
this table is also retracted — it names the same non-existent
resource-exhaustion class covered above.

---

## Recommended target count

**Current:** 48 records published (accurate as of this document's original
date, 2026-06-21; the live corpus is 80 records as of this audit,
2026-08-31 — not a correction, just the passage of time and unrelated work).
**Planned for v1.1:** +3 (00049 header injection, 00050 parasitic toolchain,
00051 OAuth rebinding) → **51**. This part of the original claim is AVE's
own internal, already-decided record planning, not an external citation,
and is not in scope for this citation audit; left as originally written.

`[RETRACTED, ORIGINAL] Recommended from this benchmark: +1 (00052 resource
exhaustion) → 52.` Removed — see "New record candidates" above and issue
#241. No net addition is recommended by this benchmark once its citations
are corrected; whatever real gaps this benchmark's five sources actually
describe have not yet been re-derived (see each dataset section above).

The record-count philosophy in the original paragraph here (research
suggesting ~25-35 genuinely distinct behavioral classes exist; AVE should
not target a count for its own sake) is a policy statement, not an external
citation, and stands unaudited and unchanged by this pass.

**Do not add records to close a count gap.** This principle, unlike the
specific "resource exhaustion" recommendation above, was correct before
this audit and remains correct after it.

**Next benchmark:** the original schedule note here ("2026-09 or when a new
dataset is published with >10 classes not previously mapped") is superseded
by this audit's own finding: the next benchmark pass should re-derive real
AVE-coverage against the five real taxonomies verified above, rather than
starting from a new dataset. That re-derivation is real, substantive work
this audit did not do and should not be assumed done.
