# SkillSpector → AVE crosswalk

**Source:** NVIDIA SkillSpector v2.0.0 — 64 patterns across 16 categories
**Target:** AVE v1.0.0 — 48 records
**Generated:** 2026-06-18
**Source:** https://github.com/NVIDIA/SkillSpector

SkillSpector organises detection as an internal scanner taxonomy across 16
categories. AVE is a behavioral standard with stable ids. This table maps
each SkillSpector category to the AVE records that cover the same behavior.

Two categories have no AVE class:
- **YARA signatures** — detects embedded known-malware artifacts, not behavioral
  vulnerability classes in skill instructions. Out of scope for AVE.
- **Taint tracking / Dangerous code (AST)** — detection techniques, not
  vulnerability classes. The underlying behaviors are covered by other AVE records.

---

## Category mapping

| SkillSpector category | AVE id(s) | Primary | Notes |
|---|---|---|---|
| prompt_injection | AVE-2026-00002, 00007, 00009, 00010 | **AVE-2026-00002** | Tool description injection (canonical), goal override, jailbreak, hidden instruction concealment |
| data_exfiltration | AVE-2026-00003, 00013, 00026, 00039 | **AVE-2026-00003** | Credential exfil, PII exfil, tool output encoding exfil, covert steganographic channel |
| privilege_escalation | AVE-2026-00012, 00022, 00045 | **AVE-2026-00045** | Cross-app escalation, permission escalation via false claim, scope creep |
| supply_chain | AVE-2026-00001, 00024, 00034 | **AVE-2026-00001** | External instruction fetch (canonical), content type mismatch, dynamic skill import |
| excessive_agency | AVE-2026-00021, 00038, 00048 | **AVE-2026-00038** | Unbounded tool use, autonomous action without confirmation, unsafe agent delegation chain |
| output_handling | AVE-2026-00040 | **AVE-2026-00040** | Insecure output injection into downstream systems |
| system_prompt_leakage | AVE-2026-00015 | **AVE-2026-00015** | System prompt extraction |
| memory_poisoning | AVE-2026-00019, 00025 | **AVE-2026-00019** | Agent memory poisoning, conversation history injection |
| tool_misuse | AVE-2026-00011, 00018 | **AVE-2026-00011** | Dynamic tool call injection, tool result manipulation |
| rogue_agent | AVE-2026-00036, 00048 | **AVE-2026-00048** | Unsafe agent delegation chain, lateral movement via agent pivot |
| trigger_abuse | AVE-2026-00001, 00027 | **AVE-2026-00001** | External instruction fetch, multi-turn persistence attack. **Gap:** conditional trigger abuse as a distinct class is not yet enumerated. |
| dangerous_code_ast | AVE-2026-00004, 00033 | **AVE-2026-00033** | Unsafe deserialization and eval, shell pipe injection. AST is a detection technique — these are the underlying classes. |
| taint_tracking | AVE-2026-00003, 00026 | **AVE-2026-00003** | Taint tracking surfaces exfiltration classes. Detection technique, not a vulnerability class. |
| yara_signatures | — | — | Detects embedded malware artifacts. Out of AVE scope — AVE enumerates behavioral classes in skill instructions, not malware payload signatures. |
| mcp_least_privilege | AVE-2026-00002, 00022 | **AVE-2026-00022** | Scope creep, tool description manipulation. **Gap:** server-card capability over-declaration is not yet a distinct AVE record. |
| mcp_tool_poisoning | AVE-2026-00002, 00029, 00041 | **AVE-2026-00002** | Tool description injection (canonical), homoglyph/Unicode obfuscation, MCP server-card injection |

---

## Gaps

| SkillSpector category | Gap |
|---|---|
| yara_signatures | YARA detects embedded malware payloads. AVE enumerates behavioral vulnerability classes in skill instructions — complementary, not overlapping. |
| trigger_abuse | Conditional trigger abuse (deferred payloads, dead-man switches) is partially covered by AVE-2026-00001 and AVE-2026-00027 but not separately enumerated. |
| mcp_least_privilege | MCP server-card capability over-declaration as a distinct behavioral class has no current AVE record. |

---

## Coverage summary

| | |
|---|---|
| SkillSpector categories mapped | 15 of 16 |
| SkillSpector categories with no AVE class | 1 (yara_signatures) |
| SkillSpector categories with partial gaps | 2 |
| AVE records referenced | 26 |

---

*Machine-readable version: [skillspector-to-ave.json](skillspector-to-ave.json)*