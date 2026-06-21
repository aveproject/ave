# SkillSpector → AVE crosswalk

**Source:** NVIDIA SkillSpector v2.0.0 — 64 patterns across 16 categories
**Target:** AVE v1.0.0 — 51 records
**Generated:** 2026-06-21
**Source:** https://github.com/NVIDIA/SkillSpector

SkillSpector organises detection as an internal scanner taxonomy across 16
categories. AVE is a behavioral standard with stable ids. This table maps
each SkillSpector category to the AVE records that cover the same behavior.

> **Updated 2026-06-21** for the 51-record set. The v1.1 migration added
> AVE-2026-00049 (HTTP Host Header Injection), AVE-2026-00050 (Parasitic
> Toolchain), and AVE-2026-00051 (OAuth Discovery Rebinding) — see the
> `supply_chain`, `rogue_agent`, `mcp_least_privilege`, and `taint_tracking`
> rows below for where they landed.

Two categories have no AVE class:
- **YARA signatures** — detects embedded known-malware artifacts, not behavioral
  vulnerability classes in skill instructions. Out of scope for AVE.
- **Taint tracking / Dangerous code (AST)** — detection techniques, not
  vulnerability classes. The underlying behaviors are covered by other AVE records.

---

## Category mapping

| SkillSpector category | AVE id(s) | Primary | Notes |
|---|---|---|---|
| prompt_injection | AVE-2026-00002, AVE-2026-00007, AVE-2026-00009, AVE-2026-00010 | **AVE-2026-00002** | AVE-2026-00002 is the canonical tool description injection class. AVE-2026-00007 covers goal override; AVE-2026-00009 jailbreak instructions; AVE-2026-00010 hidden instruction concealment. |
| data_exfiltration | AVE-2026-00003, AVE-2026-00013, AVE-2026-00026, AVE-2026-00039 | **AVE-2026-00003** | AVE-2026-00003 is credential exfiltration; AVE-2026-00013 PII exfiltration; AVE-2026-00026 tool output encoding exfil; AVE-2026-00039 covert steganographic channel. |
| privilege_escalation | AVE-2026-00012, AVE-2026-00022, AVE-2026-00045 | **AVE-2026-00045** | AVE-2026-00045 is cross-app escalation; AVE-2026-00012 permission escalation via false claim; AVE-2026-00022 scope creep. |
| supply_chain | AVE-2026-00001, AVE-2026-00024, AVE-2026-00034, AVE-2026-00049, AVE-2026-00051 | **AVE-2026-00001** | AVE-2026-00001 is the canonical metamorphic/external-fetch class; AVE-2026-00024 content type mismatch; AVE-2026-00034 dynamic skill import. AVE-2026-00049 (HTTP Host Header Injection) and AVE-2026-00051 (OAuth Discovery Rebinding) added: both are attack_class='Supply Chain - ...' in AVE's own taxonomy, sharing the supply-chain framing of a trusted server delivering tampered routing/auth metadata rather than tampered code. |
| excessive_agency | AVE-2026-00021, AVE-2026-00038, AVE-2026-00048 | **AVE-2026-00038** | AVE-2026-00038 covers unbounded tool use; AVE-2026-00021 autonomous action without confirmation; AVE-2026-00048 unsafe agent delegation chain. |
| output_handling | AVE-2026-00040 | **AVE-2026-00040** | AVE-2026-00040 covers insecure output injection into downstream systems. |
| system_prompt_leakage | AVE-2026-00015 | **AVE-2026-00015** | AVE-2026-00015 covers system prompt extraction. |
| memory_poisoning | AVE-2026-00019, AVE-2026-00025 | **AVE-2026-00019** | AVE-2026-00019 is agent memory poisoning; AVE-2026-00025 conversation history injection. |
| tool_misuse | AVE-2026-00011, AVE-2026-00018 | **AVE-2026-00011** | AVE-2026-00011 covers dynamic tool call injection; AVE-2026-00018 tool result manipulation. |
| rogue_agent | AVE-2026-00048, AVE-2026-00036, AVE-2026-00050 | **AVE-2026-00048** | AVE-2026-00048 covers unsafe agent delegation chain; AVE-2026-00036 lateral movement via agent pivot. AVE-2026-00050 (Parasitic Toolchain) added: a component that silently registers itself as additional tools/hooks in the agent's runtime is a rogue-agent pattern -- it behaves as an unauthorised actor inside the trusted tool dispatch layer, surviving session resets like a persistent rogue presence. |
| trigger_abuse | AVE-2026-00001, AVE-2026-00027 | **AVE-2026-00001** | AVE-2026-00001 covers deferred remote fetch triggers; AVE-2026-00027 multi-turn persistence attack. **Gap:** No AVE record specifically addresses conditional trigger abuse as a distinct behavioral class. |
| dangerous_code_ast | AVE-2026-00004, AVE-2026-00033 | **AVE-2026-00033** | AVE-2026-00033 covers unsafe deserialization and eval; AVE-2026-00004 shell pipe injection. *Scanner mechanic:* AST analysis is a detection technique. The underlying behavioral classes are covered by AVE records for the specific class (shell injection, eval abuse, etc.). |
| taint_tracking | AVE-2026-00003, AVE-2026-00026, AVE-2026-00049 | **AVE-2026-00003** | Taint tracking is a detection technique that surfaces exfiltration and injection classes already covered by AVE. AVE-2026-00049 (HTTP Host Header Injection) added: the attacker-controlled host value flows from a tainted source into the Host header sink -- a textbook taint-tracking detection target. *Scanner mechanic:* Taint tracking is a scanner mechanic, not a vulnerability class. It detects exfiltration and injection patterns covered by multiple AVE records. |
| yara_signatures | — | — | YARA signatures detect known malware artifacts -- not behavioral vulnerability classes in the AVE sense. Positive YARA matches indicate the skill bundles known malware, which is outside AVE's enumeration scope. AVE records describe behavioral classes in skill instructions, not embedded malware payloads. |
| mcp_least_privilege | AVE-2026-00022, AVE-2026-00002, AVE-2026-00050 | **AVE-2026-00022** | AVE-2026-00022 covers scope creep and undeclared resource access. AVE-2026-00002 covers tool description manipulation that may include overbroad capability claims. AVE-2026-00050 (Parasitic Toolchain) added: a component registering tool handlers beyond its declared manifest scope is a direct least-privilege violation at the MCP tool-registration layer. **Gap:** No AVE record specifically addresses MCP server-card capability over-declaration as a distinct class. |
| mcp_tool_poisoning | AVE-2026-00002, AVE-2026-00041, AVE-2026-00029 | **AVE-2026-00002** | AVE-2026-00002 is the canonical tool description injection class. AVE-2026-00041 covers MCP server-card injection specifically. AVE-2026-00029 covers homoglyph and Unicode obfuscation as a delivery variant. |

---

## The 3 new records

**AVE-2026-00049 (HTTP Host Header Injection)** lands in `supply_chain` (the
component shares AVE's own "Supply Chain - ..." attack_class framing: a trusted
server delivers tampered routing metadata rather than tampered code) and
`taint_tracking` (the attacker-controlled host value flows from a tainted source
into the Host header sink — a textbook taint-tracking detection target).

**AVE-2026-00050 (Parasitic Toolchain)** lands in `rogue_agent` (a component that
silently registers itself as additional tools/hooks behaves as an unauthorised
actor inside the trusted tool dispatch layer, surviving session resets like a
persistent rogue presence) and `mcp_least_privilege` (registering tool handlers
beyond the declared manifest scope is a direct least-privilege violation).

**AVE-2026-00051 (OAuth Discovery Rebinding)** lands in `supply_chain` (the
server's own discovery document is the trust-chain link being tampered with).

---

## Gaps

| SkillSpector category | Gap |
|---|---|
| yara_signatures | YARA detects embedded known-malware artifacts. AVE enumerates behavioral vulnerability classes in skill instructions, not malware payload matching. These are complementary, not overlapping. |
| trigger_abuse | Conditional trigger abuse as a distinct behavioral class (deferred payload execution, dead-man switches) is not yet a separate AVE record. Partially covered by AVE-2026-00001 and AVE-2026-00027. |
| mcp_least_privilege | Server-card capability over-declaration as a distinct behavioral class is not yet a separate AVE record, though AVE-2026-00050 now covers the runtime registration variant of this gap. |

---

## Coverage summary

| | |
|---|---|
| SkillSpector categories mapped | 15 of 16 |
| SkillSpector categories with no AVE class | 1 (yara_signatures) |
| SkillSpector categories with partial gaps | 2 |
| AVE records referenced | 29 |

---

*Machine-readable version: [skillspector-to-ave.json](skillspector-to-ave.json)*