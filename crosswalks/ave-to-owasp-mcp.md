# AVE → OWASP MCP Top 10 crosswalk

All 48 AVE records mapped to OWASP MCP Top 10 categories.

**AVE records:** 48
**OWASP MCP Top 10:** Beta 2025 (MCP01:2025 – MCP10:2025)
**AIVSS spec:** v0.8
**Reference:** https://owasp.org/www-project-mcp-top-10/

Use this mapping for compliance sign-off, risk prioritisation by OWASP
category, gap analysis against existing controls, and audit reporting.

---

## OWASP MCP Top 10 categories

| ID | Category |
|---|---|
| MCP01 | Token Mismanagement and Secret Exposure |
| MCP02 | Privilege Escalation via Scope Creep |
| MCP03 | Tool Poisoning |
| MCP04 | Software Supply Chain Attacks |
| MCP05 | Command Injection and Execution |
| MCP06 | Intent Flow Subversion |
| MCP07 | Insufficient Authentication and Authorization |
| MCP08 | Lack of Audit and Telemetry |
| MCP09 | Shadow MCP Servers |
| MCP10 | Context Injection and Over-sharing |

---

## Full mapping

| AVE ID | Title | AIVSS | Severity | Primary | Secondary |
|---|---|---|---|---|---|
| AVE-2026-00001 | External instruction fetch (metamorphic payload) | 8.0 | HIGH | MCP04 | MCP06 |
| AVE-2026-00002 | MCP tool description injection | 7.3 | HIGH | MCP03 | MCP10 |
| AVE-2026-00003 | Credential exfiltration via agent instruction | 6.8 | MEDIUM | MCP01 | MCP05 |
| AVE-2026-00004 | Shell pipe injection pattern | 5.9 | MEDIUM | MCP05 | MCP06 |
| AVE-2026-00005 | Destructive command execution | 5.6 | MEDIUM | MCP05 | |
| AVE-2026-00006 | Cryptocurrency drain attack | 7.5 | HIGH | MCP05 | MCP02 |
| AVE-2026-00007 | Goal override instruction | 6.1 | MEDIUM | MCP06 | |
| AVE-2026-00008 | Persistence and self-replication | 6.3 | MEDIUM | MCP05 | MCP04 |
| AVE-2026-00009 | Jailbreak instruction | 5.5 | MEDIUM | MCP06 | |
| AVE-2026-00010 | Hidden instruction concealment | 5.6 | MEDIUM | MCP06 | MCP08 |
| AVE-2026-00011 | Dynamic tool call injection | 5.7 | MEDIUM | MCP03 | MCP05 |
| AVE-2026-00012 | Permission escalation via false claim | 4.5 | MEDIUM | MCP02 | MCP07 |
| AVE-2026-00013 | PII exfiltration pattern | 6.5 | MEDIUM | MCP01 | MCP05 |
| AVE-2026-00014 | Trust escalation — false authority claim | 3.7 | LOW | MCP07 | MCP09 |
| AVE-2026-00015 | System prompt extraction | 4.9 | MEDIUM | MCP10 | MCP08 |
| AVE-2026-00016 | Indirect RAG prompt injection | 6.4 | MEDIUM | MCP10 | MCP03 |
| AVE-2026-00017 | MCP server impersonation | 5.7 | MEDIUM | MCP09 | MCP07 |
| AVE-2026-00018 | Tool result manipulation | 4.4 | MEDIUM | MCP03 | MCP08 |
| AVE-2026-00019 | Agent memory poisoning | 5.6 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00020 | Cross-agent A2A injection | 5.9 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00021 | Autonomous action without confirmation | 4.5 | MEDIUM | MCP02 | MCP08 |
| AVE-2026-00022 | Scope creep — undeclared resource access | 6.0 | MEDIUM | MCP02 | |
| AVE-2026-00023 | Context window manipulation | 5.8 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00024 | Content type mismatch — supply chain | 6.8 | MEDIUM | MCP04 | |
| AVE-2026-00025 | Conversation history injection | 4.5 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00026 | Tool output exfiltration encoding | 6.8 | MEDIUM | MCP01 | MCP08 |
| AVE-2026-00027 | Multi-turn attack persistence | 5.6 | MEDIUM | MCP06 | MCP10 |
| AVE-2026-00028 | File prompt injection | 5.9 | MEDIUM | MCP10 | MCP03 |
| AVE-2026-00029 | Homoglyph and Unicode obfuscation | 4.8 | MEDIUM | MCP03 | MCP04 |
| AVE-2026-00030 | Role claim privilege escalation | 4.3 | MEDIUM | MCP07 | MCP02 |
| AVE-2026-00031 | Feedback and training loop poisoning | 5.4 | MEDIUM | MCP06 | MCP04 |
| AVE-2026-00032 | Network reconnaissance instruction | 4.0 | MEDIUM | MCP05 | MCP02 |
| AVE-2026-00033 | Unsafe deserialization and eval | 4.2 | MEDIUM | MCP05 | MCP04 |
| AVE-2026-00034 | Supply chain skill import | 6.6 | MEDIUM | MCP04 | MCP03 |
| AVE-2026-00035 | Environment and sensor data manipulation | 4.2 | MEDIUM | MCP03 | MCP08 |
| AVE-2026-00036 | Lateral movement — pivot to other systems | 5.9 | MEDIUM | MCP05 | MCP02 |
| AVE-2026-00037 | Vision prompt injection via image | 5.1 | MEDIUM | MCP10 | MCP03 |
| AVE-2026-00038 | Excessive agency — unbounded tool use | 5.9 | MEDIUM | MCP02 | MCP08 |
| AVE-2026-00039 | Covert channel — steganographic exfil | 4.9 | MEDIUM | MCP01 | MCP08 |
| AVE-2026-00040 | Insecure output injection | 5.4 | MEDIUM | MCP05 | MCP10 |
| AVE-2026-00041 | MCP server-card injection | 8.2 | HIGH | MCP03 | MCP09 |
| AVE-2026-00042 | REPL code mode payload injection | 4.7 | MEDIUM | MCP05 | MCP10 |
| AVE-2026-00043 | MCP app UI injection | 4.7 | MEDIUM | MCP03 | MCP10 |
| AVE-2026-00044 | Async task result poisoning | 6.1 | MEDIUM | MCP06 | MCP10 |
| AVE-2026-00045 | Cross-app-access escalation | 6.4 | MEDIUM | MCP02 | MCP07 |
| AVE-2026-00046 | MCP tool hook hijacking | 9.1 | CRITICAL | MCP03 | MCP07 |
| AVE-2026-00047 | Hardcoded credentials in agent component | 7.8 | HIGH | MCP01 | MCP07 |
| AVE-2026-00048 | Unsafe agent delegation chain | 8.2 | HIGH | MCP03 | MCP07 |

---

## By OWASP MCP category

### MCP01 — Token Mismanagement and Secret Exposure
AVE-2026-00003, AVE-2026-00013, AVE-2026-00026, AVE-2026-00039,
AVE-2026-00047

### MCP02 — Privilege Escalation via Scope Creep
AVE-2026-00006, AVE-2026-00008, AVE-2026-00012, AVE-2026-00021,
AVE-2026-00022, AVE-2026-00030, AVE-2026-00032, AVE-2026-00036,
AVE-2026-00038, AVE-2026-00045

### MCP03 — Tool Poisoning
AVE-2026-00002, AVE-2026-00011, AVE-2026-00016, AVE-2026-00018,
AVE-2026-00029, AVE-2026-00034, AVE-2026-00035, AVE-2026-00037,
AVE-2026-00041, AVE-2026-00043, AVE-2026-00046, AVE-2026-00048

### MCP04 — Software Supply Chain Attacks
AVE-2026-00001, AVE-2026-00008, AVE-2026-00024, AVE-2026-00029,
AVE-2026-00031, AVE-2026-00033, AVE-2026-00034

### MCP05 — Command Injection and Execution
AVE-2026-00003, AVE-2026-00004, AVE-2026-00005, AVE-2026-00006,
AVE-2026-00008, AVE-2026-00011, AVE-2026-00013, AVE-2026-00032,
AVE-2026-00033, AVE-2026-00036, AVE-2026-00040, AVE-2026-00042

### MCP06 — Intent Flow Subversion
AVE-2026-00001, AVE-2026-00004, AVE-2026-00007, AVE-2026-00009,
AVE-2026-00010, AVE-2026-00019, AVE-2026-00020, AVE-2026-00023,
AVE-2026-00025, AVE-2026-00027, AVE-2026-00031, AVE-2026-00044

### MCP07 — Insufficient Authentication and Authorization
AVE-2026-00012, AVE-2026-00014, AVE-2026-00017, AVE-2026-00030,
AVE-2026-00045, AVE-2026-00046, AVE-2026-00047, AVE-2026-00048

### MCP08 — Lack of Audit and Telemetry
AVE-2026-00010, AVE-2026-00015, AVE-2026-00018, AVE-2026-00021,
AVE-2026-00026, AVE-2026-00035, AVE-2026-00038, AVE-2026-00039

### MCP09 — Shadow MCP Servers
AVE-2026-00014, AVE-2026-00017, AVE-2026-00041

### MCP10 — Context Injection and Over-sharing
AVE-2026-00002, AVE-2026-00015, AVE-2026-00016, AVE-2026-00019,
AVE-2026-00020, AVE-2026-00023, AVE-2026-00025, AVE-2026-00027,
AVE-2026-00028, AVE-2026-00037, AVE-2026-00040, AVE-2026-00042,
AVE-2026-00043, AVE-2026-00044

---

## Coverage by severity

| Severity | AIVSS | Count |
|---|---|---|
| CRITICAL | >= 9.0 | 1 |
| HIGH | 7.0–8.9 | 6 |
| MEDIUM | 4.0–6.9 | 39 |
| LOW | < 4.0 | 2 |

---

*OWASP MCP Top 10: owasp.org/www-project-mcp-top-10*
*OWASP AIVSS v0.8: aivss.owasp.org*