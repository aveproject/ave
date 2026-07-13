# AVE → OWASP MCP Top 10 crosswalk

All 56 AVE records mapped to OWASP MCP Top 10 categories.

**AVE records:** 56
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

Generated directly from each record's `owasp_mcp` field -- do not hand-edit this
table; regenerate it if records change.

| AVE ID | Title | AIVSS | Severity | Primary | Secondary |
|---|---|---|---|---|---|
| AVE-2026-00001 | Metamorphic payload via external config fetch | 8 | HIGH | MCP04 | MCP06 |
| AVE-2026-00002 | MCP tool description behavioral injection | 7.3 | HIGH | MCP03 | MCP10 |
| AVE-2026-00003 | Credential exfiltration via agent instruction | 6.8 | MEDIUM | MCP01 | MCP05 |
| AVE-2026-00004 | Arbitrary code execution via shell pipe injection in agentic c... | 5.9 | MEDIUM | MCP01 | MCP03 |
| AVE-2026-00005 | Recursive file system destruction via destructive command inje... | 5.6 | MEDIUM | MCP02 | MCP07 |
| AVE-2026-00006 | Cryptocurrency wallet drain via malicious fund transfer instru... | 7.5 | HIGH | MCP01 |  |
| AVE-2026-00007 | Agent goal hijack via direct instruction override in agentic c... | 6.1 | MEDIUM | MCP01 | MCP03 |
| AVE-2026-00008 | Agent persistence via self-replication instruction in agentic ... | 6.3 | MEDIUM | MCP04 | MCP08 |
| AVE-2026-00009 | AI identity jailbreak via role-play or persona override in age... | 5.5 | MEDIUM | MCP01 | MCP03 |
| AVE-2026-00010 | Covert instruction concealment via secrecy directive in agenti... | 5.6 | MEDIUM | MCP01 | MCP03 |
| AVE-2026-00011 | Arbitrary tool invocation via dynamic tool call injection in a... | 5.7 | MEDIUM | MCP01 |  |
| AVE-2026-00012 | Capability escalation via false permission grant in agentic co... | 4.5 | MEDIUM | MCP09 | MCP10 |
| AVE-2026-00013 | Personal data exfiltration via PII collection and transmission... | 6.5 | MEDIUM | MCP05 | MCP06 |
| AVE-2026-00014 | False authority claim via trust escalation impersonation in ag... | 3.7 | LOW | MCP09 | MCP10 |
| AVE-2026-00015 | System prompt extraction via direct interrogation instruction ... | 4.9 | MEDIUM | MCP06 |  |
| AVE-2026-00016 | Indirect Prompt Injection via RAG Retrieval | 6.4 | MEDIUM | MCP10 | MCP03 |
| AVE-2026-00017 | MCP Server Impersonation or Spoofing | 5.7 | MEDIUM | MCP09 | MCP07 |
| AVE-2026-00018 | Tool Result Manipulation or Output Poisoning | 4.4 | MEDIUM | MCP03 | MCP08 |
| AVE-2026-00019 | Agent Memory Poisoning | 5.6 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00020 | Cross-Agent Prompt Injection (A2A) | 5.9 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00021 | Autonomous Action Without User Confirmation | 4.5 | MEDIUM | MCP02 | MCP08 |
| AVE-2026-00022 | Scope Creep - Accessing Undeclared Resources | 6 | MEDIUM | MCP02 |  |
| AVE-2026-00023 | Model Context Window Manipulation | 5.8 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00024 | Supply Chain - Content Type Mismatch (Magika) | 6.8 | MEDIUM | MCP04 |  |
| AVE-2026-00025 | Conversation History Injection | 4.5 | MEDIUM | MCP10 | MCP06 |
| AVE-2026-00026 | Exfiltration via Tool Output Encoding | 6.8 | MEDIUM | MCP01 | MCP08 |
| AVE-2026-00027 | Multi-Turn Attack - Instruction Persistence Across Conversations | 5.6 | MEDIUM | MCP06 | MCP10 |
| AVE-2026-00028 | Prompt Injection via File or Document Content | 5.9 | MEDIUM | MCP10 | MCP03 |
| AVE-2026-00029 | Homoglyph or Unicode Obfuscation Attack | 4.8 | MEDIUM | MCP03 | MCP04 |
| AVE-2026-00030 | Privilege Escalation via False Role Claim | 4.3 | MEDIUM | MCP07 | MCP02 |
| AVE-2026-00031 | Training Data or Feedback Loop Poisoning | 5.4 | MEDIUM | MCP06 | MCP04 |
| AVE-2026-00032 | Network Reconnaissance Instruction | 4 | MEDIUM | MCP05 | MCP02 |
| AVE-2026-00033 | Unsafe Deserialization or Eval Instruction | 4.2 | MEDIUM | MCP05 | MCP04 |
| AVE-2026-00034 | Supply Chain - Dynamic Third-Party Skill Import | 6.6 | MEDIUM | MCP04 | MCP03 |
| AVE-2026-00035 | Environment or Sensor Data Manipulation | 4.2 | MEDIUM | MCP03 | MCP08 |
| AVE-2026-00036 | Lateral Movement - Pivot to Other Systems | 5.9 | MEDIUM | MCP05 | MCP02 |
| AVE-2026-00037 | Prompt Injection via Image or Vision Input | 5.1 | MEDIUM | MCP10 | MCP03 |
| AVE-2026-00038 | Excessive Agency - Unbounded Tool Use or Sub-Agent Spawning | 5.9 | MEDIUM | MCP02 | MCP08 |
| AVE-2026-00039 | Covert Channel - Steganographic Data Exfiltration | 4.9 | MEDIUM | MCP01 | MCP08 |
| AVE-2026-00040 | Insecure Output - Unescaped Injection into Downstream System | 5.4 | MEDIUM | MCP05 | MCP10 |
| AVE-2026-00041 | Prompt injection via MCP server-card tool descriptions before ... | 8.2 | HIGH | MCP03 | MCP09 |
| AVE-2026-00042 | Payload injection into agent-generated orchestration code via ... | 4.7 | MEDIUM | MCP05 | MCP10 |
| AVE-2026-00043 | Prompt injection via rich UI payload (canvas, artifact, form) ... | 4.7 | MEDIUM | MCP03 | MCP10 |
| AVE-2026-00044 | Prompt injection via poisoned async task result injected into ... | 6.1 | MEDIUM | MCP06 | MCP10 |
| AVE-2026-00045 | Privilege escalation via cross-app-access - pivot from low-tru... | 6.4 | MEDIUM | MCP02 | MCP07 |
| AVE-2026-00046 | MCP tool hook hijacking - redirect tool execution to attacker-... | 9.2 | CRITICAL | MCP03 | MCP06 |
| AVE-2026-00047 | Hardcoded credentials in agent component - API keys and secret... | 7.6 | HIGH | MCP02 | MCP09 |
| AVE-2026-00048 | Unsafe agent delegation chain - sub-agent spawned with inherit... | 7.7 | HIGH | MCP03 | MCP07 |
| AVE-2026-00049 | HTTP Host Header Injection via Agent-Initiated Request (BadHost) | 7.2 | HIGH | MCP04 | MCP05 |
| AVE-2026-00050 | Parasitic Toolchain — Silent Tool Registration and Persistent ... | 7.2 | HIGH | MCP04 | MCP07 |
| AVE-2026-00051 | OAuth Discovery Rebinding — Authorization Endpoint Redirected ... | 7.2 | HIGH | MCP01 | MCP07 |
| AVE-2026-00052 | Command injection via unsanitized tool-call parameter in MCP s... | 7.5 | HIGH | MCP05 | MCP04 |
| AVE-2026-00053 | Path traversal via unsanitized path parameter in MCP resource/... | 6.3 | MEDIUM | MCP02 | MCP07 |
| AVE-2026-00054 | Code-execution sandbox escape via JavaScript prototype-chain t... | 6.7 | MEDIUM | MCP05 | MCP07 |
| AVE-2026-00055 | Command execution via untrusted MCP server launch configuratio... | 7.7 | HIGH | MCP05 | MCP04 |
| AVE-2026-00056 | Zero-click data exfiltration via markdown image auto-fetch in ... | 5.8 | MEDIUM | MCP10 | MCP08 |

---

## By OWASP MCP category

### MCP01 — Token Mismanagement and Secret Exposure
AVE-2026-00003, AVE-2026-00004, AVE-2026-00006, AVE-2026-00007,
AVE-2026-00009, AVE-2026-00010, AVE-2026-00011, AVE-2026-00026,
AVE-2026-00039, AVE-2026-00051

### MCP02 — Privilege Escalation via Scope Creep
AVE-2026-00005, AVE-2026-00021, AVE-2026-00022, AVE-2026-00030,
AVE-2026-00032, AVE-2026-00036, AVE-2026-00038, AVE-2026-00045,
AVE-2026-00047, AVE-2026-00053

### MCP03 — Tool Poisoning
AVE-2026-00002, AVE-2026-00004, AVE-2026-00007, AVE-2026-00009,
AVE-2026-00010, AVE-2026-00016, AVE-2026-00018, AVE-2026-00028,
AVE-2026-00029, AVE-2026-00034, AVE-2026-00035, AVE-2026-00037,
AVE-2026-00041, AVE-2026-00043, AVE-2026-00046, AVE-2026-00048

### MCP04 — Software Supply Chain Attacks
AVE-2026-00001, AVE-2026-00008, AVE-2026-00024, AVE-2026-00029,
AVE-2026-00031, AVE-2026-00033, AVE-2026-00034, AVE-2026-00049,
AVE-2026-00050, AVE-2026-00052, AVE-2026-00055

### MCP05 — Command Injection and Execution
AVE-2026-00003, AVE-2026-00013, AVE-2026-00032, AVE-2026-00033,
AVE-2026-00036, AVE-2026-00040, AVE-2026-00042, AVE-2026-00049,
AVE-2026-00052, AVE-2026-00054, AVE-2026-00055

### MCP06 — Intent Flow Subversion
AVE-2026-00001, AVE-2026-00013, AVE-2026-00015, AVE-2026-00019,
AVE-2026-00020, AVE-2026-00023, AVE-2026-00025, AVE-2026-00027,
AVE-2026-00031, AVE-2026-00044, AVE-2026-00046

### MCP07 — Insufficient Authentication and Authorization
AVE-2026-00005, AVE-2026-00017, AVE-2026-00030, AVE-2026-00045,
AVE-2026-00048, AVE-2026-00050, AVE-2026-00051, AVE-2026-00053,
AVE-2026-00054

### MCP08 — Lack of Audit and Telemetry
AVE-2026-00008, AVE-2026-00018, AVE-2026-00021, AVE-2026-00026,
AVE-2026-00035, AVE-2026-00038, AVE-2026-00039, AVE-2026-00056

### MCP09 — Shadow MCP Servers
AVE-2026-00012, AVE-2026-00014, AVE-2026-00017, AVE-2026-00041,
AVE-2026-00047

### MCP10 — Context Injection and Over-sharing
AVE-2026-00002, AVE-2026-00012, AVE-2026-00014, AVE-2026-00016,
AVE-2026-00019, AVE-2026-00020, AVE-2026-00023, AVE-2026-00025,
AVE-2026-00027, AVE-2026-00028, AVE-2026-00037, AVE-2026-00040,
AVE-2026-00042, AVE-2026-00043, AVE-2026-00044, AVE-2026-00056

---

## Coverage by severity

| Severity | AIVSS | Count |
|---|---|---|
| CRITICAL | >= 9.0 | 1 |
| HIGH | 7.0–8.9 | 11 |
| MEDIUM | 4.0–6.9 | 43 |
| LOW | < 4.0 | 1 |

---

*OWASP MCP Top 10: owasp.org/www-project-mcp-top-10*
*OWASP AIVSS v0.8: aivss.owasp.org*
