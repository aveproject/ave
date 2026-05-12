# AVE

**Agentic Vulnerability Enumeration (AVE) Records**

The AVE standard is the open vulnerability database for agentic AI components.
Every record covers a distinct attack class affecting MCP servers, skill files,
system prompts, and agent plugins.

All records are scored with [OWASP AIVSS v0.8](https://aivss.owasp.org).

---

## Stats

| Metric | Value |
|---|---|
| Total records | 45 |
| Schema version | 0.2.0 |
| AIVSS spec | v0.8 |
| CRITICAL (AIVSS >= 9.0) | 0 |
| HIGH (AIVSS 7.0-8.9) | 3 |
| MEDIUM (AIVSS 4.0-6.9) | 40 |
| LOW (AIVSS < 4.0) | 2 |

---

## AIVSS Scoring

Every AVE record is scored using [OWASP AIVSS v0.8](https://aivss.owasp.org).

**Formula:**
```
AIVSS = ((CVSS_Base + AARS) / 2) * ThM * Mitigation_Factor
```

Where AARS (Agentic Risk Score) is the sum of 10 Agentic Risk Amplification
Factors (AARFs), each scored 0.0 / 0.5 / 1.0:

| # | Factor | Description |
|---|---|---|
| 1 | Autonomy | Agent acts without human approval |
| 2 | Tool Use | Agent has access to external tools/APIs |
| 3 | Multi-Agent | Agent interacts with other agents |
| 4 | Non-Determinism | Behavior unpredictable across runs |
| 5 | Self-Modification | Can alter own instructions or memory |
| 6 | Dynamic Identity | Assumes roles or identities at runtime |
| 7 | Persistent Memory | Retains state across sessions |
| 8 | Natural Language Input | Instruction surface via natural language |
| 9 | Data Access | Reads sensitive data (files, env, DB) |
| 10 | External Dependencies | Loads external code, skills, or plugins |

---

## Record Index

| AVE ID | Title | AIVSS | Severity |
|---|---|---|---|
| AVE-2026-00001 | Metamorphic Payload via External Config Fetch | 8.0 | HIGH |
| AVE-2026-00002 | Tool Poisoning via Description Manipulation | 7.3 | HIGH |
| AVE-2026-00003 | Data Exfiltration via Credential Theft | 6.8 | MEDIUM |
| AVE-2026-00004 | Arbitrary Code Execution via Shell Pipe Injection | 5.9 | MEDIUM |
| AVE-2026-00005 | Destructive Command Execution | 5.6 | MEDIUM |
| AVE-2026-00006 | Cryptocurrency Drain via Wallet Access | 7.5 | HIGH |
| AVE-2026-00007 | Goal Hijacking via Prompt Injection | 6.1 | MEDIUM |
| AVE-2026-00008 | Persistence via Self-Replication | 6.3 | MEDIUM |
| AVE-2026-00009 | Jailbreak via Safety Constraint Removal | 5.5 | MEDIUM |
| AVE-2026-00010 | Hidden Instruction Concealment | 5.6 | MEDIUM |
| AVE-2026-00011 | Dynamic Tool Call with Attacker Parameters | 5.7 | MEDIUM |
| AVE-2026-00012 | Privilege Escalation via Permission Grant | 4.5 | MEDIUM |
| AVE-2026-00013 | PII Exfiltration Pattern | 6.5 | MEDIUM |
| AVE-2026-00014 | Social Engineering via Trust Escalation | 3.7 | LOW |
| AVE-2026-00015 | System Prompt Disclosure | 4.9 | MEDIUM |
| AVE-2026-00016 | Indirect Prompt Injection via RAG Retrieval | 6.4 | MEDIUM |
| AVE-2026-00017 | MCP Server Impersonation | 5.7 | MEDIUM |
| AVE-2026-00018 | Tool Result Manipulation | 4.4 | MEDIUM |
| AVE-2026-00019 | Agent Memory Poisoning | 5.6 | MEDIUM |
| AVE-2026-00020 | Cross-Agent Injection via A2A Protocol | 5.9 | MEDIUM |
| AVE-2026-00021 | Human-in-the-Loop Bypass | 4.5 | MEDIUM |
| AVE-2026-00022 | Scope Creep via Undeclared Resource Access | 6.0 | MEDIUM |
| AVE-2026-00023 | Context Window Manipulation | 5.8 | MEDIUM |
| AVE-2026-00024 | Supply Chain: Binary Content Disguised as Skill | 6.8 | MEDIUM |
| AVE-2026-00025 | Conversation History Injection | 4.5 | MEDIUM |
| AVE-2026-00026 | Tool Output Exfiltration via Encoding | 6.8 | MEDIUM |
| AVE-2026-00027 | Multi-Turn Persistence Attack | 5.6 | MEDIUM |
| AVE-2026-00028 | File Content Injection | 5.9 | MEDIUM |
| AVE-2026-00029 | Homoglyph and Unicode Obfuscation | 4.8 | MEDIUM |
| AVE-2026-00030 | False Role Claim | 4.3 | MEDIUM |
| AVE-2026-00031 | Feedback Loop Poisoning | 5.4 | MEDIUM |
| AVE-2026-00032 | Internal Network Reconnaissance | 4.0 | MEDIUM |
| AVE-2026-00033 | Unsafe Deserialization in Skill Context | 4.2 | MEDIUM |
| AVE-2026-00034 | Dynamic Skill Import at Runtime | 6.6 | MEDIUM |
| AVE-2026-00035 | Sensor and Environment Manipulation | 4.2 | MEDIUM |
| AVE-2026-00036 | Lateral Movement via Agent Pivot | 5.9 | MEDIUM |
| AVE-2026-00037 | Vision and Multimodal Injection | 5.1 | MEDIUM |
| AVE-2026-00038 | Unbounded Tool Use | 5.9 | MEDIUM |
| AVE-2026-00039 | Covert Exfiltration via Steganographic Channel | 4.9 | MEDIUM |
| AVE-2026-00040 | Insecure Output Handling | 5.4 | MEDIUM |
| AVE-2026-00041 | MCP Server-Card Injection | 8.2 | HIGH |
| AVE-2026-00042 | REPL Code Mode Credential Exposure | 4.7 | MEDIUM |
| AVE-2026-00043 | MCP App UI Injection | 4.7 | MEDIUM |
| AVE-2026-00044 | Async Task Result Poisoning | 6.1 | MEDIUM |
| AVE-2026-00045 | Cross-App-Access Escalation | 6.4 | MEDIUM |

---

## JSON record schema (v0.2.0)

```json
{
  "ave_id": "AVE-2026-00001",
  "schema_version": "0.2.0",
  "component_type": "skill | mcp | system_prompt | plugin",
  "title": "...",
  "attack_class": "...",
  "description": "...",
  "affected_platforms": [],
  "affected_registries": [],
  "aivss_score": 8.0,
  "cvss_base_vector": "CVSS:4.0/...",
  "owasp_mapping": ["ASI01"],
  "owasp_mcp": ["MCP01", "MCP03"],
  "nist_ai_rmf_mapping": [],
  "mitre_atlas_mapping": [],
  "behavioral_fingerprint": "...",
  "behavioral_vector": [],
  "mutation_count": 0,
  "detection_methodology": "...",
  "indicators_of_compromise": [],
  "remediation": "...",
  "aivss": {
    "cvss_base": 8.5,
    "aarf": {
      "autonomy": 1.0,
      "tool_use": 1.0,
      "multi_agent": 0.5,
      "non_determinism": 1.0,
      "self_modification": 1.0,
      "dynamic_identity": 0.0,
      "persistent_memory": 0.5,
      "natural_language_input": 1.0,
      "data_access": 0.5,
      "external_dependencies": 1.0
    },
    "aars": 7.5,
    "thm": 1.0,
    "mitigation_factor": 1.0,
    "aivss_score": 8.0,
    "aivss_severity": "HIGH",
    "spec_version": "0.8",
    "owasp_mcp_mapping": ["MCP01", "MCP03"],
    "notes": "..."
  },
  "status": "active",
  "kill_switch_active": true,
  "researcher": "Bawbel Security Research Team",
  "researcher_url": "https://bawbel.io",
  "published": "2026-04-19T09:00:00Z",
  "last_updated": "2026-05-12T00:00:00Z",
  "references": []
}
```

---

## Related

- [bawbel/bawbel-scanner](https://github.com/bawbel/bawbel-scanner) - scanner that detects AVE vulnerabilities
- [OWASP AIVSS](https://aivss.owasp.org) - scoring standard used for all records
- [api.piranha.bawbel.io](https://api.piranha.bawbel.io) - public threat intel API
- [bawbel.io/docs](https://bawbel.io/docs) - documentation

---

## Contributing

To propose a new AVE record:
1. Open an issue with the attack class, affected component type, and a real-world example
2. Submit a PR following the schema above
3. Include AIVSS AARF scores with rationale for each factor

All submissions require at least one real-world occurrence or a working proof of concept.

---

*AVE records are published under CC BY 4.0.*
*OWASP AIVSS v0.8: aivss.owasp.org*