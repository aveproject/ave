# Evidence declarations — all 48 AVE records

Canonical values grounded in real record data: attack_class, indicators_of_compromise,
behavioral_fingerprint, detection_methodology, component_type.
Validated against schema/ave-record-1.0.0.schema.json enum constraints.

## Corrections applied (10 total)

| AVE ID | Field | Correction | Reason |
|---|---|---|---|
| AVE-2026-00002 | evidence_kind_default | multi_engine → tool_description_pattern | Attack IS the tool description — naming the detection method, not the evidence type |
| AVE-2026-00008 | evidence_kind_default | tool_description_pattern → behavioral_pattern | Self-replication is a behavioral instruction (copy to .bashrc/crontab), not tool desc |
| AVE-2026-00009 | evidence_kind_default | tool_description_pattern → behavioral_pattern | Jailbreak/persona override is behavioral, not a tool description pattern |
| AVE-2026-00026 | evidence_kind_default | tool_description_pattern → multi_engine | Encoding+exfil combo requires pattern+yara+semgrep; multi_engine describes the detection correctly |
| AVE-2026-00027 | evidence_kind_default | tool_description_pattern → behavioral_pattern | 'Remember for all future conversations' is a persistence behavioral instruction |
| AVE-2026-00032 | evidence_kind_default | tool_description_pattern → behavioral_pattern | Nmap/network recon instruction is behavioral, not a tool description |
| AVE-2026-00033 | evidence_kind_default | tool_description_pattern → behavioral_pattern | eval()/exec() abuse is behavioral tool abuse, not a tool description pattern |
| AVE-2026-00034 | evidence_kind_default | tool_description_pattern → behavioral_pattern | Dynamic skill import is a behavioral supply chain instruction |
| AVE-2026-00039 | evidence_basis_engines | pattern+semgrep → pattern+yara+semgrep | Covert channel needs YARA for unicode/steganographic char detection |
| AVE-2026-00041 | confidence_baseline | 0.75 → 0.82 | Explicit URL + IMPORTANT/WARNING directive combo is HIGH signal |

## Full table

| AVE ID | Title | layer | stage | kind | engines | conf | derivable_into |
|---|---|---|---|---|---|---|---|
| AVE-2026-00001 | Metamorphic payload via external config fetch | content | static_detection | multi_engine | pattern+semgrep+yara | 0.83 | rug-pull-chain, remote-control-chain |
| AVE-2026-00002 | MCP tool description behavioral injection | content | static_detection | tool_description_pattern | pattern+semgrep+llm | 0.75 | remote-control-chain |
| AVE-2026-00003 | Credential exfiltration via agent instruction | content | static_detection | multi_engine | pattern+semgrep+yara | 0.83 | — |
| AVE-2026-00004 | Arbitrary code execution via shell pipe injection | content | static_detection | multi_engine | pattern+semgrep+yara | 0.9 | — |
| AVE-2026-00005 | Recursive file system destruction via destructive comma | content | static_detection | multi_engine | pattern+semgrep+yara | 0.9 | — |
| AVE-2026-00006 | Cryptocurrency wallet drain via malicious fund transfer | content | static_detection | multi_engine | pattern+semgrep+yara | 0.83 | — |
| AVE-2026-00007 | Agent goal hijack via direct instruction override | content | static_detection | multi_engine | pattern+semgrep+llm | 0.75 | — |
| AVE-2026-00008 | Agent persistence via self-replication instruction | content | static_detection | behavioral_pattern | pattern+semgrep | 0.83 | — |
| AVE-2026-00009 | AI identity jailbreak via role-play or persona override | content | static_detection | behavioral_pattern | pattern+semgrep+llm | 0.75 | — |
| AVE-2026-00010 | Covert instruction concealment via secrecy directive | content | static_detection | tool_description_pattern | pattern+semgrep | 0.65 | — |
| AVE-2026-00011 | Arbitrary tool invocation via dynamic tool call injecti | content | static_detection | tool_description_pattern | pattern+semgrep | 0.65 | — |
| AVE-2026-00012 | Capability escalation via false permission grant | content | static_detection | tool_description_pattern | pattern+semgrep | 0.65 | — |
| AVE-2026-00013 | Personal data exfiltration via PII collection | content | static_detection | multi_engine | pattern+semgrep+yara | 0.83 | — |
| AVE-2026-00014 | False authority claim via trust escalation impersonatio | content | static_detection | semantic_inference | semgrep+llm | 0.52 | — |
| AVE-2026-00015 | System prompt extraction via direct interrogation | content | static_detection | behavioral_pattern | pattern+semgrep | 0.83 | — |
| AVE-2026-00016 | Indirect Prompt Injection via RAG Retrieval | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00017 | MCP Server Impersonation or Spoofing | registry_metadata | static_detection | config_schema | pattern+semgrep | 0.83 | — |
| AVE-2026-00018 | Tool Result Manipulation or Output Poisoning | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00019 | Agent Memory Poisoning | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00020 | Cross-Agent Prompt Injection (A2A) | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00021 | Autonomous Action Without User Confirmation | content | static_detection | tool_description_pattern | pattern+semgrep | 0.75 | — |
| AVE-2026-00022 | Scope Creep — Accessing Undeclared Resources | content | static_detection | tool_description_pattern | pattern+semgrep | 0.65 | — |
| AVE-2026-00023 | Model Context Window Manipulation | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00024 | Supply Chain — Content Type Mismatch (Magika) | content | static_detection | file_type_mismatch | pattern+semgrep+magika | 0.9 | — |
| AVE-2026-00025 | Conversation History Injection | content | static_detection | tool_description_pattern | pattern+semgrep | 0.65 | — |
| AVE-2026-00026 | Exfiltration via Tool Output Encoding | content | static_detection | multi_engine | pattern+semgrep+yara | 0.83 | — |
| AVE-2026-00027 | Multi-Turn Attack — Instruction Persistence Across Conv | content | static_detection | behavioral_pattern | pattern+semgrep | 0.83 | — |
| AVE-2026-00028 | Prompt Injection via File or Document Content | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00029 | Homoglyph or Unicode Obfuscation Attack | content | static_detection | tool_description_pattern | pattern+yara | 0.75 | — |
| AVE-2026-00030 | Privilege Escalation via False Role Claim | content | static_detection | tool_description_pattern | pattern+semgrep | 0.75 | — |
| AVE-2026-00031 | Training Data or Feedback Loop Poisoning | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00032 | Network Reconnaissance Instruction | content | static_detection | behavioral_pattern | pattern+semgrep+yara | 0.9 | — |
| AVE-2026-00033 | Unsafe Deserialization or Eval Instruction | content | static_detection | behavioral_pattern | pattern+semgrep+yara | 0.9 | — |
| AVE-2026-00034 | Supply Chain — Dynamic Third-Party Skill Import | content | static_detection | behavioral_pattern | pattern+semgrep+yara | 0.83 | — |
| AVE-2026-00035 | Environment or Sensor Data Manipulation | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00036 | Lateral Movement — Pivot to Other Systems | content | static_detection | behavioral_pattern | semgrep+llm | 0.75 | — |
| AVE-2026-00037 | Prompt Injection via Image or Vision Input | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00038 | Excessive Agency — Unbounded Tool Use | content | static_detection | behavioral_pattern | semgrep+llm | 0.65 | — |
| AVE-2026-00039 | Covert Channel — Steganographic Data Exfiltration | content | static_detection | multi_engine | pattern+yara+semgrep | 0.83 | — |
| AVE-2026-00040 | Insecure Output — Unescaped Injection into Downstream S | content | static_detection | tool_description_pattern | pattern+semgrep | 0.65 | — |
| AVE-2026-00041 | Prompt injection via MCP server-card tool descriptions | server_card | static_detection | tool_description_pattern | pattern+semgrep | 0.82 | — |
| AVE-2026-00042 | REPL Code Mode Payload Injection | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | rug-pull-chain |
| AVE-2026-00043 | MCP App UI Payload Injection | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00044 | Async Task Result Poisoning | runtime | runtime_observed | behavioral_pattern | semgrep+llm | 0.62 | — |
| AVE-2026-00045 | Cross-App-Access Escalation | content | static_detection | tool_description_pattern | pattern+semgrep | 0.75 | credential-exfiltration, privilege-escalation-chain |
| AVE-2026-00046 | MCP Tool Hook Hijacking | server_card | static_detection | config_schema | pattern+semgrep | 0.83 | — |
| AVE-2026-00047 | Hardcoded Credentials in Agent Component | content | static_detection | multi_engine | pattern+yara+semgrep | 0.9 | — |
| AVE-2026-00048 | Unsafe Agent Delegation Chain | content | static_detection | tool_description_pattern | pattern+semgrep | 0.83 | privilege-escalation-chain |