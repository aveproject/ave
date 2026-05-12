## AVE Records - 2026 Series (16–40)

Add these files to your `bawbel-ave/` repository. Each file follows the same structure
as the existing records (AVE-2026-00001 through AVE-2026-00015).

### New in v1.0.0 - Agentic-native attack classes (16–25)

These records cover attack patterns unique to agentic AI systems - RAG pipelines,
multi-agent architectures, MCP servers, and persistent memory.

| AVE ID | Severity | AIVSS | Title | Bawbel Rule |
|--------|----------|---------|-------|-------------|
| [`AVE-2026-00016`](AVE-2026-00016.md) | 🟠 HIGH | 8.2 | Indirect Prompt Injection via RAG Retrieval | `bawbel-rag-injection` |
| [`AVE-2026-00017`](AVE-2026-00017.md) | 🟠 HIGH | 8.6 | MCP Server Impersonation or Spoofing | `bawbel-mcp-impersonation` |
| [`AVE-2026-00018`](AVE-2026-00018.md) | 🟠 HIGH | 8.1 | Tool Result Manipulation or Output Poisoning | `bawbel-tool-result-manipulation` |
| [`AVE-2026-00019`](AVE-2026-00019.md) | 🔴 CRITICAL | 9.2 | Agent Memory Poisoning | `bawbel-memory-poisoning` |
| [`AVE-2026-00020`](AVE-2026-00020.md) | 🟠 HIGH | 8.7 | Cross-Agent Prompt Injection (A2A) | `bawbel-a2a-injection` |
| [`AVE-2026-00021`](AVE-2026-00021.md) | 🟠 HIGH | 8.3 | Autonomous Action Without User Confirmation | `bawbel-autonomous-action` |
| [`AVE-2026-00022`](AVE-2026-00022.md) | 🟡 MEDIUM | 6.8 | Scope Creep - Accessing Undeclared Resources | `bawbel-scope-creep` |
| [`AVE-2026-00023`](AVE-2026-00023.md) | 🟠 HIGH | 8.0 | Model Context Window Manipulation | `bawbel-context-manipulation` |
| [`AVE-2026-00024`](AVE-2026-00024.md) | 🔴 CRITICAL | 9.5 | Supply Chain - Content Type Mismatch (Magika) | `bawbel-content-type-mismatch` |
| [`AVE-2026-00025`](AVE-2026-00025.md) | 🟠 HIGH | 8.5 | Conversation History Injection | `bawbel-history-injection` |

### New in v1.0.0 - Advanced attack classes (26–40)

These records cover more advanced attack vectors including multi-turn persistence,
supply chain attacks, lateral movement, covert channels, and unsafe output handling.

| AVE ID | Severity | AIVSS | Title | Bawbel Rule |
|--------|----------|---------|-------|-------------|
| [`AVE-2026-00026`](AVE-2026-00026.md) | 🔴 CRITICAL | 9.1 | Exfiltration via Tool Output Encoding | `bawbel-tool-output-exfil` |
| [`AVE-2026-00027`](AVE-2026-00027.md) | 🟠 HIGH | 8.4 | Multi-Turn Attack - Instruction Persistence Across Conversations | `bawbel-multiturn-attack` |
| [`AVE-2026-00028`](AVE-2026-00028.md) | 🟠 HIGH | 8.3 | Prompt Injection via File or Document Content | `bawbel-file-prompt-injection` |
| [`AVE-2026-00029`](AVE-2026-00029.md) | 🟠 HIGH | 8.0 | Homoglyph or Unicode Obfuscation Attack | `bawbel-homoglyph-attack` |
| [`AVE-2026-00030`](AVE-2026-00030.md) | 🔴 CRITICAL | 9.0 | Privilege Escalation via False Role Claim | `bawbel-role-claim-escalation` |
| [`AVE-2026-00031`](AVE-2026-00031.md) | 🟠 HIGH | 8.6 | Training Data or Feedback Loop Poisoning | `bawbel-feedback-poisoning` |
| [`AVE-2026-00032`](AVE-2026-00032.md) | 🟠 HIGH | 8.2 | Network Reconnaissance Instruction | `bawbel-network-recon` |
| [`AVE-2026-00033`](AVE-2026-00033.md) | 🔴 CRITICAL | 9.3 | Unsafe Deserialization or Eval Instruction | `bawbel-unsafe-deserialization` |
| [`AVE-2026-00034`](AVE-2026-00034.md) | 🔴 CRITICAL | 9.2 | Supply Chain - Dynamic Third-Party Skill Import | `bawbel-supply-chain-skill` |
| [`AVE-2026-00035`](AVE-2026-00035.md) | 🟠 HIGH | 7.9 | Environment or Sensor Data Manipulation | `bawbel-env-manipulation` |
| [`AVE-2026-00036`](AVE-2026-00036.md) | 🔴 CRITICAL | 9.4 | Lateral Movement - Pivot to Other Systems | `bawbel-lateral-movement` |
| [`AVE-2026-00037`](AVE-2026-00037.md) | 🟠 HIGH | 8.5 | Prompt Injection via Image or Vision Input | `bawbel-vision-prompt-injection` |
| [`AVE-2026-00038`](AVE-2026-00038.md) | 🟠 HIGH | 8.1 | Excessive Agency - Unbounded Tool Use or Sub-Agent Spawning | `bawbel-excessive-agency` |
| [`AVE-2026-00039`](AVE-2026-00039.md) | 🟠 HIGH | 8.3 | Covert Channel - Steganographic Data Exfiltration | `bawbel-covert-channel` |
| [`AVE-2026-00040`](AVE-2026-00040.md) | 🟠 HIGH | 8.2 | Insecure Output - Unescaped Injection into Downstream System | `bawbel-unsafe-output` |

### Complete AIVSS score summary

| Record | AIVSS | Severity |
|--------|---------|----------|
| `AVE-2026-00016` | 8.2 | HIGH |
| `AVE-2026-00017` | 8.6 | HIGH |
| `AVE-2026-00018` | 8.1 | HIGH |
| `AVE-2026-00019` | 9.2 | CRITICAL |
| `AVE-2026-00020` | 8.7 | HIGH |
| `AVE-2026-00021` | 8.3 | HIGH |
| `AVE-2026-00022` | 6.8 | MEDIUM |
| `AVE-2026-00023` | 8.0 | HIGH |
| `AVE-2026-00024` | 9.5 | CRITICAL |
| `AVE-2026-00025` | 8.5 | HIGH |
| `AVE-2026-00026` | 9.1 | CRITICAL |
| `AVE-2026-00027` | 8.4 | HIGH |
| `AVE-2026-00028` | 8.3 | HIGH |
| `AVE-2026-00029` | 8.0 | HIGH |
| `AVE-2026-00030` | 9.0 | CRITICAL |
| `AVE-2026-00031` | 8.6 | HIGH |
| `AVE-2026-00032` | 8.2 | HIGH |
| `AVE-2026-00033` | 9.3 | CRITICAL |
| `AVE-2026-00034` | 9.2 | CRITICAL |
| `AVE-2026-00035` | 7.9 | HIGH |
| `AVE-2026-00036` | 9.4 | CRITICAL |
| `AVE-2026-00037` | 8.5 | HIGH |
| `AVE-2026-00038` | 8.1 | HIGH |
| `AVE-2026-00039` | 8.3 | HIGH |
| `AVE-2026-00040` | 8.2 | HIGH |