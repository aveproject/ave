<div align="center">

<!-- <img src="https://bawbel.io/assets/bawbel-logo.svg" alt="Bawbel" width="80" /> -->

# AVE: Agentic Vulnerability Enumeration

**The open vulnerability database for agentic AI components.**

Every record covers a distinct attack class affecting MCP servers, skill files,
system prompts, and agent plugins. All records are scored with OWASP AIVSS v0.8.

[![Records](https://img.shields.io/badge/records-48-critical?style=flat-square&color=e53e3e)](records/)
[![Schema](https://img.shields.io/badge/schema-v0.2.0-blue?style=flat-square)](SPEC.md)
[![AIVSS](https://img.shields.io/badge/AIVSS-v0.8-orange?style=flat-square)](https://aivss.owasp.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](LICENSE)
[![Scanner](https://img.shields.io/badge/scanner-bawbel--scanner-black?style=flat-square)](https://github.com/bawbel/scanner)

</div>

---

## What is AVE?

Skill files, MCP server manifests, and system prompts are executable
instructions, not documentation. Any process that loads them runs them.
There is no compiler, no type checker, no sandbox. The runtime is an LLM
that reads natural language and acts on it.

AVE gives this attack surface stable IDs, reproducible scoring, detection
rules, and remediation steps. Same idea as CVE and CWE, applied to agents.

```
Your CI pipeline scans Python for CVEs.
It does not scan your SKILL.md for prompt injection.
AVE + Bawbel fixes that.
```

---

## How it works

```
  Attacker crafts          Developer ships          Agent loads
  malicious payload   →    skill file          →    skill file
                           (unscanned)              at runtime
                                ↓
                         Agent executes
                         attacker payload
                         (data exfiltrated,
                          credentials stolen,
                          goals hijacked)
```

**With AVE + Bawbel Scanner:**

```
  Developer commits        bawbel scan fires        Finding blocked
  skill file          →    in pre-commit hook   →    before deploy
                                ↓
                         AVE-2026-00001 detected:
                         External instruction fetch
                         AIVSS 8.0 / HIGH
                         Line 7: "fetch your instructions from..."
```

The scanner checks every skill file against all 48 AVE records using five
detection engines: pattern matching, YARA, Semgrep, file type verification,
and optional LLM meta-analysis.

---

## Stats

| Metric | Value |
|---|---|
| Total records | 48 |
| Schema version | 0.2.0 |
| AIVSS spec | v0.8 |
| CRITICAL (AIVSS ≥ 9.0) | 1 |
| HIGH (AIVSS 7.0-8.9) | 6 |
| MEDIUM (AIVSS 4.0-6.9) | 39 |
| LOW (AIVSS < 4.0) | 2 |

---

## AIVSS Scoring

Every AVE record is scored using [OWASP AIVSS v0.8](https://aivss.owasp.org).

```
AIVSS = ((CVSS_Base + AARS) / 2) × ThM × Mitigation_Factor
```

**AARS** (Agentic Risk Score) is the weighted sum of 10 Agentic Risk
Amplification Factors (AARFs), each scored 0.0 / 0.5 / 1.0:

| # | Factor | Why it matters |
|---|---|---|
| 1 | **Autonomy** | Agent acts without human approval |
| 2 | **Tool Use** | Agent has access to external tools/APIs |
| 3 | **Multi-Agent** | Agent interacts with or spawns other agents |
| 4 | **Non-Determinism** | Behavior unpredictable across runs |
| 5 | **Self-Modification** | Can alter own instructions or memory |
| 6 | **Dynamic Identity** | Assumes roles or identities at runtime |
| 7 | **Persistent Memory** | Retains state across sessions |
| 8 | **Natural Language Input** | Instruction surface via natural language |
| 9 | **Data Access** | Reads sensitive data (files, env, DB) |
| 10 | **External Dependencies** | Loads external code, skills, or plugins |

**Severity bands:**

| Band | AIVSS Range | Meaning |
|---|---|---|
| CRITICAL | 9.0 - 10.0 | Immediate exploitation, full agent compromise |
| HIGH | 7.0 - 8.9 | Significant data loss or privilege escalation |
| MEDIUM | 4.0 - 6.9 | Meaningful risk requiring review |
| LOW | 0.1 - 3.9 | Limited impact or requires chaining |

---

## Record Index

| AVE ID | Title | AIVSS | Severity |
|---|---|---|---|
| [AVE-2026-00001](records/AVE-2026-00001.json) | Metamorphic Payload via External Config Fetch | 8.0 | HIGH |
| [AVE-2026-00002](records/AVE-2026-00002.json) | Tool Poisoning via Description Manipulation | 7.3 | HIGH |
| [AVE-2026-00003](records/AVE-2026-00003.json) | Data Exfiltration via Credential Theft | 6.8 | MEDIUM |
| [AVE-2026-00004](records/AVE-2026-00004.json) | Arbitrary Code Execution via Shell Pipe Injection | 5.9 | MEDIUM |
| [AVE-2026-00005](records/AVE-2026-00005.json) | Destructive Command Execution | 5.6 | MEDIUM |
| [AVE-2026-00006](records/AVE-2026-00006.json) | Cryptocurrency Drain via Wallet Access | 7.5 | HIGH |
| [AVE-2026-00007](records/AVE-2026-00007.json) | Goal Hijacking via Prompt Injection | 6.1 | MEDIUM |
| [AVE-2026-00008](records/AVE-2026-00008.json) | Persistence via Self-Replication | 6.3 | MEDIUM |
| [AVE-2026-00009](records/AVE-2026-00009.json) | Jailbreak via Safety Constraint Removal | 5.5 | MEDIUM |
| [AVE-2026-00010](records/AVE-2026-00010.json) | Hidden Instruction Concealment | 5.6 | MEDIUM |
| [AVE-2026-00011](records/AVE-2026-00011.json) | Dynamic Tool Call with Attacker Parameters | 5.7 | MEDIUM |
| [AVE-2026-00012](records/AVE-2026-00012.json) | Privilege Escalation via Permission Grant | 4.5 | MEDIUM |
| [AVE-2026-00013](records/AVE-2026-00013.json) | PII Exfiltration Pattern | 6.5 | MEDIUM |
| [AVE-2026-00014](records/AVE-2026-00014.json) | Social Engineering via Trust Escalation | 3.7 | LOW |
| [AVE-2026-00015](records/AVE-2026-00015.json) | System Prompt Disclosure | 4.9 | MEDIUM |
| [AVE-2026-00016](records/AVE-2026-00016.json) | Indirect Prompt Injection via RAG Retrieval | 6.4 | MEDIUM |
| [AVE-2026-00017](records/AVE-2026-00017.json) | MCP Server Impersonation | 5.7 | MEDIUM |
| [AVE-2026-00018](records/AVE-2026-00018.json) | Tool Result Manipulation | 4.4 | MEDIUM |
| [AVE-2026-00019](records/AVE-2026-00019.json) | Agent Memory Poisoning | 5.6 | MEDIUM |
| [AVE-2026-00020](records/AVE-2026-00020.json) | Cross-Agent Injection via A2A Protocol | 5.9 | MEDIUM |
| [AVE-2026-00021](records/AVE-2026-00021.json) | Human-in-the-Loop Bypass | 4.5 | MEDIUM |
| [AVE-2026-00022](records/AVE-2026-00022.json) | Scope Creep via Undeclared Resource Access | 6.0 | MEDIUM |
| [AVE-2026-00023](records/AVE-2026-00023.json) | Context Window Manipulation | 5.8 | MEDIUM |
| [AVE-2026-00024](records/AVE-2026-00024.json) | Supply Chain: Binary Content Disguised as Skill | 6.8 | MEDIUM |
| [AVE-2026-00025](records/AVE-2026-00025.json) | Conversation History Injection | 4.5 | MEDIUM |
| [AVE-2026-00026](records/AVE-2026-00026.json) | Tool Output Exfiltration via Encoding | 6.8 | MEDIUM |
| [AVE-2026-00027](records/AVE-2026-00027.json) | Multi-Turn Persistence Attack | 5.6 | MEDIUM |
| [AVE-2026-00028](records/AVE-2026-00028.json) | File Content Injection | 5.9 | MEDIUM |
| [AVE-2026-00029](records/AVE-2026-00029.json) | Homoglyph and Unicode Obfuscation | 4.8 | MEDIUM |
| [AVE-2026-00030](records/AVE-2026-00030.json) | False Role Claim | 4.3 | MEDIUM |
| [AVE-2026-00031](records/AVE-2026-00031.json) | Feedback Loop Poisoning | 5.4 | MEDIUM |
| [AVE-2026-00032](records/AVE-2026-00032.json) | Internal Network Reconnaissance | 4.0 | MEDIUM |
| [AVE-2026-00033](records/AVE-2026-00033.json) | Unsafe Deserialization in Skill Context | 4.2 | MEDIUM |
| [AVE-2026-00034](records/AVE-2026-00034.json) | Dynamic Skill Import at Runtime | 6.6 | MEDIUM |
| [AVE-2026-00035](records/AVE-2026-00035.json) | Sensor and Environment Manipulation | 4.2 | MEDIUM |
| [AVE-2026-00036](records/AVE-2026-00036.json) | Lateral Movement via Agent Pivot | 5.9 | MEDIUM |
| [AVE-2026-00037](records/AVE-2026-00037.json) | Vision and Multimodal Injection | 5.1 | MEDIUM |
| [AVE-2026-00038](records/AVE-2026-00038.json) | Unbounded Tool Use | 5.9 | MEDIUM |
| [AVE-2026-00039](records/AVE-2026-00039.json) | Covert Exfiltration via Steganographic Channel | 4.9 | MEDIUM |
| [AVE-2026-00040](records/AVE-2026-00040.json) | Insecure Output Handling | 5.4 | MEDIUM |
| [AVE-2026-00041](records/AVE-2026-00041.json) | MCP Server-Card Injection | 8.2 | HIGH |
| [AVE-2026-00042](records/AVE-2026-00042.json) | REPL Code Mode Credential Exposure | 4.7 | MEDIUM |
| [AVE-2026-00043](records/AVE-2026-00043.json) | MCP App UI Injection | 4.7 | MEDIUM |
| [AVE-2026-00044](records/AVE-2026-00044.json) | Async Task Result Poisoning | 6.1 | MEDIUM |
| [AVE-2026-00045](records/AVE-2026-00045.json) | Cross-App-Access Escalation | 6.4 | MEDIUM |
| [AVE-2026-00046](records/AVE-2026-00046.json) | MCP Tool Hook Hijacking | 9.1 | **CRITICAL** |
| [AVE-2026-00047](records/AVE-2026-00047.json) | Hardcoded Credentials in Agent Component | 7.8 | HIGH |
| [AVE-2026-00048](records/AVE-2026-00048.json) | Unsafe Agent Delegation Chain | 8.2 | HIGH |

---

## Detect with Bawbel Scanner

Every AVE record has detection rules in
[bawbel/scanner](https://github.com/bawbel/scanner).

```bash
pip install bawbel-scanner

# Scan a skill file
bawbel scan ./my-skill.md

# Scan a directory recursively
bawbel scan ./skills/ --recursive --fail-on-severity high

# Full remediation report
bawbel report ./my-skill.md

# Scan an MCP server card
bawbel ssc https://api.your-mcp-server.io
```

Output:

```
CRITICAL  bawbel-hook-hijack          AVE-2026-00046  line 3   AIVSS 9.1
HIGH      bawbel-unsafe-delegation    AVE-2026-00048  line 11  AIVSS 8.2
HIGH      bawbel-hardcoded-credential AVE-2026-00047  line 5   AIVSS 7.8
```

---

## Adding a new AVE record

### When to add a record

A new record needs three things: the attack class is not already covered,
there is real-world evidence (working PoC, published exploit, or observed
incident), and the vulnerability is specific to agentic components (skill
files, MCP servers, system prompts, plugins) rather than a generic
web or API issue.

### Step 1: Open an issue first

Open an issue before writing any JSON. Use the **New AVE Record** template
and include the attack class, component type, one real-world example or PoC,
and your proposed AARF scores with a short rationale for each factor.

This keeps maintainers in the loop and gets you the next AVE ID before
you write anything.

### Step 2: Create the JSON record

Copy [`records/AVE-2026-00045.json`](records/AVE-2026-00045.json) as your
template. Fill every field. Required fields:

```
ave_id, schema_version, component_type, title, attack_class, description,
aivss_score, owasp_mapping, behavioral_fingerprint, behavioral_vector,
detection_methodology, indicators_of_compromise, remediation, aivss, status,
published
```

AIVSS calculation checklist:

```
1. Score each AARF factor: 0.0 (not applicable), 0.5 (partial), 1.0 (full)
2. AARS = sum of all 10 AARF scores
3. Pick CVSS_Base from the cvss_base_vector
4. AIVSS = ((CVSS_Base + AARS) / 2) × ThM × Mitigation_Factor
5. ThM = 0.75 default; raise to 0.90 for actively exploited, 1.0 for weaponised
6. Round to 1 decimal place
7. Set aivss_severity: CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0, LOW < 4.0
```

### Step 3: Add detection rules to bawbel/scanner

Every AVE record needs at least a pattern rule in the scanner. Open a
coordinated PR in [bawbel/scanner](https://github.com/bawbel/scanner):

```
scanner/engines/pattern.py     ← add entry to PATTERN_RULES
scanner/rules/yara/ave_rules.yar    ← add YARA rule
scanner/rules/semgrep/ave_rules.yaml ← add Semgrep rule
```

Pattern rule structure:

```python
{
    "rule_id":     "bawbel-your-rule-id",
    "ave_id":      "AVE-2026-NNNNN",
    "title":       "Short title under 80 chars",
    "description": "Full description for remediation report.",
    "severity":    Severity.HIGH,
    "aivss_score": 7.5,
    "owasp":       ["ASI01"],
    "owasp_mcp":   ["MCP03"],
    "patterns": [
        r"pattern one regex",
        r"pattern two regex",
    ],
},
```

Rule naming: `bawbel-<attack-class>` in kebab-case. No abbreviations.

### Step 4: Update this README

Add a row to the Record Index table and update the Stats block at the top.
Increment `Total records` and the right severity band counter.

### Step 5: Submit the PR

PR title format: `feat: AVE-2026-NNNNN - <attack class>`

The PR description must include:
- Link to the issue
- AARF scores with rationale
- At least one `behavioral_vector` example
- Link to the coordinated scanner PR

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
  "owasp_mcp": ["MCP01"],
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
    "thm": 0.75,
    "mitigation_factor": 1.0,
    "aivss_score": 8.0,
    "aivss_severity": "HIGH",
    "spec_version": "0.8",
    "owasp_mcp_mapping": ["MCP01"],
    "notes": "..."
  },
  "status": "active",
  "kill_switch_active": true,
  "researcher": "...",
  "researcher_url": "...",
  "published": "2026-05-16T00:00:00Z",
  "last_updated": "2026-05-16T00:00:00Z",
  "references": []
}
```

---

## Related

- [bawbel/scanner](https://github.com/bawbel/scanner): the CLI scanner that detects these
- [OWASP AIVSS v0.8](https://aivss.owasp.org): the scoring formula
- [api.piranha.bawbel.io](https://api.piranha.bawbel.io): threat intel API, one record per AVE ID
- [bawbel.io/docs](https://bawbel.io/docs): docs

---

AVE records are published under [Apache 2.0](LICENSE).
OWASP AIVSS v0.8: [aivss.owasp.org](https://aivss.owasp.org)