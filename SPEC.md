# AVE Specification

**Agentic Vulnerability Enumeration: the open standard for AI agent security.**

> Version: 0.2.0
> Status: Active
> Maintainer: [Bawbel](https://bawbel.io)
> License: Apache 2.0
> Scoring: [OWASP AIVSS v0.8](https://aivss.owasp.org)

---

## Table of Contents

1. [What is AVE?](#1-what-is-ave)
2. [Why not CVE?](#2-why-not-cve)
3. [Governance](#3-governance)
4. [Scope](#4-scope)
5. [AVE ID Format](#5-ave-id-format)
6. [Record Schema](#6-record-schema)
7. [AIVSS Scoring](#7-aivss-scoring)
8. [Framework Mappings](#8-framework-mappings)
9. [Submitting a Record](#9-submitting-a-record)
10. [Disclosure Policy](#10-disclosure-policy)

---

## 1. What is AVE?

AVE is an open numbering system for vulnerabilities in agentic AI components:
skill files, MCP servers, system prompts, agent plugins, A2A protocols, and
RAG knowledge bases.

Each record answers four questions:

- **What** is the vulnerability? (attack class, behavioral description)
- **Where** does it appear? (component type, affected registries, platforms)
- **How dangerous** is it? (OWASP AIVSS v0.8 score, agentic risk factors)
- **How do you find it?** (behavioral fingerprint, detection rules, IOCs)

AVE records power [bawbel-scanner](https://github.com/bawbel/bawbel-scanner)
and are indexed in [PiranhaDB](https://api.piranha.bawbel.io), the public
threat intelligence API for agentic AI components.

The specification is open. Any tool can implement it. Any researcher can
submit records.

---

## 2. Why not CVE?

CVE was designed in 1999 for deterministic software flaws. It works well for
buffer overflows, SQL injection, and use-after-free. AVE covers a different
attack surface.

| Dimension | CVE | AVE |
|---|---|---|
| Vulnerability type | Deterministic code flaw | Behavioral, probabilistic, natural language |
| Subject | Specific software version | Agentic component (any format, any platform) |
| Reproducibility | Exact reproduction required | Behavioral pattern matching |
| Patching | Vendor issues patched version | Component removed or behavioral policy applied |
| Mutation tracking | One CVE per instance | One record covers all behavioral variants |
| Scoring | CVSS | OWASP AIVSS v0.8 |
| Processing speed | Days to months | Near real-time via PiranhaDB |

AVE and CVE are complementary. A SKILL.md with a traditional RCE in embedded
Python gets a CVE. The prompt injection instruction in the same file that
hijacks the agent's goals gets an AVE. Both are necessary.

---

## 3. Governance

AVE v0.2.0 is maintained by [Bawbel](https://bawbel.io).

### Current state

Bawbel owns the AVE numbering system, the record schema, and the PiranhaDB
API. The specification is open source (Apache 2.0). Anyone can read it,
implement it, submit records, and propose changes via GitHub pull request.
Bawbel makes final decisions on schema changes and record acceptance today.

### Guiding principle

The long-term goal is for AVE to be governed by a neutral body where no
single organization holds a majority. What that body looks like, whether
an existing foundation such as OWASP, the Linux Foundation, or OpenSSF,
or something new, will be decided based on what the community and ecosystem
actually support. We are not planning that in advance.

Bawbel's commitment: when AVE reaches the adoption level where neutral
governance makes sense, we will transfer ownership. We will not use
governance control to extract commercial advantage from the standard.

### How to participate now

- Submit AVE records via pull request (see [Section 9](#9-submitting-a-record))
- Propose schema changes by opening a GitHub issue
- Implement AVE in your own tools (Apache 2.0, no permission needed)
- If your organization is interested in co-governing AVE as it matures,
  email bawbel.io@gmail.com subject: `AVE Governance: [organization name]`


---

## 4. Scope

AVE covers every artifact that defines what an AI agent can do.

| Component | component_type | Examples | Primary Attack Classes |
|---|---|---|---|
| Skill files | skill | SKILL.md, .cursorrules, CLAUDE.md | Prompt injection, goal hijack, metamorphic payload |
| MCP servers | mcp | Any MCP-compatible server manifest | Tool poisoning, server-card injection |
| System prompts | prompt | LLM deployment instructions | Jailbreak, safety bypass, PII leakage |
| Agent plugins | plugin | Copilot plugins, Bedrock agents | Supply chain poisoning, capability escalation |
| A2A protocols | a2a | Google A2A handlers, multi-agent configs | Agent impersonation, transitive trust exploitation |
| RAG sources | rag | LlamaIndex, LangChain, Bedrock KB | Data poisoning, indirect prompt injection |
| Fine-tuned models | model | HuggingFace, Azure AI, Vertex AI | Model poisoning, backdoor triggers |

**Out of scope:** vulnerabilities in agent runtime software such as model
weights, inference engines, and orchestration frameworks. Those get CVEs.

---

## 5. AVE ID Format

```
AVE-{YEAR}-{SEQUENCE}
```

- `YEAR`: four-digit calendar year the record was created
- `SEQUENCE`: five-digit zero-padded integer, assigned sequentially

Examples: `AVE-2026-00001`, `AVE-2026-00045`

IDs are permanent. A published AVE ID is never reused or deleted. If a record
is found to be incorrect it is marked `disputed` and the dispute is noted
inline.

---

## 6. Record Schema

### v0.2.0 (current)

```json
{
  "ave_id": "AVE-2026-00001",
  "schema_version": "0.2.0",
  "component_type": "skill",
  "title": "One sentence describing the attack",
  "attack_class": "Category - Subcategory",
  "description": "Full technical description of the attack pattern.",
  "affected_platforms": ["claude-code", "cursor", "windsurf"],
  "affected_registries": ["clawhub.io", "smithery.ai"],
  "aivss_score": 8.0,
  "cvss_base_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
  "owasp_mapping": ["ASI01", "ASI07"],
  "owasp_mcp": ["MCP01", "MCP03"],
  "nist_ai_rmf_mapping": ["MAP-1.5", "MEASURE-2.5"],
  "mitre_atlas_mapping": ["AML.T0054"],
  "behavioral_fingerprint": "One sentence behavioral signature.",
  "behavioral_vector": ["capability-tag-1", "capability-tag-2"],
  "mutation_count": 12,
  "detection_methodology": "Step by step detection instructions.",
  "indicators_of_compromise": [
    "Indicator one",
    "Indicator two"
  ],
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
    "notes": "Rationale for AARF scores."
  },
  "remediation": "Step by step remediation guidance.",
  "status": "active",
  "kill_switch_active": false,
  "researcher": "Researcher name or team",
  "researcher_url": "https://researcher-url.example.com",
  "published": "2026-04-19T09:00:00Z",
  "last_updated": "2026-05-12T00:00:00Z",
  "references": [
    "https://reference-url.example.com"
  ]
}
```

### Field reference

| Field | Type | Required | Description |
|---|---|---|---|
| ave_id | string | yes | Unique identifier in AVE-YYYY-NNNNN format |
| schema_version | string | yes | Currently 0.2.0 |
| component_type | string | yes | skill, mcp, prompt, plugin, a2a, rag, or model |
| title | string | yes | One sentence. Present tense. No trailing period. |
| attack_class | string | yes | Category - Subcategory. No em dashes. |
| description | string | yes | Full technical description. |
| affected_platforms | array | yes | At least one platform. |
| affected_registries | array | yes | At least one registry, or ["any"]. |
| aivss_score | float | yes | Top-level AIVSS score 0.0 to 10.0. |
| cvss_base_vector | string | yes | CVSSv4.0 base vector string. |
| owasp_mapping | array | yes | OWASP ASI codes. At least one. |
| owasp_mcp | array | yes | OWASP MCP Top 10 codes. At least one. |
| nist_ai_rmf_mapping | array | yes | NIST AI RMF function codes. |
| mitre_atlas_mapping | array | yes | MITRE ATLAS technique IDs. |
| behavioral_fingerprint | string | yes | One sentence behavioral signature. |
| behavioral_vector | array | yes | Capability tags for toxic flow detection. |
| mutation_count | int | yes | Number of documented payload variants. |
| detection_methodology | string | yes | Step-by-step detection instructions. |
| indicators_of_compromise | array | yes | At least two IOCs. |
| aivss | object | yes | Full AIVSS v0.8 block. See Section 6. |
| remediation | string | yes | Step-by-step remediation instructions. |
| status | string | yes | active, mitigated, disputed, or deprecated. |
| kill_switch_active | bool | yes | Whether active kill-switch coordination is in progress. |
| researcher | string | yes | Discovering researcher or team. |
| researcher_url | string | no | URL for researcher attribution. |
| published | string | yes | ISO 8601 publication timestamp. |
| last_updated | string | yes | ISO 8601 last update timestamp. |
| references | array | yes | At least one reference URL. |

---

## 7. AIVSS Scoring

All AVE records are scored using [OWASP AIVSS v0.8](https://aivss.owasp.org).

### Formula

```
AIVSS = ((CVSS_Base + AARS) / 2) * ThM * Mitigation_Factor
```

Where:

- `CVSS_Base` is the CVSSv4.0 base score (0.0 to 10.0)
- `AARS` is the Agentic Risk Score: sum of 10 AARF values (0.0 to 10.0)
- `ThM` is the Threat Multiplier: 1.0 = actively exploited, 0.9 = PoC exists, 0.75 = theoretical
- `Mitigation_Factor`: 1.0 = none, 0.83 = partial mitigation, 0.67 = strong mitigation

### 10 Agentic Risk Amplification Factors (AARFs)

Each AARF is scored 0.0 (absent), 0.5 (partial), or 1.0 (fully present).

| Factor | What it measures |
|---|---|
| autonomy | Agent acts without human approval |
| tool_use | Agent has access to external tools or APIs |
| multi_agent | Agent interacts with other agents |
| non_determinism | Behavior is unpredictable across runs |
| self_modification | Agent can alter its own instructions or memory |
| dynamic_identity | Agent assumes roles or identities at runtime |
| persistent_memory | Agent retains state across sessions |
| natural_language_input | Instruction surface is natural language |
| data_access | Agent reads sensitive data (files, env vars, databases) |
| external_dependencies | Agent loads external code, skills, or plugins |

### Severity bands

| Score | Severity | Recommended CI action |
|---|---|---|
| 0.0 | None | Pass |
| 0.1 to 3.9 | Low | Pass with warning |
| 4.0 to 6.9 | Medium | Configurable |
| 7.0 to 8.9 | High | Fail |
| 9.0 to 10.0 | Critical | Fail, block merge |

---

## 8. Framework Mappings

Every AVE record maps to four external frameworks.

**OWASP ASI Top 10:** `ASI01` through `ASI10`. In `owasp_mapping` field.

**OWASP MCP Top 10:** `MCP01` through `MCP10`. In `owasp_mcp` field.
Full table: [OWASP_MCP_MAPPING.md](./OWASP_MCP_MAPPING.md)

**NIST AI RMF:** `MAP`, `MEASURE`, `MANAGE`, `GOVERN` functions.
Example values: `MAP-1.5`, `MEASURE-2.5`, `MANAGE-1.3`

**MITRE ATLAS:** Adversarial ML techniques.
Example values: `AML.T0054`, `AML.T0051.000`

---

## 9. Submitting a Record

### Requirements

A valid submission requires:

- A real-world occurrence or a working proof of concept
- The affected component type and at least one affected platform
- CVSS base vector and AIVSS AARF scores with written rationale
- At least two indicators of compromise
- Step-by-step remediation guidance

### Process

**Step 1: Check for existing coverage.**
Search [PiranhaDB](https://api.piranha.bawbel.io/records) and this repository.
If the attack class is already covered, open an issue first.

**Step 2: Fill the template.**
Copy `records/template.json`. Fill every required field.
Validate before submitting:

```bash
pip install bawbel-scanner
bawbel ave-validate ./your-record.json
```

**Step 3: Open a pull request.**
Target the `main` branch. Title: `AVE: [Attack class] - [brief title]`

**Step 4: Review timeline.**

| Stage | Timeline |
|---|---|
| Acknowledgment | 48 hours |
| Technical review | 7 days |
| Publication | 14 days |
| Credit | Permanent |

Every accepted record permanently credits the researcher and is eligible for a
$10 thank-you bounty.

---

## 10. Disclosure Policy

Bawbel follows coordinated disclosure.

**Component publishers:** 90-day notification window before publication.
Critical severity (AIVSS 9.0+): 14-day window. Unresponsive publishers
after 14 days: disclosure proceeds.

**Registry operators:** Notified simultaneously with publishers.

**Community:** All published records are freely accessible in this repository
and via PiranhaDB. No redacted or partial disclosures.

---


---

## Contact

| Purpose | Contact |
|---|---|
| AVE submission | bawbel.io@gmail.com subject: AVE Submission: [title] |
| Critical disclosure | bawbel.io@gmail.com subject: AVE CRITICAL: [title] |
| Schema questions | [github.com/bawbel/ave/issues](https://github.com/bawbel/ave/issues) |

---

*AVE - Agentic Vulnerability Enumeration*
*Maintained by [Bawbel](https://bawbel.io) - Apache License 2.0*