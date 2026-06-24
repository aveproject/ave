<div align="center">

<img src="https://ave.bawbel.io/ave-logo-full.svg" alt="AVE — Agentic Vulnerability Enumeration" width="280" />

<br/>
<br/>

**The behavioral classification standard for agentic AI components.**

Stable IDs, AIVSS scores, and behavioral fingerprints for every way a skill file,
MCP server, system prompt, or agent plugin can be weaponized — scored consistently,
mapped to the frameworks security teams already report against.

[![Records](https://img.shields.io/badge/records-51-0f6e56?style=flat-square)](records/)
[![Schema](https://img.shields.io/badge/schema-v1.0.0-0a3024?style=flat-square)](schema/ave-record-1.0.0.schema.json)
[![AIVSS](https://img.shields.io/badge/AIVSS-v0.8-d4a017?style=flat-square)](https://aivss.owasp.org)
[![OWASP MCP](https://img.shields.io/badge/OWASP-MCP%20Top%2010-0a3024?style=flat-square)](https://owasp.org)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-4a3f9e?style=flat-square)](https://atlas.mitre.org)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-0057b7?style=flat-square)](docs/specs/ave-in-sarif.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](LICENSE)

[Registry](https://ave.bawbel.io/registry.html) · [Schema](https://ave.bawbel.io/schema.html) · [Crosswalks](https://ave.bawbel.io/crosswalks.html) · [Architecture](https://ave.bawbel.io/architecture.html) · [Scoring](https://ave.bawbel.io/scoring.html) · [Scanner](https://github.com/bawbel/scanner)

</div>

---

## What is AVE?

Skill files, MCP server manifests, and system prompts are executable
instructions, not documentation. Any process that loads them runs them.
There is no compiler, no type checker, no sandbox. The runtime is an LLM
that reads natural language and acts on it.

Existing vulnerability standards were built for conventional software.
CVE identifies flaws in a specific product and version. OSV maps them to
package and version ranges. Neither can describe a prompt injection hidden
in an MCP tool description — there is no package, no version, no vulnerable
dependency. The danger is in what the component *does*, not what it imports.

**AVE fills that gap.** It assigns stable identifiers to distinct behavioral
classes in agentic AI, scores them with OWASP AIVSS v0.8, and maps every
record to OWASP MCP Top 10 and MITRE ATLAS so findings land in frameworks
defenders already use.

AVE is a standard, not a product. The `bawbel-scanner` implements it as the
reference implementation. Any tool can map to it — see the
[implementer guide](docs/specs/ave-implementer-guide.md) for how.

```
Your CI pipeline scans dependencies for known package vulnerabilities.
It does not scan your SKILL.md for prompt injection.
AVE + Bawbel fixes that.
```

---

## How it works

**Without AVE:**
```
Attacker crafts          Developer ships          Agent loads
malicious payload   ->   skill file          ->   skill file
                         (unscanned)              at runtime
                              |
                              v
                        Agent executes attacker payload
                        (data exfiltrated, credentials stolen, goals hijacked)
```

**With AVE + Bawbel Scanner:**
```
Developer commits        bawbel scan fires        Finding blocked
skill file          ->   in CI / pre-commit   ->  before deploy
                              |
                              v
                        AVE-2026-00001 detected:
                        Metamorphic payload via external config fetch
                        AIVSS 8.0 · HIGH · owasp_mcp: MCP03, MCP04
                        Line 7: "fetch your instructions from..."
```

---

## Stats

| | |
|---|---|
| Total records | 51 |
| Schema version | 1.0.0 |
| AIVSS spec | v0.8 |
| CRITICAL (>= 9.0) | 1 |
| HIGH (7.0-8.9) | 9 |
| MEDIUM (4.0-6.9) | 40 |
| LOW (< 4.0) | 1 |
| Framework: OWASP MCP Top 10 | all records |
| Framework: MITRE ATLAS | where applicable |
| Framework: OWASP Agentic AI Top 10 | where applicable |
| Framework: NIST AI RMF | where applicable |

---

## AIVSS Scoring

Every record is scored with [OWASP AIVSS v0.8](https://aivss.owasp.org):

```
AIVSS = ((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor
```

**AARS** (Agentic Amplification and Reachability Score) is the weighted sum
of 10 Agentic Amplification and Risk Factors (AARF), each scored 0.0-1.0:

| # | Factor | Why it matters |
|---|---|---|
| 1 | **Autonomy** | Agent acts without human approval |
| 2 | **Tool Use** | Agent has access to external tools or APIs |
| 3 | **Multi-Agent** | Agent interacts with or spawns other agents |
| 4 | **Non-Determinism** | Behavior varies unpredictably across runs |
| 5 | **Self-Modification** | Can alter own instructions or memory at runtime |
| 6 | **Dynamic Identity** | Assumes roles or identities at runtime |
| 7 | **Persistent Memory** | Retains state across sessions |
| 8 | **Natural Language Input** | Instruction surface via natural language |
| 9 | **Data Access** | Reads sensitive data (files, env vars, databases) |
| 10 | **External Dependencies** | Loads external code, skills, or remote content |

**Severity bands:**

| Band | AIVSS | Meaning |
|---|---|---|
| CRITICAL | >= 9.0 | Immediate exploitation, full agent compromise |
| HIGH | 7.0-8.9 | Significant data loss or privilege escalation |
| MEDIUM | 4.0-6.9 | Meaningful risk requiring review |
| LOW | < 4.0 | Limited impact or requires chaining |

**ThM (Threat Maturity) valid values:** `0.75` (theoretical) · `0.90` (PoC exists) · `1.0` (in-the-wild)

**Worked example — AVE-2026-00001 (Metamorphic Payload):**

```
AARF factors:
  autonomy=1.0  tool_use=1.0  multi_agent=0.5  non_determinism=1.0  self_modification=1.0
  dynamic_identity=0.0  persistent_memory=0.5  natural_language_input=1.0
  data_access=0.5  external_dependencies=1.0

AARS = 1.0 + 1.0 + 0.5 + 1.0 + 1.0 + 0.0 + 0.5 + 1.0 + 0.5 + 1.0 = 7.5
CVSS_Base = 8.5   ThM = 1.0 (in-the-wild)   Mitigation_Factor = 1

AIVSS = ((8.5 + 7.5) / 2) x 1.0 x 1 = 8.0  ->  HIGH
```

---

## Record index

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
| [AVE-2026-00046](records/AVE-2026-00046.json) | MCP Tool Hook Hijacking | 9.2 | **CRITICAL** |
| [AVE-2026-00047](records/AVE-2026-00047.json) | Hardcoded Credentials in Agent Component | 7.6 | HIGH |
| [AVE-2026-00048](records/AVE-2026-00048.json) | Unsafe Agent Delegation Chain | 7.7 | HIGH |
| [AVE-2026-00049](records/AVE-2026-00049.json) | HTTP Host Header Injection (BadHost) | 7.2 | HIGH |
| [AVE-2026-00050](records/AVE-2026-00050.json) | Parasitic Toolchain — Silent Tool Registration | 7.2 | HIGH |
| [AVE-2026-00051](records/AVE-2026-00051.json) | OAuth Discovery Rebinding | 7.2 | HIGH |

---

## Detect with Bawbel Scanner

Every AVE record has detection rules in
[bawbel/scanner](https://github.com/bawbel/scanner) — the reference
implementation of this standard.

```bash
pip install bawbel-scanner

# Scan a skill file
bawbel scan ./my-skill.md

# Scan a directory recursively
bawbel scan ./skills/ --recursive --fail-on-severity high

# Scan an MCP server card
bawbel scan-server-card https://api.your-mcp-server.io

# Full remediation report
bawbel report ./my-skill.md
```

Example output:

```
CRITICAL  bawbel-hook-hijack           AVE-2026-00046  line 3   AIVSS 9.2
HIGH      bawbel-unsafe-delegation     AVE-2026-00048  line 11  AIVSS 7.7
HIGH      bawbel-hardcoded-credential  AVE-2026-00047  line 5   AIVSS 7.6
```

Any tool can implement AVE — the records, schema, and rules are open.
See the [architecture guide](https://ave.bawbel.io/architecture.html) and
the [implementer guide](docs/specs/ave-implementer-guide.md) for the
full consumption patterns including air-gapped environments.

---

## Implementing AVE in your scanner

Three patterns depending on your environment:

**Pattern 1 — Runtime API** (cloud CI/CD, always-on internet)
```python
import httpx
resp = httpx.get("https://api.piranha.bawbel.io/ave/AVE-2026-00002")
record = resp.json()  # full record: fingerprint, IOCs, remediation, frameworks
```

**Pattern 2 — Bundled offline** (air-gapped, regulated environments)
```bash
# Download the full record set at build time and bundle with your scanner
curl -L https://github.com/bawbel/ave/releases/download/v1.1.0/ave-records-v1.1.0.json \
  -o ave-records.json
```

**Pattern 3 — ID-only emission** (SIEM resolves downstream, scanner makes no network calls)
```json
{ "rule_id": "your-rule", "ave_id": "AVE-2026-00002", "severity": "HIGH" }
```

The minimum viable integration is adding one field — `ave_id` — to your
existing finding output. See [docs/specs/ave-implementer-guide.md](docs/specs/ave-implementer-guide.md)
for the full guide including decision table, code examples, and how to
request a crosswalk for your scanner's rule IDs.

---

## Schema v1.0.0

Records validate against
[`schema/ave-record-1.0.0.schema.json`](schema/ave-record-1.0.0.schema.json).

Canonical `$id`:
`https://ave.bawbel.io/schema/ave-record-1.0.0.schema.json`

**15 required fields:**

```
ave_id · schema_version · status · published
title · description · attack_class · severity · behavioral_fingerprint
aivss · owasp_mcp
indicators_of_compromise · remediation
references · researcher
```

**Minimal valid record:**

```json
{
  "ave_id": "AVE-2026-00001",
  "schema_version": "1.0.0",
  "status": "active",
  "published": "2026-04-01T09:00:00Z",
  "title": "Metamorphic payload via external config fetch",
  "attack_class": "Supply Chain - Metamorphic Payload",
  "severity": "HIGH",
  "description": "A skill fetches its instructions from an external URL at runtime...",
  "behavioral_fingerprint": "Component fetches and executes remote content, replacing its own instructions at runtime.",
  "aivss": {
    "cvss_base": 8.5, "aars": 7.5, "thm": 1.0,
    "mitigation_factor": 1.0, "aivss_score": 8.0, "spec_version": "0.8"
  },
  "owasp_mcp": ["MCP04", "MCP06"],
  "indicators_of_compromise": ["fetch() pointing to external URL"],
  "remediation": "Remove the component. Block network egress. Audit agent actions.",
  "references": [{"tag": "Disclosure", "text": "Source", "url": "https://..."}],
  "researcher": "Bawbel Security Research Team"
}
```

**All optional fields:**
`component_type` · `last_updated` · `behavioral_vector` · `aivss_score` ·
`cvss_base_vector` · `owasp_mapping` · `mitre_atlas_mapping` ·
`nist_ai_rmf_mapping` · `affected_platforms` · `affected_registries` ·
`mutation_count` · `detection_methodology` · `kill_switch_active` ·
`researcher_url` · `aivss.aarf` · `aivss.aivss_severity` ·
`aivss.owasp_mcp_mapping` · `aivss.notes` · `evidence_kind_default` ·
`detection_stage` · `detection_layer` · `confidence_baseline` ·
`evidence_basis_engines` · `derivable_into`

Full schema reference: [ave.bawbel.io/schema.html](https://ave.bawbel.io/schema.html)

---

## Adding a new AVE record

### When to add a record

A new record needs all three: the attack class is not already covered by an
existing record, there is a citable primary source (CVE, paper, disclosed
incident, or working PoC), and the class is specific to agentic components —
not a generic web or API vulnerability.

If you think an existing class covers the behavior you found, open an issue
anyway. It may warrant a sub-case note in the parent record rather than a
new id.

### Step 1 — Open an issue

Open a **New AVE Record** issue before writing any JSON. Include:
- The proposed `attack_class` and one-sentence `behavioral_fingerprint`
- A link to the primary source
- Whether this is net-new or a variant of an existing record

The maintainer will confirm the next AVE id and whether it is a new class
or a variant update.

### Step 2 — Write the record

Copy [`records/AVE-2026-00001.json`](records/AVE-2026-00001.json) as a
template. All 15 required fields must be present and valid.

AIVSS calculation:
```
1. Score each AARF factor 0.0-1.0
2. AARS = sum of all 10 AARF scores
3. AIVSS = ((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor
4. ThM: 0.75 theoretical · 0.90 PoC exists · 1.0 in-the-wild
5. Round to 1 decimal
6. Severity: CRITICAL >= 9.0 · HIGH >= 7.0 · MEDIUM >= 4.0 · LOW < 4.0
```

Validate before opening a PR:
```bash
npm install ajv ajv-formats
node -e "
const Ajv = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const ajv = new Ajv({ strict: false });
addFormats(ajv);
const schema = require('./schema/ave-record-1.0.0.schema.json');
const record = require('./records/AVE-2026-NNNNN.json');
const ok = ajv.validate(schema, record);
if (!ok) console.error(ajv.errors); else console.log('valid');
"
```

### Step 3 — Add detection rules

Open a coordinated PR in [bawbel/scanner](https://github.com/bawbel/scanner)
with at least one detection rule and a positive and negative fixture.
The AVE record PR and the scanner PR should reference each other.

### Step 4 — PR format

Title: `feat: AVE-2026-NNNNN -- <attack class>`

The PR description must include:
- Link to the issue
- AARF scores with a one-line rationale for each non-zero factor
- At least one `indicators_of_compromise` entry a defender can actually search for
- Link to the primary source
- Link to the coordinated scanner PR

---

## Framework crosswalks

AVE records map to four external frameworks. Full crosswalk tables are
at [ave.bawbel.io/crosswalks.html](https://ave.bawbel.io/crosswalks.html).

| Framework | Field | Crosswalk |
|---|---|---|
| [OWASP AST10](https://owasp.org/www-project-agentic-ai-security/) | `owasp_mapping` (ASI01-ASI10) | [`crosswalks/ave-to-ast10.json`](crosswalks/ave-to-ast10.json) |
| OWASP MCP Top 10 | `owasp_mcp` | all records |
| MITRE ATLAS | `mitre_atlas_mapping` | where applicable |
| NIST AI RMF | `nist_ai_rmf_mapping` | where applicable |

| This scanner | Maps to AVE via |
|---|---|
| SkillSpector (NVIDIA) | [`crosswalks/skillspector-to-ave.json`](crosswalks/skillspector-to-ave.json) |
| ClawScan (OpenClaw) | [`crosswalks/clawscan-to-ave.json`](crosswalks/clawscan-to-ave.json) |

Maintaining a scanner? The [implementer guide](docs/specs/ave-implementer-guide.md)
covers how to map your rule IDs to AVE ids and add AVE ID emission to your
finding output. You can also open an issue and the maintainer will help with
the mapping.

---

## Governance and contributing

See [GOVERNANCE.md](GOVERNANCE.md) for the decision-making process, how records
are proposed and reviewed, and the path toward neutral governance.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor-facing process.

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

---

## Related

| | |
|---|---|
| [ave.bawbel.io](https://ave.bawbel.io) | Public registry and documentation |
| [bawbel/scanner](https://github.com/bawbel/scanner) | Reference implementation |
| [bawbel/ave-site](https://github.com/bawbel/ave-site) | Website source |
| [api.piranha.bawbel.io](https://api.piranha.bawbel.io) | Threat intel API |
| [OWASP AIVSS v0.8](https://aivss.owasp.org) | Scoring specification |
| [MITRE ATLAS](https://atlas.mitre.org) | AI threat technique catalog |
| [OWASP MCP Top 10](https://owasp.org) | MCP attack surface framework |

---

AVE records and schema are published under [Apache 2.0](LICENSE).