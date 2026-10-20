# Scoring history

AVE record severity has been produced by two different methodologies. Scores published
before 2026-05-12 are not comparable to scores published after it. This document states
what changed, when, and why, so that anyone holding an older number can tell which
methodology produced it.

## Summary

| | Before | After |
|---|---|---|
| Metric | CVSS-AI (project-defined) | OWASP AIVSS v0.8 |
| Formula | Not published. SPEC.md section 6 described "an extended CVSS 4.0 scoring model" with five agentic dimensions (Agentic Scope, Human Oversight, Tool Access, Persistence, Real-World Action) and gave no way to combine them | `AIVSS = ((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor` |
| Specification | none external | https://aivss.owasp.org |
| Recorded in records as | `cvss_ai_score`, and `cvss_ai_vector` holding a plain CVSS 4.0 vector | `aivss` object with `spec_version: "0.8"`, plus `aivss_score` and `cvss_base_vector` |
| Changed in | #17 (merged to `develop`) and #18 (merged to `main`): the same change, merged to each branch | |
| Effective | 2026-05-12 | |

These are different metrics, not a revision of one metric. A record whose number moved did
not become less dangerous. It is being measured by a different instrument against a
published external specification.

## Why the change was made

CVSS-AI was a scale this project defined for itself. Its formula was never published, so
no other tool could verify a CVSS-AI number, and a reader had to take the score on trust.
The project adopted OWASP AIVSS v0.8 to replace it with an external, published standard
and to align AVE scoring with the OWASP AIVSS specification and its working group. Under
AIVSS every input is stated in the record (`cvss_base`, the ten AARF factors, `aars`,
`thm`, `mitigation_factor`), so anyone can recompute a score and check the arithmetic.

## What changed numerically

45 published records carried a CVSS-AI score before the migration. All 45 are now scored
with AIVSS v0.8. The 25 marked (1) were also printed with their CVSS-AI scores in the
bawbel-scanner v1.0.0 and v1.0.1 release notes.

Before is `cvss_ai_score` in each record at commit 8c50921, the parent of #17. After is
`aivss.aivss_score` in `dist/ave-records-latest.json` at 6b9f174. Pre-migration records had
no `severity` field, so the CVSS-AI band is derived from the score. Both scales use the
same thresholds: CRITICAL >= 9.0, HIGH 7.0-8.9, MEDIUM 4.0-6.9, LOW < 4.0.

| AVE ID | Title | CVSS-AI | AIVSS v0.8 | Band change |
|---|---|---|---|---|
| AVE-2026-00001 | Metamorphic payload via external config fetch | 9.4 CRITICAL | 8.0 HIGH | CRITICAL to HIGH |
| AVE-2026-00002 | MCP tool description behavioral injection | 8.7 HIGH | 7.3 HIGH | none |
| AVE-2026-00003 | Credential exfiltration via agent instruction | 8.5 HIGH | 6.8 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00004 | Arbitrary code execution via shell pipe injection in agentic component | 8.8 HIGH | 5.9 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00005 | Recursive file system destruction via destructive command injection in agentic component | 9.1 CRITICAL | 5.6 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00006 | Cryptocurrency wallet drain via malicious fund transfer instruction in agentic component | 9.6 CRITICAL | 7.5 HIGH | CRITICAL to HIGH |
| AVE-2026-00007 | Agent goal hijack via direct instruction override in agentic component | 8.1 HIGH | 6.1 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00008 | Agent persistence via self-replication instruction in agentic component | 8.4 HIGH | 6.3 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00009 | AI identity jailbreak via role-play or persona override in agentic component | 8.3 HIGH | 5.5 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00010 | Covert instruction concealment via secrecy directive in agentic component | 7.9 HIGH | 5.6 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00011 | Arbitrary tool invocation via dynamic tool call injection in agentic component | 8.2 HIGH | 5.7 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00012 | Capability escalation via false permission grant in agentic component | 7.8 HIGH | 4.5 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00013 | Personal data exfiltration via PII collection and transmission in agentic component | 8.0 HIGH | 6.5 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00014 | False authority claim via trust escalation impersonation in agentic component | 6.5 MEDIUM | 3.7 LOW | MEDIUM to LOW |
| AVE-2026-00015 | System prompt extraction via direct interrogation instruction in agentic component | 6.2 MEDIUM | 4.9 MEDIUM | none |
| AVE-2026-00016 (1) | Indirect Prompt Injection via RAG Retrieval | 8.2 HIGH | 6.4 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00017 (1) | MCP Server Impersonation or Spoofing | 8.6 HIGH | 5.7 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00018 (1) | Tool Result Manipulation or Output Poisoning | 8.1 HIGH | 4.4 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00019 (1) | Agent Memory Poisoning | 9.2 CRITICAL | 5.6 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00020 (1) | Cross-Agent Prompt Injection (A2A) | 8.7 HIGH | 5.9 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00021 (1) | Autonomous Action Without User Confirmation | 8.3 HIGH | 4.5 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00022 (1) | Scope Creep - Accessing Undeclared Resources | 6.8 MEDIUM | 6.0 MEDIUM | none |
| AVE-2026-00023 (1) | Model Context Window Manipulation | 8.0 HIGH | 5.8 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00024 (1) | Supply Chain - Content Type Mismatch (Magika) | 9.5 CRITICAL | 6.8 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00025 (1) | Conversation History Injection | 8.5 HIGH | 4.5 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00026 (1) | Exfiltration via Tool Output Encoding | 9.1 CRITICAL | 6.8 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00027 (1) | Multi-Turn Attack - Instruction Persistence Across Conversations | 8.4 HIGH | 5.6 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00028 (1) | Prompt Injection via File or Document Content | 8.3 HIGH | 5.9 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00029 (1) | Homoglyph or Unicode Obfuscation Attack | 8.0 HIGH | 4.8 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00030 (1) | Privilege Escalation via False Role Claim | 9.0 CRITICAL | 4.3 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00031 (1) | Training Data or Feedback Loop Poisoning | 8.6 HIGH | 5.4 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00032 (1) | Network Reconnaissance Instruction | 8.2 HIGH | 4.0 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00033 (1) | Unsafe Deserialization or Eval Instruction | 9.3 CRITICAL | 4.2 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00034 (1) | Supply Chain - Dynamic Third-Party Skill Import | 9.2 CRITICAL | 6.6 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00035 (1) | Environment or Sensor Data Manipulation | 7.9 HIGH | 4.2 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00036 (1) | Lateral Movement - Pivot to Other Systems | 9.4 CRITICAL | 5.9 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00037 (1) | Prompt Injection via Image or Vision Input | 8.5 HIGH | 5.1 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00038 (1) | Excessive Agency - Unbounded Tool Use or Sub-Agent Spawning | 8.1 HIGH | 5.9 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00039 (1) | Covert Channel - Steganographic Data Exfiltration | 8.3 HIGH | 4.9 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00040 (1) | Insecure Output - Unescaped Injection into Downstream System | 8.2 HIGH | 5.4 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00041 | Prompt injection via MCP server-card tool descriptions before agent makes first call | 9.3 CRITICAL | 8.2 HIGH | CRITICAL to HIGH |
| AVE-2026-00042 | Payload injection into agent-generated orchestration code via poisoned tool results in REPL/Code Mode | 9.1 CRITICAL | 4.7 MEDIUM | CRITICAL to MEDIUM |
| AVE-2026-00043 | Prompt injection via rich UI payload (canvas, artifact, form) rendered by MCP App | 8.4 HIGH | 4.7 MEDIUM | HIGH to MEDIUM |
| AVE-2026-00044 | Prompt injection via poisoned async task result injected into future agent context | 8.6 HIGH | 8.1 HIGH | none |
| AVE-2026-00045 | Privilege escalation via cross-app-access - pivot from low-trust to high-trust MCP server using shared agent session | 9.0 CRITICAL | 6.4 MEDIUM | CRITICAL to MEDIUM |

Aggregate, all 45: mean change -2.75, median -2.80, range -5.1 to -0.5. 41 of 45 changed
severity band. Every change was downward.

The 25 from the release notes: mean change -3.11, median -3.20. 24 of 25 changed band.

The uniform direction is expected. The two scales are not calibrated to each other, and
AIVSS averages a CVSS base against an agentic amplification score rather than compounding
them. A systematic offset between the scales is a property of the change of instrument,
not evidence that any individual record was re-judged.

The new numbers are not the old numbers with one input changed:

- If ThM had been introduced later, the new score would equal the old score x ThM. That
  holds for 1 of the 45 records
- If AARS had been revised down with `cvss_base` held, 36 of the 45 records would need a
  pre-migration AARS above 10.0, up to 21.4. AARS is the sum of ten factors of at most
  1.0 each, so its maximum is 10.0

Reproduce one row:

```bash
git show 8c50921:records/AVE-2026-00019.json \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['cvss_ai_score'])"   # 9.2
python3 -c "
import json
r = {x['ave_id']: x for x in json.load(open('dist/ave-records-latest.json'))}
print(r['AVE-2026-00019']['aivss']['aivss_score'], r['AVE-2026-00019']['severity'])
"                                                                                  # 5.6 MEDIUM
```

## Later corrections

Release 1.1.0 corrected six records, AVE-2026-00046 to AVE-2026-00051, whose AIVSS scores
did not follow the formula or used ThM values outside 0.75, 0.90, and 1.0. That was a
correction within one metric, not a change of metric. It is logged in CHANGELOG.md under
1.1.0, "AIVSS score corrections". Severity bands were unchanged.

## Current distribution

As of 2026-10-20, 87 records (`dist/ave-records-latest.json` at 6b9f174):

```
CRITICAL  1
HIGH     20
MEDIUM   64
LOW       2

AIVSS  mean 5.89  median 5.90  stdev 1.23  range 3.1 to 9.2
```

Reproduce:

```bash
curl -sL https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json \
  -o ave.json
python3 -c "
import json, statistics as st
from collections import Counter
r = json.load(open('ave.json'))
s = [float(x['aivss']['aivss_score']) for x in r]
print(len(r), dict(Counter(x['severity'] for x in r)))
print('mean %.2f median %.2f stdev %.2f range %.1f to %.1f'
      % (st.mean(s), st.median(s), st.pstdev(s), min(s), max(s)))
"
```

## Known property: Threat Maturity drives band assignment

ThM (Threat Maturity) takes three values: 0.75 theoretical, 0.90 PoC exists, 1.0 in the
wild. Across the current 87 records:

```
ThM 0.75   n=25   mean AIVSS 4.94
ThM 0.90   n=13   mean AIVSS 5.75
ThM 1.00   n=49   mean AIVSS 6.41

severity bands as published:    CRITICAL 1 | HIGH 20 | MEDIUM 64 | LOW 2
severity bands if ThM were 1.0: CRITICAL 1 | HIGH 30 | MEDIUM 56
```

ThM places 12 of 87 records a band lower than they would sit at ThM 1.0: 10 that would be
HIGH are MEDIUM, and 2 that would be MEDIUM are LOW. This is intended behavior of the AIVSS
specification and matches how CVSS temporal metrics work, but it has a consequence worth
stating plainly for anyone tracking findings over time:

**25 records currently sit at ThM 0.75. A published proof of concept raises a record's
score by 20 percent (ThM 0.90). Evidence in the wild raises it by 33 percent (ThM 1.0). At
ThM 0.90, 5 of the 25 cross into HIGH. At ThM 1.0, 9 do.** A finding closed today as
MEDIUM can reappear as HIGH without the underlying class changing.

Consumers that need a maturity-independent number for long-term tracking can read
`aivss.cvss_base`, `aivss.aars`, and `aivss.mitigation_factor` from the record and compute
`((cvss_base + aars) / 2) x mitigation_factor` themselves. That is the score with ThM held
at 1.0. Whether to publish it as a field is an open question, below.

## Stability policy

What is immutable:

- `ave_id`. Never renumbered, never reused, never reassigned. A deprecated record keeps its
  id and points at whatever superseded it.

What may change, and under what conditions:

- `aivss.thm` may change when threat maturity changes, which is the field's purpose.
  A ThM change is recorded in the record's `last_updated` and in CHANGELOG.md.
- `aivss.cvss_base` and the `aivss.aarf` factors may change only if a factor was scored
  against stated evidence incorrectly. This is a correction and is logged, as in 1.1.0.
- `aivss.spec_version` changes only on adoption of a new AIVSS specification revision.
  A specification change affecting published scores is recorded in this document, with
  the full before and after table, as above.

Any future change that moves more than five records across a severity band gets an entry
in this document. Silent corpus-wide score movement will not happen again.

## Open questions

- Publish a maturity-independent score alongside `aivss_score`, so governance consumers
  have a stable value to track and a separate value to prioritize by. Tracked in #342.
- The current distribution places 74 percent of records in MEDIUM. Whether that reflects
  the corpus or a property of averaging a low-variance `cvss_base` (mean 8.31, stdev 0.74)
  against AARS is open. Tracked in #343.

## Affected published artifacts

These carry pre-migration CVSS-AI scores and have not been edited, because editing a
published release note rewrites history. They are listed here so a reader who finds one
knows why it disagrees with the registry.

- bawbel-scanner v1.0.0 release notes: https://github.com/bawbel/scanner/releases/tag/v1.0.0
- bawbel-scanner v1.0.1 release notes: https://github.com/bawbel/scanner/releases/tag/v1.0.1

Neither release body is edited. Where the platform allows comments, each gets a comment
linking here.
