# AIVSS scoring reference

AVE scores every record with the equation in OWASP AIVSS v0.8 (sections 3.3 to 3.5 of "AIVSS Scoring System For
OWASP Agentic AI Core Security Risks", https://aivss.owasp.org). Schema 2.0.0 is the first schema that does; schema
1.x used a different equation, described at the end.

```
aars         = (10 - cvss_base) * (factor_sum / 10) * thm
aivss_score  = round_half_up((cvss_base + aars) * mitigation_factor, 1)
```

`factor_sum` is the sum of the ten `aivss.aarf` factors. `aars` is the agentic uplift: the part of the distance from
the CVSS base to 10 that the factors bridge. The score is `cvss_base` plus that uplift, scaled by the mitigation
factor. `scripts/validate_records.py` recomputes `aars` and the score from the record's own inputs, in exact decimal
arithmetic, and `tests/test_aivss_v08.py` reproduces the ten worked examples in OWASP's document.

## The inputs

| Field | OWASP name | Values | Chosen by |
|---|---|---|---|
| `cvss_base` | CVSS_Base | a CVSS v4.0 base score, 0 to 10 | the CVSS v4.0 vector |
| `aarf` | the ten Risk Amplification Factors | each 0, 0.5 or 1 | the rubric below |
| `thm` | Threat Multiplier | 0.5, 0.97 or 1.0 | exploit maturity |
| `mitigation_factor` | Mitigation_Factor | 1.0, 0.83 or 0.67 | mitigation strength |

### cvss_base

CVSS v4.0 is the baseline AIVSS requires; do not use a CVSS v3.1 score (v0.8, section 3.1.1). Put the vector in
`cvss_base_vector` and assess its Subsequent System metrics (SC, SI, SA) honestly: an agent that is compromised
usually reaches other systems, but not every class does.

Under this equation the CVSS base is the floor of the score. The uplift is never negative, so a record never scores
below `cvss_base * mitigation_factor`. That makes the base the input that matters most: an inflated vector inflates
the score by the same amount, and no choice of factors can bring it down.

### The ten factors

Each factor is 0 (not present), 0.5 (partial or limited) or 1 (full or unconstrained). The keys are AVE's; the names
and the rubric are OWASP's (v0.8, section 2.3, Table 2).

| AVE key | OWASP factor | 0 | 0.5 | 1 |
|---|---|---|---|---|
| `autonomy` | Execution Autonomy | human always in the loop | autonomous in non-critical or sandboxed paths only | autonomous commits in production or critical systems |
| `tool_use` | External Tool Control Surface (Tools) | read-only tools, or no external access | mixed read and write, scoped or allowlisted | broad, high-authority tools (cloud, CI/CD, SQL, OT) |
| `natural_language_input` | Natural Language Interface (Language) | structured inputs only | natural language for retrieval or Q&A, not directly executing | natural language prompts directly drive tool execution and planning |
| `context` | Contextual Awareness (Context) | none, operates in a vacuum | narrow signals | broad environmental signals drive autonomous decisions |
| `non_determinism` | Behavioral Non-Determinism | deterministic, rule-based or fixed seed | bounded variance with strict guardrails | high variance, weak guards, probabilistic logic |
| `opacity` | Opacity and Reflexivity (Opacity) | full traceability, deterministic logging | partial or fragmented logs, "black box" reasoning | low visibility, cannot trace why an action was taken |
| `persistent_memory` | Persistent State Retention (Persistence) | none, stateless | ephemeral or session-based memory only | long-term memory persists across sessions |
| `dynamic_identity` | Dynamic Identity (Identity) | fixed identity or service account | limited swaps, scoped per tool | assumes roles or crosses tenant boundaries dynamically |
| `multi_agent` | Multi-Agent Interactions (Multi-Agent) | isolated instance | limited coordination with one or two known agents | complex orchestration, swarms, market-style logic |
| `self_modification` | Self-Modification (Self-Mod) | none, static configuration | can update its own prompts or configuration only | can alter tools, control flow, or generate and execute code |

AVE scores a behavioral class, the way OWASP's own case studies score its Core Risks (section 3.6), so a factor
describes the typical agentic deployment the class acts in. Score every record by the same reading, and do not
inflate a factor to reach a more severe-sounding band: report the computed result and explain it in `aivss.notes`.

The two factors AVE did not score under schema 1.x, Context and Opacity, were assessed for every record when it
moved to 2.0.0, by these rules:

- **Context.** 1: the class acts through broad runtime context (tool results, retrieved or user content, memory,
  history, shared state, several components or agents, a live registry). 0.5: one static source the agent reads
  (a skill file, tool description, server card, agent card, manifest or configuration), or one narrow signal.
  0: the class does not depend on what the agent has read (a defect in server code, transport, configuration or a
  static artifact).
- **Opacity.** 1: the class hides itself, arrives at runtime from outside any reviewed artifact, or breaks
  attribution (concealed, obfuscated, fragmented, remotely supplied, persistent, silent or cross-component). 0.5:
  the attacker's text or setting is readable in a file, description, response or configuration, but why the agent
  acted on it, or where the effect lands, is not evident from logs. 0: a deterministic path visible in code,
  configuration or ordinary logs, with no agent judgment involved.

### thm

The Threat Multiplier follows exploit maturity (v0.8, section 3.3.2, Table 4a):

| `thm` | Maturity | Use when |
|---|---|---|
| 1.0 | Attacked | exploited in the wild, or weaponised |
| 0.97 | Proof-of-Concept | functional exploit code or a detailed walkthrough exists |
| 0.5 | Unreported | no known exploit, theoretical only |

OWASP's default is 0.97, on the argument that natural-language agentic exploits need no compilation and a proof of
concept is a short step from an attack. AVE's evidence bar is stricter: choose from the record's own sources, and say
so in `aivss.notes`. When `mutation_count` rises, the note states the ThM decision, raised or unchanged
(`scripts/check_mutation_thm_trail.py`).

### mitigation_factor

| `mitigation_factor` | Strength | Use when |
|---|---|---|
| 1.0 | No or weak mitigation | mitigations are absent or ineffective. The default |
| 0.83 | Partial | some mitigations exist but are incomplete, not reliably enforceable, or not validated |
| 0.67 | Strong | effective mitigations are in place, validated and enforceable under real conditions |

Do not discount only because a fix is theoretically possible. Every record so far uses 1.0 or 0.83. OWASP calls 0.67
a provisional floor (v0.8, section 3.4.1), so reach for it only with a stated reason.

## Severity bands and rounding

- CRITICAL: 9.0 to 10.0
- HIGH: 7.0 to 8.9
- MEDIUM: 4.0 to 6.9
- LOW: below 4.0

`severity` is the band the score falls in, and `scripts/validate_records.py` fails a record where it is not. The score
is rounded half up to one decimal (9.85 is 9.9, 9.35 is 9.4), as OWASP specifies.

OWASP also advises (section 3.2) that scores are ordinal: do not average them, and read a score by its band, not its
decimal.

## Worked examples

Each is a published record; `python scripts/validate_records.py` checks the arithmetic.

**STDIO transport shell injection, AVE-2026-00060 (CRITICAL, 9.9).** `cvss_base` 9.8, a near-maximum base. Factors:
autonomy 1, tool_use 1, natural_language_input 0.5, everything else 0, so `factor_sum` 2.5. `thm` 1.0,
`mitigation_factor` 1.0. `aars = (10 - 9.8) * (2.5 / 10) * 1.0 = 0.05`, and `(9.8 + 0.05) * 1.0 = 9.85`, which rounds
half up to 9.9. A narrow class with a near-maximum base stays near the top: the base is the floor.

**TLS verification disabled, AVE-2026-00061 (MEDIUM, 6.4).** `cvss_base` 7.5, `factor_sum` 1.0 (autonomy 0.5, tool_use
0.5), `thm` 1.0, `mitigation_factor` 0.83 because a simple, standard fix exists. `aars = (10 - 7.5) * (1.0 / 10) * 1.0
= 0.25`, and `(7.5 + 0.25) * 0.83 = 6.4325`, which rounds to 6.4.

**False authority claim, AVE-2026-00014 (MEDIUM, 6.3).** `cvss_base` 6.5, `factor_sum` 6.5, `thm` 0.5 because the
class is theoretical, `mitigation_factor` 0.83. `aars = (10 - 6.5) * (6.5 / 10) * 0.5 = 1.1375`, and
`(6.5 + 1.1375) * 0.83 = 6.339125`, which rounds to 6.3. Theoretical maturity halves the uplift.

## What schema 1.x did

Schema 1.x computed `round(((cvss_base + aars) / 2) * thm * mitigation_factor, 1)` with `aars` the plain sum of ten
AVE factors (the eight above that correspond to OWASP's, plus `data_access` and `external_dependencies`), `thm` one
of 0.75, 0.90 and 1.0, and Python's `round()`. That is the AIVSS v0.5 equation with the v0.8 Mitigation_Factor added,
not the v0.8 equation (#395). Schema 1.3.0, the catalog release v1.2.0 and `scripts/validate_records.py` for 1.x
records keep it exactly as published. Moving to v0.8 (#399) re-scored every record; each carries a `revisions` entry
with its old and new score and a note in `aivss.notes` saying what was assessed and what the earlier values were.

## Always independently re-verify

Run `python scripts/validate_records.py` before treating a score as final. To check one by hand:

```python
from decimal import Decimal, ROUND_HALF_UP
d = Decimal
cvss, factor_sum, thm, mf = d("9.8"), d("2.5"), d("1.0"), d("1.0")
aars = (10 - cvss) * (factor_sum / 10) * thm
print(aars, ((cvss + aars) * mf).quantize(d("0.1"), ROUND_HALF_UP))   # 0.05 9.9
```
