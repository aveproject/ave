# AIVSS v0.8 conformance statement for AVE

**Status (2026-11-05): decisions D1 to D12, D15, D16, D18 and D19 are approved by the maintainer (D12 stays conditional on TX4); D13, D14, D17 and D21 are approved as changed; D20 is withdrawn and replaced by an amendment to D1, the table in section 6.1, whose values are initial and adjustable during S03b (section 13).** Step S01 of the plan to conform AVE scoring to OWASP AIVSS v0.8 (#399, issue #446). It is report only: no record, schema file, validator or `dist/` file changes. The one code addition is a standalone arithmetic module, `scripts/aivss_v08.py`, with its tests in `tests/test_aivss_v08.py`; nothing imports it. Nothing here becomes AVE's rule except what section 13 marks approved, and nothing is applied to a record before S02, which waits for this pull request to merge and the public comment period (D18) to open. The pilot that tests this statement is `docs/audits/aivss-v0.8-pilot.md`, with its data in `docs/audits/aivss-v0.8-pilot.json`.

**Date:** 2026-11-04, reread and extended 2026-11-05 (the arithmetic module and its tests, the approvals, D17 to D21). **Repository state:** `develop` at `0753b2d`.

## 1. What this statement is for

OWASP AIVSS v0.8 scores one vulnerability in one deployment. AVE catalogues classes of vulnerability, each defined once and detected many times. A score in an AVE record therefore has to answer a question the specification does not ask: for which deployment? This statement says how AVE answers it, so that two assessors scoring the same class get the same inputs, and so that a record can be exported into OWASP's own report format (Appendix A of the specification).

It covers: the equations and constants (section 3), the CVSS input (4), the class-level assessment rule (5), the ten factors (6), the threat multiplier (7), the mitigation factor (8), rounding and bands (9), the proposed schema 2.0.0 `aivss` object (10), every place the sources differ (11), the deviations and open questions (12), and the decisions the maintainer must make (13).

## 2. Source, and how it was read

- Document: *AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8*, Part 2, `https://aivss.owasp.org/assets/publications/AIVSS%20Scoring%20System%20For%20OWASP%20Agentic%20AI%20Core%20Security%20Risks%20v0.8.pdf`. 98 pages, SHA-256 `a2abbd215f0d7790d273c30a893a09c0dc37a6c109765eb0363c01af897fd9af`. OWASP announced v0.8 on 2026-03-19.
- Read in full, from the PDF text and not from a summary: sections 1 to 4 (including Tables 1 to 5 and the ten worked examples of 3.6), sections 5 to 7, and Appendices A to D. Every section number below was checked against that text.
- Re-derived rather than trusted: for each of the ten worked examples in 3.6, the factor sum, AARS, raw score, rounded score and band; and each example's CVSS v4.0 base score from its vector, with two independent implementations (section 4). All ten agree with the specification.
- Appendix A (the report JSON schema) was transcribed into a JSON Schema file and used as a validator: OWASP's ten examples validate in that shape, and the AVE pilot is exported in it (section 10). Four negative controls (a factor of 0.3, a threat multiplier of 0.9, an unknown category, a missing factor) are refused.

Where a secondary source, a task file or an AVE document differs from the specification, the specification wins and the difference is listed in section 11.

## 3. The equations and constants

| Quantity | Specification | Section | AVE 2.0.0 |
|---|---|---|---|
| Factors | Ten, each 0.0, 0.5 or 1.0: Autonomy, Tools, Language, Context, Non-Determinism, Opacity, Persistence, Identity, Multi-Agent, Self-Mod | 2.1, 2.2, Table 1 | Same ten, same three levels |
| Factor_Sum | Sum of the ten, 0.0 to 10.0 | 3.3.1 | Stored as `factor_sum` |
| Agentic Risk Gap | `10 - CVSS_Base` | 3.3.1 | Same |
| AARS (the uplift) | `(10 - CVSS_Base) x (Factor_Sum / 10) x ThM` | 3.3.1 | Same. Optional intermediate in the specification (3.3.3, 3.5) |
| ThM | Attacked 1.00, Proof-of-Concept 0.97, Unreported 0.50. Default 0.97 | 3.3.2, Table 4a | Same values; see section 7 |
| Primary equation | `AIVSS = (CVSS_Base + AARS) x Mitigation_Factor` | 3.4, 3.4.0 | Same |
| Mitigation_Factor | No/Weak 1.00, Partial 0.83, Strong 0.67. Default 1.0. 0.67 is a provisional floor | 3.4.1, Table 4b | Same values; see section 8 |
| Rounding | `RoundHalfUp(AIVSS_raw, 1)`; 8.64 becomes 8.6, 8.65 becomes 8.7 | 3.4.0, 3.5.1 | Same, in exact decimal arithmetic |
| Bands | Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9 | 3.5.2 | Same; a score below 0.1 has no band |
| CVSS baseline | CVSS v4.0 only; v3.1 scores must not be used | 3.1.1 | Same; see section 4 |
| Reading scores | Ordinal, not interval. Do not average. Read by band, not by decimal | 3.2 | Same; AVE tooling must not average scores |

The score is computed from the unrounded AARS (3.4.0, step 3). AARS has at most five decimal places for every legal input (CVSS to one decimal, Factor_Sum in steps of 0.5, ThM to two decimals; checked by enumerating the whole input grid), so an exact stored AARS needs five places.

**Arithmetic must be exact decimal.** A float product misrounds raw values that are exact ties. Over the full grid (CVSS 0.0 to 10.0 in steps of 0.1, Factor_Sum 0.0 to 10.0 in steps of 0.5, three ThM levels, three mitigation levels: 19,089 inputs) a float implementation rounds 36 results, every one exactly one tenth low, and 2 of those cross a band: for example CVSS 3.9, Factor_Sum 5.0, ThM 1.00, Mitigation_Factor 1.0 has raw score 6.95, which the specification's rule makes 7.0 HIGH and a float product makes 6.9 MEDIUM. `scripts/aivss_v08.py` is the exact implementation. Its tests (`tests/test_aivss_v08.py`) cover OWASP's ten examples, the tie inputs above, the constants, the refusals and the five-decimal bound on AARS, and all 22 mutations of the module that were tried are caught. The excerpt below is its core.

```python
from decimal import Decimal as D, ROUND_HALF_UP
THM = {"attacked": D("1.00"), "poc": D("0.97"), "unreported": D("0.50")}
MITIGATION = {"none": D("1.00"), "partial": D("0.83"), "strong": D("0.67")}
BANDS = (("CRITICAL", D("9.0")), ("HIGH", D("7.0")), ("MEDIUM", D("4.0")), ("LOW", D("0.1")))

def aars(cvss_base, factor_sum, thm):          # 3.3.1, exact
    return (10 - D(str(cvss_base))) * (D(str(factor_sum)) / 10) * THM[thm]

def aivss(cvss_base, factor_sum, thm, mitigation):   # 3.4.0 steps 1 to 4
    raw = (D(str(cvss_base)) + aars(cvss_base, factor_sum, thm)) * MITIGATION[mitigation]
    return raw.quantize(D("0.1"), rounding=ROUND_HALF_UP)

def band(score):                               # 3.5.2; below 0.1 the specification defines no band
    for name, floor in BANDS:
        if score >= floor:
            return name
    raise ValueError("no band below 0.1")
```

## 4. How `cvss_base` is determined

v0.8 takes a CVSS v4.0 base score as input (3.1.1). The audit in `docs/audits/cvss-input-reconciliation.md` (S00, #403) found that the stored `cvss_base` equals the score of the record's own vector for 3 of 88 valid vectors, and that one vector (AVE-2026-00066) is not valid CVSS v4.0. Because v0.8 adds the uplift to the base, the base is the floor of the score (section 5.4). This statement therefore makes the vector the input and the number a derived value. Decision D17 sets the policy for choosing among sources for a vector and for the subsequent-system metrics.

1. **The vector is authoritative.** `cvss_base_vector` is the assessment; `aivss.cvss_base` is the score computed from it. A validator rule recomputes it and fails on a mismatch.
2. **Base metrics only.** The vector carries the eleven base metrics. Threat (`E`) and environmental metrics are not used: exploit maturity is already ThM, and counting it in both would count it twice. The specification's own examples are base vectors (3.6).
3. **Two named implementations**, pinned in the development requirements, and a test that fails if they disagree on any record: the Red Hat Product Security `cvss` Python library (3.6 used here) and the scoring files of FIRST's `FIRSTdotorg/cvss-v4-calculator` at commit `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a`, run unchanged in a context with no file, network or DOM access. They agreed on all 88 valid vectors in S00. In this work they also agree on the three reference vectors (9.3, 10.0, 0.0), on the ten vectors of OWASP's examples (each equals the base the specification states), and on all ten vectors derived for the pilot.
4. **How a class's vector is derived.** Start from the vector OWASP gives for the nearest Core Risk in 3.6 and change a metric only where the class's description or sources state a difference, writing the reason. The metric rules:

| Metric | Rule for a class |
|---|---|
| AV | `N` when the attacker's input reaches the agent over a network or registry. `L` only when the class needs a file placed by someone with local access |
| AC | `L` unless the class's text says the attacker must defeat an existing defence or meet a hard-to-meet condition |
| AT | `P` only for a deployment precondition the class names that is not part of its own mechanism (for example, the product uses async task queues). The model following the injected content is the mechanism and is scored in Non-Determinism, so it is `N` |
| PR | `N` unless the text says the attacker needs an account on the vulnerable system |
| UI | `A` when the victim must knowingly install, enable or approve something the attacker supplied for the class to apply. `P` when the victim only uses the product normally (opens a repository, asks an ordinary question). `N` when no victim action is needed |
| VC, VI, VA | The agent runtime and its host. `H` when the class lets the attacker cause the outcome in full without a further vulnerability, `L` when only partially or for a subset, `N` when the described mechanism does not |
| SC, SI, SA | `H` when the class's mechanism, as described, causes impact outside the vulnerable system's security domain at the reasonable worst case for the reference deployment profile (decision D17, part 4). Propagation that needs further steps beyond the class is not counted. Tool reach is counted once, in Tools (D2) |

The AV, AC, AT, PR and UI rows are the pilot's working rules. Decision D17 part 2 (the reasonable worst case) may change them, and S03a settles them.

The specification's wording on subsequent systems (3.1.1: assess them "based on the full scope of systems the compromised agent can reach through its tool access, delegation chains, and inter-agent communication paths") can be read literally, and then every class that steers an agent with default tools gets `SC:H/SI:H`, as in OWASP's 3.6.1. OWASP's other nine examples do not do that: they set subsequent impacts only where the scenario states propagation (cascade, orchestration, connected internal tools). FIRST's own guidance puts the line at the security domain: a vulnerability in a component serving "components in a different security domain" has Subsequent System impact, and one confined to a shared security scope does not (CVSS v4.0 User Guide, guidance on the Vulnerable System and Subsequent System). Decisions D2 and D17 set AVE's rule on that basis. The pilot's vectors were derived earlier, under "the class states propagation", and are not re-derived here; S03a re-derives them under D17.

## 5. The class-level assessment rule

### 5.1 The problem

Section 3.6 scores ten scenarios. Each is a deployment: "an externally available agent ... possessing high autonomy and access to internal code generation tools" (3.6.1), "a central orchestration agent" (3.6.4), "a water treatment agent" (3.6.7). Its factors describe that deployment. A catalogue entry has no scenario of its own, so something must stand in for it.

### 5.2 What OWASP's own examples show

| Section | Core Risk | Aut | Tools | Lang | Ctx | NonD | Opac | Pers | Ident | Multi | SelfM | Sum | CVSS | AIVSS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 3.6.1 | Agentic AI Tool Misuse | 1 | 1 | 1 | 1 | 1 | 1 | 0.5 | 1 | 1 | 0.5 | 9.0 | 9.4 | 9.9 |
| 3.6.2 | Agent Access Control Violation | 1 | 1 | 1 | 1 | 0.5 | 1 | 1 | 1 | 0.5 | 0 | 8.0 | 8.7 | 9.7 |
| 3.6.3 | Agent Cascading Failures | 1 | 0.5 | 1 | 1 | 1 | 1 | 0.5 | 0.5 | 1 | 0.5 | 8.0 | 7.1 | 9.4 |
| 3.6.4 | Agent Orchestration and Multi-Agent Exploitation | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0.5 | 9.5 | 9.4 | 10.0 |
| 3.6.5 | Agent Identity Impersonation | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0.5 | 0 | 7.5 | 7.4 | 9.3 |
| 3.6.6 | Agent Memory and Context Manipulation | 1 | 0.5 | 1 | 1 | 0.5 | 1 | 1 | 0 | 0.5 | 1 | 7.5 | 5.8 | 8.9 |
| 3.6.7 | Insecure Agent Critical Systems Interaction | 1 | 1 | 0.5 | 1 | 0.5 | 1 | 0.5 | 0 | 1 | 1 | 7.5 | 6.9 | 9.2 |
| 3.6.8 | Agent Supply Chain and Dependency Risk | 1 | 1 | 0 | 0 | 1 | 1 | 0.5 | 1 | 1 | 0 | 6.5 | 9.3 | 9.7 |
| 3.6.9 | Agent Untraceability | 1 | 1 | 0 | 0 | 1 | 1 | 0.5 | 0.5 | 1 | 0.5 | 6.5 | 5.3 | 8.3 |
| 3.6.10 | Agent Goal and Instruction Manipulation | 0.5 | 0 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 6.5 | 2.1 | 7.1 |

All ten use ThM 0.97 and Mitigation_Factor 1.0 (3.6, introduction). What they show:

- **Factor sums run from 6.5 to 9.5 (mean 7.65).** No example is below 6.5. All ten land HIGH or CRITICAL, including a CVSS 2.1 that becomes 7.1 (3.7 says this is the intended behaviour).
- **Autonomy is 1.0 in nine, Opacity 1.0 in all ten, Language 1.0 in seven, Context 1.0 in eight.** The deployment-dependent factors sit at or near the top because the scenarios are chosen to have them.
- **Mechanism factors follow the mechanism, not the deployment.** Language is 0 for supply chain and untraceability because "the attack is code-level; natural language plays no role" (3.6.8, 3.6.9). Context is 0 where the attack is "triggered at import time with no context dependency". Persistence is 0 for a single deepfake interaction (3.6.5). So the examples are scenario-specific, not worst case: Tools is 0.5 for cascading failures and memory manipulation, 0 for goal manipulation.
- **Subsequent-system impacts are set only where the scenario propagates** (3.6.1, 3.6.3, 3.6.4); in the other seven they are all `N`.
- **One internal inconsistency.** 3.6.8 scores Identity 1.0 because "the attacker inherits the agent's full system identity", but Table 2 defines Identity as runtime role or identity change (0.0 for a fixed identity or service account). AVE follows Table 2 (section 12, U4).

### 5.3 The rule

*Amended 2026-11-05 (D1): the four deployment factors take the values in the table in section 6.1, one column per component type. Items 2 and 3 describe what that table is for.*

1. **Reference deployment profile (RDP).** A class is assessed as deployed this way: one agent of the kind the record's `component_type` names (skill, mcp_server, agent), operated by one user, with the tools and permissions its ecosystem grants by default, with its ecosystem's default confirmation behaviour, and with no hardening beyond those defaults. A multi-agent deployment applies only to a class whose mechanism is multi-agent. Hardening is credited once, in Mitigation_Factor, and never inside the factors.
2. **Two kinds of factor.** *Mechanism factors* (Language, Context, Persistence, Identity, Multi-Agent, Self-Mod) are taken from what the class does, as its description and fingerprint state it, whatever the deployment. *Deployment factors* (Autonomy, Tools, Non-Determinism, Opacity) are taken from the RDP. Table 6 in section 6 says what each level means for each factor.
3. **Typical, not worst case.** Deployment factors take the value that is typical for the component type as shipped. Worst case is not used for three reasons. OWASP's own examples are not worst case. A worst-case rule would set the four deployment factors to 1.0 for nearly every class and remove the factors' power to tell a broad class from a narrow one. And "typical as shipped" can be checked by a second assessor, whereas "worst imaginable" cannot. The section 6.1 table follows this for Autonomy and Tools, which differ by component type, but sets Non-Determinism and Opacity at 1.0 in every column, because each column describes the LLM-driven agent that uses the component and OWASP scores Opacity 1.0 in all ten of its examples (amended 2026-11-05).
4. **Calibration anchors.** Each class is compared with the nearest Core Risk in 3.6 (Table 3 lists each Core Risk's high-impact factors). Copy that example's factor vector, then change a factor only for a reason written from the class's description or sources. The anchor is recorded (section 10, `core_risk`; Appendix A requires an `owasp_category`). Where no Core Risk fits well, say so. In the pilot the anchor was weak for AVE-2026-00039 and 00058.
5. **Evidence is stated for every non-zero factor**: one line, citing the record's description, fingerprint or a reference. A factor with no stated basis is 0.0 (no inflation without a reason, the same discipline as the existing "do not inflate" rule in `references/aivss-scoring.md`).
6. **Do not force a band.** The honest computed result is reported. Where it feels wrong, the notes say so, and the inputs are not adjusted.

### 5.4 What the rule cannot do

Because v0.8 adds the uplift to the CVSS base, the base is a floor. With OWASP's factor sums the floor is high:

| Factor_Sum | Score at CVSS 2.0 | 4.0 | 6.0 | 8.0 | Lowest base that scores HIGH | Lowest base that scores CRITICAL |
|---|---|---|---|---|---|---|
| 2.5 | 3.9 | 5.5 | 7.0 | 8.5 | 6.0 | 8.7 |
| 3.5 | 4.7 | 6.0 | 7.4 | 8.7 | 5.4 | 8.5 |
| 5.0 | 5.9 | 6.9 | 7.9 | 9.0 | 4.1 | 8.0 |
| 6.5 | 7.0 | 7.8 | 8.5 | 9.3 | 1.8 | 7.2 |
| 8.0 | 8.2 | 8.7 | 9.1 | 9.6 | 0.0 | 5.4 |
| 9.5 | 9.4 | 9.5 | 9.7 | 9.8 | 0.0 | 0.0 |

(ThM 0.97, Mitigation_Factor 1.0.) At OWASP's lowest sum, a class is HIGH from a base of 1.8. The only things that keep a class with a high base out of HIGH or CRITICAL are a low Factor_Sum and a Mitigation_Factor below 1. For the corpus this means the CVSS vectors, not the factors, decide most of the severity distribution (decisions D14 and D17).

## 6. The ten factors for a catalogue entry

Adapted from Table 2. "Mechanism" factors come from the class; "deployment" factors come from the RDP.

| Factor | Kind | 0.0 | 0.5 | 1.0 |
|---|---|---|---|---|
| 1 Autonomy | Deployment | A human performs or approves the harmful step every time | The step runs unattended only in non-critical or sandboxed paths, or behind a confirmation users routinely accept | The step is committed without a human co-sign in the RDP, or the class itself removes the co-sign |
| 2 Tools | Deployment | The exploit path needs no tool, or read-only tools only | Mixed read and write tools, scoped or allowlisted | The exploit path uses or reaches broad, high-authority tools (shell, filesystem write, cloud, CI/CD, SQL, network egress) |
| 3 Language | Mechanism | Structural mechanism (configuration, bytes, protocol); no natural-language step | Natural language is used for retrieval, description or question answering but does not itself drive tool execution in the exploit | Natural-language content (instruction, description, result) directly drives tool selection, execution or planning in the exploit |
| 4 Context | Mechanism | The exploit is independent of what the agent has read or sensed | One narrow or static source (a manifest, a configuration, one declared input) | Broad runtime content carries the exploit: tool results, retrieved or user content, memory, history, shared state, several components |
| 5 Non-Determinism | Deployment | Deterministic once triggered (rule-based or fixed) | Variance bounded by explicit rules or strict guardrails | An LLM-driven step with weak guardrails, whose outcome varies run to run |
| 6 Opacity | Mechanism and deployment | The effect is traceable end to end in logs or a reviewable artifact | An artifact or log exists, but why the agent acted is a black box | The effect cannot be traced to its cause, or is built to evade review (hidden from scanners, no audit signal) |
| 7 Persistence | Mechanism | Stateless | Session state only, or an artifact that persists outside the agent's own memory (an installed component, a committed configuration, remote content fetched each session) | The agent's own memory or retained state carries the effect across sessions (a memory store, retained credentials) |
| 8 Identity | Mechanism | One fixed identity or service account on the exploit path | Limited identity change (scoped to one tool), or a claim of identity within a scope | The exploit assumes roles or crosses tenant boundaries dynamically |
| 9 Multi-Agent | Mechanism | One isolated instance | Limited coordination with one or two known agents or services | Orchestration or swarm patterns are the exploit's path |
| 10 Self-Mod | Mechanism | None | Can change its own prompts or configuration only | Can alter tools, control flow, or generate and execute code |

Three clarifications were made while piloting, and the pilot lists where they applied: Persistence (1.0 only for the agent's own state, consistent with OWASP's 3.6.2 against 3.6.8), Context (the rule PR #401 also used), and Self-Mod for a single injected instruction (0.5, as in 3.6.1; 1.0 only for repeated goal conditioning, as in 3.6.10).

### 6.1 Deployment-factor values per component type (amendment to D1)

D1 takes the four deployment factors (Autonomy, Tools, Non-Determinism, Opacity) from the reference deployment and not from the class. They are published here, one column per `component_type`, so that every record of a type starts from the same four numbers and a second assessor checks them against one table. Each column describes the agent that uses the component, as D1's reference profile does. **These are initial values. The maintainer reviewed and revised them on 2026-11-05, and they are adjustable during S03b.** An adjustment is recorded with its reason and its effect on the bands, because it moves every record of that component type.

| Factor | skill | mcp_server | agent |
|---|---|---|---|
| Autonomy | 1.0 | 0.5 | 1.0 |
| Tools | 1.0 | 0.5 | 1.0 |
| Non-Determinism | 1.0 | 1.0 | 1.0 |
| Opacity | 1.0 | 1.0 | 1.0 |

Basis, from Table 2 and OWASP's examples:

- **Autonomy.** skill 1.0: the host agent executes the skill's instructions and tools without a per-step human co-sign once the skill is enabled. mcp_server 0.5: the client normally asks before a tool call or a server's first use, a confirmation users routinely accept. agent 1.0: it acts on its own plan (nine of OWASP's ten examples score 1.0).
- **Tools.** skill 1.0: a skill reaches the host agent's tools (shell, filesystem, network). mcp_server 0.5: it exposes its own tool set, mixed read and write and scoped to the server. agent 1.0: broad, high-authority tools.
- **Non-Determinism, 1.0 in all three columns.** Each column describes the agent that uses the component, and that agent's LLM interprets its inputs with no hard guardrail. A deterministic server does not make the agent that calls it deterministic. OWASP scores Non-Determinism 1.0 in seven of its ten examples and 0.5 in three, and 0 in none. (An earlier draft gave mcp_server 0.0 because server code is deterministic; that is withdrawn.)
- **Opacity, 1.0 in all three columns.** Why the agent acted is not traceable, and OWASP scores Opacity 1.0 in all ten examples. (An earlier draft gave skill and mcp_server 0.5 because the artifact is readable and reviewable. That reading concerns the artifact and not the agent, and no departure from OWASP's practice is justified here, so none is made.)

Two of the four values are now the same in every column, so the columns differ only in Autonomy and Tools, and only for `mcp_server`.

Eight records have no column: AVE-2026-00016 (`other`), 00054 (`tool`), and 00081, 00083, 00084, 00085, 00086 and 00087 (no `component_type`). In S03b each is assigned to the nearest of the three types, with the reason stated in the record's notes. No new columns are added.

Effect on the pilot: replacing the four factors by the table's values, with the pilot's six mechanism factors kept, changes the band of one of the ten records. AVE-2026-00063 goes from 6.7 MEDIUM to 7.0 HIGH, exactly on the boundary. Scores rise by 0.0 to 0.5 and Factor_Sum by 0.0 to 2.0, never down, because the table sets Non-Determinism and Opacity at the top for every record. The change for 00063 is the cost of fixing the deployment factors per type: the pilot scored it Non-Determinism 0 (a deterministic configuration flag) and Opacity 0.5. Limits: the pilot has 9 skills, 1 `mcp_server` and no `agent`, so the `agent` column is tested by nothing and the `mcp_server` column by one record, and no value was checked against any product's default behaviour.

AVE's current factors map as follows (they were assigned against AVE's own definitions, not Table 2): `autonomy`, `non_determinism` and `multi_agent` keep their names; `tool_use` is Tools; `natural_language_input` is Language; `persistent_memory` is Persistence; `dynamic_identity` is Identity; `self_modification` is Self-Mod; `data_access` and `external_dependencies` have no counterpart; Context and Opacity are new. Carrying the eight over by value would carry definitions that differ from Table 2 (this is why the S01 plan says not to).

## 7. The threat multiplier

| Tier | Specification (Table 4a) | Evidence an AVE record must cite |
|---|---|---|
| Attacked, 1.00 | "Vulnerability is being actively exploited in the wild" | A primary source documenting exploitation outside a research setting: an incident report, an advisory that states exploitation, a vendor confirmation |
| Proof-of-Concept, 0.97 | "Functional exploit code or detailed walkthrough exists" | A primary source with exploit code, a reproduction, or a detailed walkthrough of this class's mechanism: a paper that demonstrates it, an advisory with reproduction steps |
| Unreported, 0.50 | "No known exploit; theoretical vulnerability only" | The cited sources only classify or describe the weakness (a taxonomy page, a CWE, a standard) and none demonstrates it |

The specification's default is 0.97 and argues that for agentic exploits the distance from proof of concept to attack is negligible (3.3.2). AVE therefore uses PoC when the evidence tier cannot be told apart, and records the tier and its source in the notes.

**What happens to today's `thm` (1, 0.9, 0.75).** The plan in #399 maps them by definition (0.75 to Unreported, 0.9 to PoC, 1.0 to Attacked). That is wrong for 1.0, because AVE's own documents define it two ways. `CONTRIBUTING.md` says 1.0 is "exploited in the wild or weaponised". `references/aivss-scoring.md` says 1 is "real and demonstrated (a disclosed CVE, published research, a working exploit description)" and that "every record in this corpus so far has scored 1". In the pilot, mapping by value agrees with the tier the cited evidence supports for **4 of the 10 pilot records** (00039, 00044, 00058, 00066). The ten are not a sample of the 89, so no corpus rate follows: 49 of the 89 records are stored at 1.0, and only the five of those in the pilot were checked against their sources. Of those five, one cites an in-the-wild source (AVE-2026-00044); two are PoC; two cite nothing that demonstrates the class (and AVE-2026-00046's writeup says its 1.0 "reflects ... an in-the-wild threat maturity" while the record cites no incident). Two of the four stored at 0.75 are demonstrated in cited research and are PoC. This is decision D3.

## 8. The mitigation factor

| Level | Specification (Table 4b) | Rule for a class |
|---|---|---|
| None / Weak, 1.00 | Mitigations absent or ineffective | No mitigation that is effective, validated and enforceable exists in the RDP as shipped. Advice in the record's `remediation` alone is not a mitigation |
| Partial, 0.83 | Some mitigations exist, but they are incomplete, not reliably enforceable, or not validated against realistic misuse | A mitigation exists and is in use (a vendor fix for the nearest instance, a scanner that flags the class) but does not cover the class, is off by default, or has not been validated |
| Strong, 0.67 | Effective, validated, consistently enforceable under real operating conditions, fail-closed where applicable | Default-on in the RDP, with a cited validation. A class is by definition a missing control, so Strong should be rare |

AVE's current 0.83 is defined differently ("a simple, well-known, standard mitigation exists and is reasonably expected to be applied"), but the values and the groups of records line up: in the pilot, carrying 1.0 to None and 0.83 to Partial agrees with an assessment against Table 4b for 10 of 10 records (decision D4). The specification calls the 0.67 floor "a provisional anchor ... subject to empirical calibration" (3.4.1); it may change in a later version.

## 9. Rounding and bands

Half up, to one decimal, on the unrounded product (3.4.0, 3.5.1). Bands as in 3.5.2. A score below 0.1 has no band in the specification, so the validator rejects it instead of assigning one; in practice no class reaches it, because a class with any impact has a CVSS base well above 0 and the uplift only adds. The record's `severity` is the band in AVE's upper-case spelling and must agree with `aivss.aivss_score` (CLAUDE.md hard rule 6); Appendix A's `severity` is title case, a mapping done at export. The legacy rounding (Python `round()` on a float, ties to even) stays in the frozen 1.x records and is not used for 2.0.0.

## 10. The schema 2.0.0 `aivss` object

Appendix A defines the report format OWASP uses: per finding, `id`, `title`, `description`, `owasp_category`, `cvss_base {vector_string, score}`, `amplification_factors` (ten keys), `threat_multiplier`, and `scores {factor_sum, aars, mitigation_factor, aivss, severity}`. The AVE object is aligned with it where that costs nothing and departs from it where an AVE record needs something else.

```json
"aivss": {
  "spec_version": "0.8",
  "cvss_base": 9.3,
  "aarf": {
    "autonomy": 1.0, "tools": 1.0, "language": 1.0, "context": 1.0, "non_determinism": 0.5,
    "opacity": 1.0, "persistence": 0.5, "identity": 0.0, "multi_agent": 0.0, "self_mod": 1.0
  },
  "factor_sum": 7.0,
  "threat_maturity": "poc",
  "thm": 0.97,
  "aars": 0.47530,
  "mitigation": "none",
  "mitigation_factor": 1.0,
  "aivss_score": 9.8,
  "aivss_severity": "CRITICAL",
  "core_risk": "Agent Supply Chain & Dependency Risk",
  "notes": "..."
}
```

(The values are the pilot's for AVE-2026-00001.)

| AVE field | Appendix A field | Rule and departure |
|---|---|---|
| `cvss_base_vector` (record level, unchanged) | `cvss_base.vector_string` | Kept at record level: it is an existing field that consumers read. The exporter nests it |
| `aivss.cvss_base` | `cvss_base.score` | Derived from the vector (section 4); the validator checks equality |
| `aivss.aarf` with Appendix A's ten key names | `amplification_factors` | The inner keys follow Appendix A (`tools`, `language`, `persistence`, `identity`, `self_mod` replace five AVE names), so the object exports without a mapping table. The container keeps AVE's name `aarf`: the specification never uses that word (it does not occur in v0.8; it is a v0.5-era term), but renaming a container is a second break for readers of `aivss.aarf` on top of the changes in its content (D5) |
| `aivss.factor_sum` | `scores.factor_sum` | Stored, validated |
| `aivss.threat_maturity` and derived `aivss.thm` | `threat_multiplier` | Appendix A stores only the number. AVE stores the tier an assessor decides (`attacked`, `poc`, `unreported`) and the number it implies, and the validator checks they agree |
| `aivss.aars` | `scores.aars` | The uplift, up to five decimals, exact. This is a different meaning from today's `aars` (a factor sum), which is why 2.0.0 is a major version. The specification makes AARS optional (3.3.3, 3.5) and Appendix A makes it required; AVE stores it |
| `aivss.mitigation` and derived `aivss.mitigation_factor` | `scores.mitigation_factor` | As for the threat multiplier |
| `aivss.aivss_score` | `scores.aivss` | Name kept (existing field) |
| `aivss.aivss_severity` | `scores.severity` | Upper case (existing), title-cased on export |
| `aivss.core_risk` (new, optional) | `owasp_category` | The nearest Core Risk, the calibration anchor, one of Appendix A's ten names. Appendix A requires it, so an AVE record cannot be exported without it (D8) |
| `ave_id`, `title`, `description` (record level) | `id`, `title`, `description` | Mapped on export |
| `aivss.spec_version` | none | Kept, and no longer a constant: it names the specification the numbers follow (D13) |
| `aivss.notes` | `metadata.notes` | Kept |

The exporter is not part of this work. The pilot data file shows the export is possible: the ten pilot records are written in Appendix A shape and validate against the transcribed schema.

The validator for 2.0.0 should recompute and compare: the CVSS vector is valid v4.0; `cvss_base` equals its score under the two named implementations; every factor is 0.0, 0.5 or 1.0 and all ten are present; `factor_sum`; `thm` and `mitigation_factor` against their level names; `aars` exactly; `aivss_score` exactly; the band and the record's `severity`.

## 11. Where the sources differ

I found no difference between the specification and #395's reading of it. The differences are in the S01 task file, in AVE's documents, and in the draft PR.

| # | Source | It says | The specification says | What was done |
|---|---|---|---|---|
| 1 | S01 task, `test_published_worked_example` | A "published worked example": CVSS 6.0, Factor_Sum 7.0, PoC, partial mitigation, AARS 2.716, AIVSS 7.2 | There is no such example. The only worked examples are the ten in 3.6, all with ThM 0.97 and Mitigation_Factor 1.0. The arithmetic of the task's example is right (2.716; 7.234 rounds to 7.2) | Test renamed. Consequence: no published example exercises ThM 1.00 or 0.50, or Mitigation_Factor 0.83 or 0.67, so those paths rest on the equation text alone |
| 2 | S01 task, `aivss_v08.score` | Float arithmetic | Round half up: "8.65 becomes 8.7" (3.5.1) | 36 of 19,089 grid inputs misround and 2 cross a band (section 3). Corrected to exact decimal; tests added for four tie inputs |
| 3 | S01 task, `BANDS` and `band(0.0) == "LOW"` | Low floor 0.0 | Low is 0.1 to 3.9 (3.5.2); 0.0 has no band | Floor set to 0.1; `band(0.0)` raises; test changed |
| 4 | S01 task, factor key names | `tools`, `language`, `persistence`, `identity`, `self_mod` | Same as Appendix A | Kept |
| 5 | `CONTRIBUTING.md` ("AIVSS v0.8 calculation"), `references/aivss-scoring.md`, `docs/specs/researcher-process.md` Step 5, `check_aivss_arithmetic` | `((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor` with AARS a factor sum | `(CVSS_Base + AARS) x Mitigation_Factor` with AARS an uplift (3.3.1, 3.4) | Known since #395; changes with 2.0.0 |
| 6 | `CONTRIBUTING.md` and `references/aivss-scoring.md` on `thm` | Two definitions of 1.0 (in the wild; demonstrated) | Table 4a | Section 7 |
| 7 | #399 | `cvss_base` is kept as the record states it; no catalog v1.3.0 | S00 shows the stored base differs from its vector for 85 of 88 valid vectors; the plan since decided v1.3.0 | #399's text is out of date on both and should be updated |
| 8 | Draft PR #401 | See below | | See below |
| 9 | The specification itself | Section 2.2: the factors "are listed in the exact order required for the calculation vector in Section 3" | Section 3 defines no vector string | Not a deviation; no vector format is proposed (U2) |
| 10 | The specification itself | Appendix D refers to "the scoring methodology described in Sections 4.1 to 4.8" | The methodology is Section 3; Section 4 has only 4.1 and 4.2 | Harmless dangling reference |
| 11 | The specification itself | 3.3.3 and 3.5: AARS "may be recorded", not the primary output | Appendix A requires `scores.aars` | AVE stores it |
| 12 | The specification itself | 3.6.8 scores Identity 1.0 for "inherits the agent's full system identity" | Table 2 defines Identity as role or identity change | AVE follows Table 2 (U4) |

**Draft PR #401 (labelled design; seed material only).** Its claim to reproduce OWASP's ten worked examples holds. Its table of the ten (CVSS base, Factor_Sum, AARS, score) equals my transcription of the specification, its `aivss_v08` function reproduces all ten, and it agrees with exact decimal arithmetic on all 19,089 grid inputs. Its tests use only the base and the sum, so they do not check the vectors or the factor values; those were verified here separately. Its ThM values (0.5, 0.97, 1), Mitigation_Factor values (0.67, 0.83, 1), equations and rounding are the same as this file's. The differences:

- **Factor keys.** It keeps AVE's eight names (`tool_use`, `natural_language_input`, `persistent_memory`, `dynamic_identity`, `self_modification` and three unchanged) and adds `context` and `opacity`. This statement uses Appendix A's names (D5). It carried eight factors over by value and kept the stored `cvss_base`; both contradict this plan.
- **Band floor.** Its validator keeps LOW at 0.0; the specification says 0.1.
- **AARS storage.** It stores AARS to four decimals and compares within half a unit of the fourth place; an exact AARS can have five (2.74995 in its own test), which is why it needs a tolerance.
- **`spec_version`** stays a constant `"0.8"`; the threat and mitigation levels are not stored, only their numbers.
- **The branch** is 31 commits behind `develop` (it lacks, for example, `tests/test_ave_conformance.py`), so its diff against `develop` shows deletions that are not its own; it needs a rebase before any reuse.

## 12. Deviations from the specification, and open questions

**Deviations: none intended.** Every constant, equation, rounding rule and band in section 3 is the specification's. AVE adds only what the specification leaves to the assessor: how to assess a class (section 5), what evidence supports a tier (7, 8), and which optional values to record (10).

**Unresolved, to be settled with the decisions in section 13:**

- **U1.** The specification gives no default for a factor (only for ThM and Mitigation_Factor). AVE's rule is that a factor with no stated basis is 0.0 (5.3, item 5).
- **U2.** "The calculation vector in Section 3" (2.2) is not defined. No vector string is proposed.
- **U3.** A score under 0.1 has no band (3.5.2); AVE rejects it.
- **U4.** Identity: Table 2 against the rationale in 3.6.8. AVE follows Table 2.
- **U5.** Whether CVSS v4.0 threat metrics may be in the base: the specification says "the CVSS v4.0 score of the vulnerability" and its examples are base vectors. AVE uses base metrics only.
- **U6.** The 0.67 floor is provisional (3.4.1) and may change in a later version of the specification.
- **U7.** Whether a class-level score has the meaning the specification gives a deployment-level score. AVE's position: a class score is the score of the class assessed in the RDP, and it is a reference point, not a finding in anyone's deployment.
- **U8.** The status of the AIVSS 1.0 candidate (D13).

## 13. Decision list for the maintainer

Each item has a recommendation. None is applied until approved in writing. Status as of 2026-11-05:

| Decision | Status |
|---|---|
| D1 to D11, D15, D16, D18 | Approved as recommended |
| D1 (amendment) | The deployment-factor values per component type are published as a table (section 6.1), in place of D20. The maintainer revised the values on 2026-11-05 (Non-Determinism and Opacity 1.0 in all columns); they are initial and adjustable during S03b |
| D12 | Approved as recommended; stays conditional on TX4 |
| D13, D14, D17 | Approved as changed in the maintainer's message of 2026-11-05 (D2 is amended by D17 part 4) |
| D19 | Approved (maintainer, 2026-11-05) |
| D20 | Withdrawn as written; replaced by the D1 amendment |
| D21 | Approved with the change that the full tier is band-sensitive records only (maintainer, 2026-11-05) |

**D1. Reference profile rule.** Adopt section 5.3: the RDP, mechanism factors from the class, deployment factors typical as shipped, an anchor per class, a stated basis for every non-zero factor. Alternatives: worst case for deployment factors (sets four factors to 1.0 almost everywhere), or a profile per component type (more precise, more to maintain). *Recommend: the RDP as written.* *Amended 2026-11-05 by the maintainer: the deployment-factor values per component type are published as a table (section 6.1) in place of a new decision. The table's values are initial and adjustable during S03b.*

**D2. Subsequent-system impact, and reach counted once.** Score `SC/SI/SA` only for propagation the class itself states, and count tool reach once, in the Tools factor. The literal reading of 3.1.1 gives every steering class `SC:H/SI:H` and a base near 9.4. *Recommend: as written; it follows nine of OWASP's ten examples.* *Amended by D17 part 4 (2026-11-05) for `SC`, `SI` and `SA`: the test is impact outside the vulnerable system's security domain at the reasonable worst case, not only propagation the description states. The half that counts tool reach once, in Tools, is unchanged.*

**D3. ThM mapping.** Options: (a) assess each record's tier from its cited sources (recommended); (b) map by value as #399 plans (agrees with the evidence for 4 of the 10 pilot records, which are not a sample of the 89; of the five pilot records stored at 1.0 it calls all five Attacked, where the evidence supports that for one); (c) PoC for every record except cited in-the-wild exploitation. Option (a) needs primary sources, and 22 records still lack one (the quality queue). *Recommend (a), with PoC where the evidence tier cannot be told apart, and a rule that an in-the-wild claim must carry its citation.*

**D4. Mitigation mapping.** Carry 1.0 to None and 0.83 to Partial by value, and apply section 8's definition to new assessments. *Recommend: yes.* `Strong` only with a cited validation.

**D5. Field names.** Appendix A's ten inner key names; keep the container name `aarf`. The alternative is `amplification_factors` for full alignment, one more break for readers. *Recommend: inner keys renamed, container kept.*

**D6. Levels and derived numbers.** Store `threat_maturity` and `mitigation` as well as the numbers, and validate they agree. *Recommend: yes.*

**D7. AARS storage.** Store `aars` exactly, to five decimals, and compare exactly. *Recommend: yes.*

**D8. `core_risk`.** Add the optional field, one of Appendix A's ten names, as the calibration anchor and for export. *Recommend: yes, optional.*

**D9. A transition field.** Shape: `legacy_scoring` `{method: "ave-derived-v1", aarf_sum, aars, thm, mitigation_factor, aivss_score, aivss_severity}`. *Recommend: do not put it on active records.* The 1.x numbers stay in the frozen `dist/ave-records-v1.3.0.json`, in git history and in the `revisions` entry that records the change, and a field beside the new score invites the comparison 3.2 warns against. If the maintainer wants it, keep it to records whose `aivss` is optional (D10).

**D10. `aivss` for `rejected` and `merged` records.** Make it optional for them, so no score is asserted for something declared not a class; keep it required for `active` and `deprecated`. Their last 1.x score stays in the frozen files and the status `revisions` entry. *Recommend: yes.*

**D11. `vulnerability_rationale.agentic_distinction`.** Add as an optional documented string in 2.0.0 (not 2.1.0). The seven D7 JUSTIFY records already carry the distinction inside `vulnerability_rationale.vulnerability`; this gives it a place of its own for later records. *Recommend: yes.*

**D12. CWE mapping field.** Conditional on TX4. TX4 has not been delivered, so there is no proposal to approve; the item stays on the list and nothing is added to 2.0.0 for it.

**D13. The AIVSS 1.0 candidate.** Facts found on 2026-11-04:

- The publications listed on `aivss.owasp.org` are v0.5 and v0.8; its homepage calls v0.8 "the latest version". The same homepage links "the AIVSS 1.0 calculator" at `aivss.owasp.org/calculator/`, titled "OWASP AIVSS 1.0 · Reference Calculator".
- OWASP's open letter of 2025-12-08 said v1.0 would be published at RSA 2026; v0.8 was published on 2026-03-19 instead. That announcement says v0.8 "sets the stage for the highly anticipated v1.0 release, slated for publication before the end of 2026", and opened a public review period on 2026-04-16.
- The candidate's repository is `kenhuangus/aivss-v1-calculator` (created 2026-08-28, last push 2026-10-22, Apache-2.0). Its owner login, `kenhuangus`, matches the Substack that signs the project's open letter as "Ken Huang, Co-Lead, OWASP AIVSS Project" (the letter is linked from `aivss.owasp.org`), and v0.8 names Ken Huang on the AIVSS leadership team; I did not verify that the GitHub account is that person's. It holds code only; its commit history shows the specification copies were removed, so the 1.0 specification text was not available to compare with.
- Its model differs from v0.8. There is no factor sum, ThM or Mitigation_Factor. Five categorical agentic metrics (LC, CP, AP, RH classify; ES informs an uplift) go in a separate `AIVSS:1.0/...` vector; the CVSS v4.0 score is kept unchanged (CVSS-BTE, so exploit maturity is in the CVSS vector); an Agentic Effect Class (A0, A1, A2, AX) is derived by a rule ladder; the AIVSS score is read from a lookup table keyed by the CVSS band and the class, and is never lower than CVSS-BTE. Its `legacy` command reproduces "withdrawn v0.x uplift scores" and says they must not be used for 1.0 compliance.
- It says of itself: "The Table 6 cell values are policy settings that have not yet been validated against independently rated findings"; the remediation overlay "not empirically calibrated"; `first_validation_status: not-submitted`; "OWASP does not endorse AIVSS v1".

*Cost of a later move:* every class re-assessed on five new metrics; the ten factors, ThM and Mitigation_Factor leave the model; a new major schema (3.0.0). The CVSS v4.0 vector made authoritative here carries over; the factor judgments do not. *Decided 2026-11-05:* proceed with v0.8; do the CVSS vectors first (S03a, D19), since they carry over to any later method; re-check OWASP's status at S03 start. Also kept from the proposal: method-specific values stay inside `aivss` and the CVSS vector outside it, so a second method could be added beside the first, and `spec_version` is a stated value and not a constant.

**D14. The severity distribution.** The pilot and the estimates say the same thing: under v0.8 most classes are HIGH or CRITICAL, MEDIUM is reachable mainly by classes with a narrow effect and a lower base, and LOW is unlikely.

| Measure | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| Today (89 records) | 1 | 20 | 66 | 2 |
| Estimate A: stored base, AVE's ten factors as they are, ThM 0.97 | 50 | 31 | 8 | 0 |
| Estimate B: stored base, the eight shared factors, ThM 0.97 | 41 | 39 | 9 | 0 |
| Estimate C: as B, ThM mapped by value | 37 | 41 | 11 | 0 |
| Floor: vector-computed base (S00), all ten factors 0, 88 valid vectors | 43 | 42 | 2 | 1 |
| Floor: stored base, all factors 0 | 15 | 48 | 26 | 0 |
| Ceiling: all factors 1 (vector-computed base / stored base) | 54 / 55 | 34 / 34 | 0 / 0 | 0 / 0 |
| Pilot, 10 records, before | 1 | 2 | 6 | 1 |
| Pilot, 10 records, after | 6 | 1 | 3 | 0 |

The floors and ceilings use each record's stored Mitigation_Factor and ThM 0.97. The estimates run on non-conformant inputs (AVE's factors were not assigned against Table 2, Context and Opacity are unscored, and the stored bases are not the vector bases), so they are not a re-score. The pilot is ten records, six of them chosen by name, so it is not a sample and its frequencies must not be scaled up. What it supports: a class with a base of 9.0 or more and no mitigation credit is CRITICAL whatever the factors do (three of the four pilot records that never changed band under any alternative tried have such a base: AVE-2026-00001, 00044 and 00046; the fourth, 00066, has a base of 8.7 and a Factor_Sum of 5.0); bounded-effect classes can stay MEDIUM; and estimate C, applied to the pilot's ten, put 4 of the 10 in a different band from the pilot (6 agree). Re-derived pilot bases averaged 0.7 below both the stored bases (10 records) and the S00 vector bases (9 records), so the vector-based floor probably overstates. *Decision:* whether a distribution of this shape is acceptable to publish, and whether the README, the site and the implementer guide should say plainly that v0.8 raises most scores. *Decided 2026-11-05:* yes, review the S03 vector re-derivation before the factor assignment (it decides most of the outcome), and show the CVSS-B band beside the AIVSS band in the registry and on the site. FIRST's rating scale (CVSS v4.0 specification, Table 22: None 0.0, Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0) matches AIVSS's except for None, so the two bands can sit side by side. The CVSS-B band can be derived from `aivss.cvss_base` when it is displayed, so it needs no schema field; it is a display change in the registry and site repositories. With the vectors in the records today the CVSS-B band alone is 67 CRITICAL, 20 HIGH and 1 LOW (88 valid vectors).

**D15. A second assessor near the band edges.** In the pilot, 6 of 10 records change band under at least one reasonable alternative choice (vector, ThM rule, mitigation, or a half-point on every factor). *Recommend:* a second independent assessment for any record whose score is within 0.5 of a band boundary, using the annotator-agreement kit once it exists.

**D16. Update #399.** Its statements that `cvss_base` is kept as stored and that there is no catalog v1.3.0 no longer match the plan. *Recommend:* edit #399 or close it in favour of a corrected tracking issue.

**D17. CVSS vector policy (S03a).** The base is the floor of the v0.8 score (section 5.4), and the vectors in the records today put it high. Of the 88 valid vectors, 67 compute to a base of 9.0 or more and 87 to 7.0 or more (only AVE-2026-00058, at 2.3, is below 7.0; nine are exactly 10.0). Counting a vector as having subsequent-system impact when at least one of `SC`, `SI` or `SA` is `H`, 82 of the 88 qualify (`SC` 72, `SI` 71, `SA` 20; at least two 62; all three 19; none 6). An earlier draft said 63; that was the vectors with one or two High, not at least one. A class with a base of 9.0 and no mitigation credit is CRITICAL whatever its factors say, so the vectors, more than the factors, decide the distribution.

Policy, approved 2026-11-05 with part 4 as changed by the maintainer:

1. **CVSS-B only.** Base metrics only. Threat, Environmental and Supplemental metrics are not used; exploit maturity is ThM.
2. **Reasonable worst case, per FIRST.** The CVSS v4.0 specification says the Base Score "assumes the reasonable worst-case impact across different deployed environments". For a class, the environment is its reference deployment profile (section 5.3).
3. **Name the systems.** Each vector's notes name the vulnerable system and any subsequent system, in words (for example, "the agent runtime and its host" and "the sub-agent that obeys the output").
4. **Subsequent systems.** `SC`, `SI` or `SA` is `H` when the class's mechanism, as described, causes impact outside the vulnerable system's security domain at the reasonable worst case for the reference deployment profile (FIRST). A cited demonstration is preferred evidence but not required. Propagation that needs further steps beyond the class is not counted. Tool reach is counted once, in Tools (D2). The profile is the same one that sets the deployment factors (section 6.1).
5. **No double counting.** An effect is counted once: tool reach in Tools, exploit maturity in ThM, hardening in Mitigation_Factor, and an impact in the vector or in a factor but not in both.
6. **An advisory vector as a start where one exists.** Seeds for S03a, each confirmed on 2026-11-05 against its entry in the GitHub Advisory Database (all `reviewed`), which carries the publisher's CVSS v4.0 vector, and each recomputed with both implementations (all agree with the stated score):

| Record | Advisory | CVE | Product | Vector | Score |
|---|---|---|---|---|---|
| AVE-2026-00064 | GHSA-4fgq-fpq9-mr3g | CVE-2025-59536 | Claude Code | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 8.7 |
| AVE-2026-00063 | GHSA-mmgp-wc2j-qcv7 | CVE-2026-33068 | Claude Code | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 7.7 |
| AVE-2026-00088 | GHSA-ff64-7w26-62rf | CVE-2026-25725 | Claude Code | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 7.7 |
| AVE-2026-00089 | GHSA-w5fx-fh39-j5rw | CVE-2025-59532 | Codex | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 8.6 |
| AVE-2026-00089 | GHSA-w828-4qhx-vxx3 | CVE-2026-34452 | Anthropic SDK for Python | `CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | 5.8 |
| AVE-2026-00073 | GHSA-jh7p-qr78-84p7 | CVE-2026-21852 | Claude Code | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N` | 5.3 |

   That is five records and six advisories; the maintainer's estimate was about 6 records. Each vector is for the nearest instance in a named product and not for the class, so S03a starts from it, changes only what the class differs in, and says so. The only seeded record in the pilot is AVE-2026-00063: its pilot vector (7.2) differs from the advisory's (7.7) in `AT` (`N` against `P`) and in `VC` and `VA` (`L` against `H`). The advisory GHSA-w828-4qhx-vxx3 also carries a CVSS 3.1 score (5.3), which is not used (3.1.1). None of the six publishers scores any subsequent-system impact, while 82 of the 88 vectors in the records have at least one High (part 4 decides which is right for a class). Records 00064, 00088 and 00089 cite further advisories that are not seeded here. The other records that cite a CVE, GHSA or advisory are 00029, 00044 (an incident write-up), 00052 and 00053 (proposed for rejection), 00054 (deferred), 00055 and 00056; no CVSS v4.0 vector was checked for them. If an advisory has only CVSS 3.1, do not convert it (3.1.1).
7. **Two implementations.** The Red Hat `cvss` library and FIRST's calculator source, pinned, with a test that fails if they disagree on any record.
8. **A second assessor on ten records.** Before S03a's vectors are applied, a second assessor, or a separate pass that has not seen the first vectors, derives vectors independently for the pilot's ten records, and the two sets are compared metric by metric: exact-vector agreement per metric, the difference in base score, and whether the CVSS-B band agrees. The pass thresholds are the maintainer's to set. The pilot's own sensitivity is the evidence: 6 of 10 records change band under one alternative choice, and the vector is the choice that moves the most (4 of the 9 records with a valid stored vector).

The pilot's vectors predate this policy (parts 2 and 4 in particular) and are not re-derived here; S03a re-derives them.

**D18. When to open the 30-day public comment period.** `CONTRIBUTING.md` ("Schema changes") says a major schema version "needs a migration path for existing records and a 30-day comment period before merging". It names no start event, no venue and no content. Schema 2.0.0 is a major version: it changes the meaning of `aars` and `thm`, removes two `aarf` keys and renames five. The release step S05 gates on the period having closed.

*Recommend:* open it as soon as the S01 pull request merges, so that what the public reads is the approved statement and not a draft. Open it in a public issue or discussion on `aveproject/ave`, not in a comment on the pull request, and put in the opening post:

1. links to the conformance statement, the pilot report with its data file, and the migration path;
2. the migration path as it stands then: what each existing field becomes (the `aarf` keys, `aars`, `thm`, `mitigation_factor`, the score and severity, `schema_version`), what happens to the 1.x numbers (D9, D10), and what consumers must change. Section 10 of the statement is the field mapping; the per-record migration itself comes later, in S03;
3. the day it opens and the day it closes;
4. what is open to change (the choices in D1 to D17) and what is not (the equations, constants and bands, which are OWASP's);
5. how to comment, and that each comment gets a written answer on the thread before S05.

Points the maintainer should settle:

- **The clock starts when the post is made**, not when this list is approved, and nothing is posted before the S01 pull request has merged. The post is a public act, so it is drafted for approval first.
- **Early or late.** Opening before S03 lets comments change the method before 89 records are re-assessed, which is cheap, but the public cannot yet see re-scored values. Opening after S03 shows the real numbers, but a change to the method then costs a re-score. Recommend early.
- **What restarts the clock.** Proposed: a change to the equations, the field mapping or the migration path restarts the 30 days; an editorial change does not.
- **Where it is announced.** The thread should be somewhere downstream tools and consumers of the dist files can subscribe to. Which channels is the maintainer's call, and nothing is announced outside the repository without approval.
- **What "merging" means.** The wording is "before merging". Read here as the merge that publishes schema 2.0.0 (S05), not the merges into a `release/2.0` branch. If the maintainer reads it as the first merge of 2.0.0 files into `develop`, the period has to be complete before S02.

**D19. Split S03 into S03a and S03b.** *Approved 2026-11-05.*

- **S03a: the CVSS vectors**, for all 89 records, under D17. They are reusable: the OWASP 1.0 candidate keeps the official CVSS v4.0 vector and score intact (its README), so the vectors carry over to a later AIVSS method as well as serving v0.8 now.
- **S03b: the AIVSS inputs** under v0.8 (the four deployment factors for the record's component type from the table in section 6.1, the six mechanism factors, the ThM tier and the mitigation level, tiered by D21), only after a checkpoint on OWASP's status. The checkpoint re-reads `aivss.owasp.org`, its publications list and the candidate repository. It is made at S03 start (D13) and again before S03b begins, because S03a does not depend on the answer and the answer may change while it runs. OWASP's announcement of 2026-03-19 says v1.0 is "slated for publication before the end of 2026". If v1.0 has been published by then, S03b waits for a maintainer decision (D13 gives the cost); if not, S03b proceeds on v0.8.
- **Where S03a's output lives (proposed).** S00 warned that changing `cvss_base` before 2.0.0 would silently rescore the 1.x scores. So S03a delivers a reviewed table of vectors, with the systems named (D17), and applies it to the records only on the 2.0.0 branch with the rest of the migration, not on `develop`.
- **Gate.** S02 does not start until this pull request has merged and the public comment period (D18) has opened.

**D20. Withdrawn 2026-11-05.** The maintainer withdrew it as written (5 to 8 reference deployment profiles instead of per-record factors) and amended D1 instead, with the table of deployment-factor values per component type in section 6.1. No new decision. One finding is kept because it supports D19 and D21: with the vectors in the records today, the factor sum moves the distribution little (50 CRITICAL, 35 HIGH, 2 MEDIUM, 1 LOW at a Factor_Sum of 3.0, and 54, 33, 1, 0 at 8.0; 88 valid vectors, ThM 0.97, stored mitigation), because 67 of the 88 bases already put the CVSS-B band at CRITICAL.

**D21. Tier S03b by band sensitivity.** *Approved 2026-11-05, with the change that the full tier is band-sensitive records only.* After S03a, compute each record's band at zero and at maximum uplift, and recompute it whenever a vector or a mitigation level changes:

- **Floor:** its S03a vector base times its Mitigation_Factor (stored, or assessed once S03b assesses it), at Factor_Sum 0.
- **Ceiling:** Factor_Sum 10 with the top of its ThM range (Attacked 1.00, unless its sources rule that tier out), times the same Mitigation_Factor. At ThM 1.00 the ceiling is 10 times the Mitigation_Factor: 10.0 with no mitigation credit, 8.3 with Partial, 6.7 with Strong.
- **Full tier: band-sensitive records only.** The band can change between floor and ceiling. The record gets the full assessment as in the pilot (every factor with a basis, the uncertain calls scored) and second-assessor review.
- **Light tier: every band-insensitive record.** Floor and ceiling are in the same band. The record gets the six mechanism factors with a one-line basis each, on top of the four values from the table in section 6.1.
- **Edge check, within the light tier.** A band-insensitive record whose floor is less than 0.5 above the lower boundary of its band, or whose ceiling is less than 0.5 below the next boundary up, gets an independent check of its vector and its mitigation level (D15, D17 part 8). It does not get a full factor assessment.

Indicative sizes on today's vectors, which S03a will change: of the 88 valid vectors, 14 are band-sensitive (full tier), and 74 are band-insensitive (light tier), of which 27 are within 0.5 of a boundary and get the edge check. AVE-2026-00066 has no valid vector yet. The numbers will move, because re-derived bases were 0.7 lower on average in the pilot and lower bases make more records band-sensitive. With no mitigation credit a record is band-insensitive only if its floor is CRITICAL (a base of 9.0 or more); with Partial credit (ceiling 8.3), only if its floor is HIGH (a base of about 8.4 or more). The six mechanism factors are still assessed for the light tier because AARS and the score are stored and exported.
