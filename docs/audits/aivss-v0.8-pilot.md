# AIVSS v0.8 pilot: ten records assessed under the conformance statement

Tests `docs/specs/aivss-v0.8-conformance.md` (S01, #399, issue #446) on ten real records. Report only: no record, schema file, validator or `dist/` file changed (the one code addition is the standalone arithmetic module `scripts/aivss_v08.py` and its tests), and none of these scores is proposed for publication. The data is in `docs/audits/aivss-v0.8-pilot.json`, in the format of OWASP's Appendix A report schema.

**Date:** 2026-11-04. **Records:** `develop` at `0753b2d`. **Assessor:** one (the author of this report). No second assessment was made.

## Summary

- Under the statement, the ten move from **1 CRITICAL, 2 HIGH, 6 MEDIUM, 1 LOW** to **6 CRITICAL, 1 HIGH, 3 MEDIUM, 0 LOW**. All ten scores rise; the mean Factor_Sum is 5.6 (OWASP's own examples: 7.65).
- The classes that end CRITICAL are those that give the attacker broad control of what an agent does or runs (AVE-2026-00001, 00019, 00020, 00044, 00046, 00066). The classes with a bounded effect stay MEDIUM (00039, 00058, 00063) or HIGH (00024). That is the separation the plain-language check asks for (below).
- **The result is not robust to reasonable alternative choices.** 6 of 10 records change band under at least one alternative (a different vector, ThM rule, mitigation level, or half a point on every factor). The four that never do (00001, 00044, 00046, 00066) have a CVSS base of 8.7 to 9.3 and Factor_Sum of 5.0 to 8.0. The CVSS vector is the most influential input: using the vector in the record today changes the band of 4 of the 9 records that have a valid one.
- **The re-derived CVSS bases are lower on average than the ones in the records**: 0.7 below the stored `cvss_base` (10 records, from 2.6 lower to 0.9 higher) and 0.7 below the base of the stored vector (9 records, from 2.4 lower to 2.8 higher). So the corpus-wide estimate that uses the stored vectors probably overstates severity.
- The earlier corpus estimate put 6 of the ten in the same band as the pilot. It was one band too high for three (00024, 00039, 00063) and one band too low for one (00019).
- Mapping today's `thm` by value agrees with the tier the cited evidence supports for **4 of the 10 pilot records** (00039, 00044, 00058, 00066). The ten are not a sample of the 89, so this is not a corpus rate; 49 of the 89 records are stored at 1.0, and only the five of them in the pilot were checked (one cites in-the-wild exploitation).
- The statement changed in three places while piloting (end of this report).

## Selection rule (written before any record was assessed)

1. The maintainer's six: AVE-2026-00001, 00019, 00039, 00044, 00063 and 00066. (00039 has the largest estimated jump under the S01 task's two scenarios, 4.3 and 4.0; with ThM mapped by definition, AVE-2026-00072 is larger at 4.0 against 3.8, and it has a pending lifecycle decision.)
2. One record from each current band not yet represented. LOW has two records (00014 at 3.7, 00058 at 3.1): take the lower, **00058**. CRITICAL has one: **00046**.
3. Two more, to widen how the class enters the agent (`provenance_vector.entry_class`): the two most frequent entry classes not yet represented, `runtime` (12 records) and `skill_file` (4), taking from each the lowest `ave_id` with no pending lifecycle decision: **00020** and **00024**. Excluded as pending: 00035, 00049, 00052, 00053, 00054, 00060, 00061, 00062 and 00072.

Coverage is partial and the limits matter: 8 of 13 entry classes (not `tool_schema`, `retrieved_document`, `user_input`, `transport`, `operator_config`); 9 records are `skill` components, 1 is `mcp_server` and none is `agent`; all are `active`.

## Method

For each record, in the order the statement gives:

1. Choose the nearest OWASP Core Risk as the calibration anchor (section 3.6).
2. Derive the CVSS v4.0 base vector from the class's described impact (statement section 4), and score it with two implementations: the Red Hat `cvss` library 3.6 and FIRST's `cvss-v4-calculator` scoring files at commit `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a` (run unchanged in a context with no file, network or DOM access). They agree on all ten.
3. Assign the ten factors by the statement's Table in section 6, with one line of basis for each non-zero factor taken from the record's description, fingerprint, `security_boundary`/`missing_control` text or references.
4. Choose the ThM tier from the evidence the record cites, and the mitigation level against Table 4b.
5. Compute AARS and the score in exact decimal arithmetic (the reference form in the statement's section 3), rounded half up, and band it.
6. Write down every uncertain call, and score the plausible alternative.

The arithmetic was checked first against OWASP's ten worked examples (all reproduce, including each example's CVSS base from its vector in both implementations). The input files are `records/` at the commit above.

## Before and after

"Stored base" is the record's `aivss.cvss_base`; "stored vector" is the base score its own `cvss_base_vector` computes to (S00); "pilot base" is the base of the vector derived here. "Old" values are the schema 1.3.0 ones. Level names for ThM: A attacked, P proof of concept, U unreported; for mitigation: N none, P partial.

| Record | Class (entry class) | Stored base | Stored vector | Pilot base | Old factor sum | Pilot Factor_Sum | Old ThM | Pilot ThM | Old mit. | Pilot mit. | AARS (uplift) | Old score and band | Pilot score and band |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 00001 | Metamorphic payload via external config fetch (content) | 8.5 | 9.5 | 9.3 | 7.5 | 7.0 | 1 | P 0.97 | 1 | N 1.00 | 0.4753 | 8.0 HIGH | **9.8 CRITICAL** |
| 00019 | Agent memory poisoning (memory) | 8.0 | 9.4 | 7.0 | 7.0 | 7.0 | 0.75 | P 0.97 | 1 | N 1.00 | 2.0370 | 5.6 MEDIUM | **9.0 CRITICAL** |
| 00020 | Cross-agent prompt injection, A2A (runtime) | 8.7 | 9.4 | 8.3 | 7.0 | 7.0 | 0.75 | P 0.97 | 1 | N 1.00 | 1.1543 | 5.9 MEDIUM | **9.5 CRITICAL** |
| 00024 | Content type mismatch (skill_file) | 8.5 | 9.0 | 7.5 | 5.0 | 3.5 | 1 | U 0.50 | 1 | N 1.00 | 0.4375 | 6.8 MEDIUM | **7.9 HIGH** |
| 00039 | Steganographic covert channel (content) | 8.5 | 7.0 | 5.9 | 4.5 | 4.0 | 0.75 | U 0.50 | 1 | N 1.00 | 0.8200 | 4.9 MEDIUM | **6.7 MEDIUM** |
| 00044 | Async task result poisoning (tool_response) | 8.2 | 8.9 | 9.1 | 8.0 | 8.0 | 1 | A 1.00 | 1 | N 1.00 | 0.7200 | 8.1 HIGH | **9.8 CRITICAL** |
| 00046 | MCP tool hook hijacking (server_card_document) | 10.0 | 10.0 | 9.3 | 8.5 | 8.0 | 1.0 | U 0.50 | 1 | N 1.00 | 0.2800 | 9.2 CRITICAL | **9.6 CRITICAL** |
| 00058 | Trigger scope deception (registry_metadata) | 6.5 | 2.3 | 5.1 | 3.5 | 3.5 | 0.75 | U 0.50 | 0.83 | P 0.83 | 0.8575 | 3.1 LOW | **4.9 MEDIUM** |
| 00063 | Approval gate bypass by configuration (registry_metadata) | 8.5 | 9.3 | 7.2 | 3.0 | 3.0 | 1 | P 0.97 | 0.83 | P 0.83 | 0.8148 | 4.8 MEDIUM | **6.7 MEDIUM** |
| 00066 | Hallucinated skill-name squatting (model_generated) | 9.0 | invalid | 8.7 | 4.75 | 5.0 | 0.9 | P 0.97 | 1 | N 1.00 | 0.6305 | 6.2 MEDIUM | **9.3 CRITICAL** |

Bands: before 1 CRITICAL, 2 HIGH, 6 MEDIUM, 1 LOW; after 6, 1, 3, 0.

## The assessments

Factor order: Autonomy, Tools, Language, Context, Non-Determinism, Opacity, Persistence, Identity, Multi-Agent, Self-Mod. "Anchor" is the nearest Core Risk and its factor vector in OWASP's example.

### AVE-2026-00001 Metamorphic payload via external config fetch

- **Anchor:** Agent Supply Chain and Dependency Risk (3.6.8), 1, 1, 0, 0, 1, 1, 0.5, 1, 1, 0 (sum 6.5).
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`, base 9.3 (library 9.3, FIRST 9.3). The stored vector is `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` (9.5). Changes: AT `P` to `N` (the model following the fetched content is the mechanism, not a named deployment condition); `SC/SI/SA` to `N` (the description states no propagation beyond the component's own behaviour). From the anchor: `VA:L` and not `H` (the description replaces behaviour and states no loss of availability).
- **Factors:** Autonomy 1.0, the replaced behaviour runs with no co-sign once the component is approved ("change the component's behavior after it passes a security review"). Tools 1.0, the fetch uses network tools and the replaced instructions then drive the agent's tools (IoC: `fetch()`, `requests.get()`, `curl`, `wget`). Language 1.0, the fetched content is natural-language instructions replacing the component's own (the anchor scores 0 because its mechanism is code). Context 1.0, remote content fetched at runtime is runtime content. Non-Determinism 0.5, the swap is deterministic and the model follows explicit instructions. Opacity 1.0, "invisible to static scanners because the malicious payload does not exist at scan time". Persistence 0.5, the content is fetched in every session while the component stays installed, outside the agent's own memory. Self-Mod 1.0, the fetched content replaces the component's own behavioural instructions (fingerprint: "fetch and execute remote content"). Identity 0 and Multi-Agent 0: the text names neither. **Sum 7.0.**
- **ThM:** Proof of Concept. Greshake et al. 2023 (arXiv 2302.12173) demonstrates indirect injection through attacker-controlled retrieved content; the other references (ATLAS AML.T0010, CWE-494) classify. No in-the-wild source is cited. Old value 1.
- **Mitigation:** none. The record's `mitigation` names pinning and egress blocking, but none is cited as default-on or validated. Old value 1.
- **Result:** AARS 0.4753, **9.8 CRITICAL** (was 8.0 HIGH).
- **Uncertain:** whether installation counts as the victim's action (`UI:A`: base 8.6, 9.6, still CRITICAL). CRITICAL under all seven alternatives tried.

### AVE-2026-00019 Agent Memory Poisoning

- **Anchor:** Agent Memory and Context Manipulation (3.6.6), 1, 0.5, 1, 1, 0.5, 1, 1, 0, 0.5, 1 (sum 7.5).
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`, base 7.0 (library 7.0, FIRST 7.0). Stored vector `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` (9.4). The anchor scores an insider with database privileges (`AV:A/AC:H/PR:H`, 5.8); here the attacker is a component that can write memory, with no privilege: `AV:N`, `AC:L`, `PR:N`, and `UI:A` because the user installs the component. `VC:L/VI:H/VA:N` as in 3.6.6: the corruption is of the agent's beliefs and disclosure is incidental. Subsequent systems `N`: the effect crosses sessions, not systems.
- **Factors:** Autonomy 1.0, the agent acts on poisoned beliefs in later sessions with no co-sign. Tools 0.5, the write uses the memory interface and later actions use the agent's scoped tools (as 3.6.6). Language 1.0, instructions or facts in natural language are stored and followed. Context 1.0, persistent memory is the agent's context source (as 3.6.6). Non-Determinism 0.5, influence on later behaviour is reliable but not certain (as 3.6.6). Opacity 1.0, "no provenance or integrity check gates writes", so entries cannot be traced to their writer. Persistence 1.0, "in all subsequent sessions". Self-Mod 1.0, the component writes the agent's own standing context (as 3.6.6). Identity 0. Multi-Agent 0: the description names no other agent (the anchor's 0.5 is for limited downstream interaction this text does not state). **Sum 7.0.**
- **ThM:** Proof of Concept. Cohen et al. 2024 (arXiv 2403.02817) and Zou et al. 2024 (PoisonedRAG, arXiv 2402.07867) demonstrate poisoning of stored or retrieved context; no in-the-wild source. Old value 0.75.
- **Mitigation:** none (remediation advice only). Old value 1.
- **Result:** AARS 2.0370, **9.0 CRITICAL** (was 5.6 MEDIUM).
- **Uncertain:** it sits exactly on the CRITICAL edge. It is HIGH with ThM mapped by the old value (8.1) and with every factor 0.5 lower (7.9). `VC:H` instead of `VC:L` gives base 8.5 and 9.5; `UI:N` gives 8.8 and 9.6.

### AVE-2026-00020 Cross-Agent Prompt Injection (A2A)

- **Anchor:** Agent Orchestration and Multi-Agent Exploitation (3.6.4), 1, 1, 1, 1, 1, 1, 1, 1, 1, 0.5 (sum 9.5).
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N`, base 8.3 (library 8.3, FIRST 8.3). Stored vector `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` (9.4). The malicious component sits in the first agent's context, so that agent is the vulnerable system (its output is attacker-controlled, `VI:H`) and the sub-agent that obeys it is the subsequent system (`SC:H/SI:H`, the propagation the description states). `AC:L`: no defence is beaten; the missing control is the boundary itself. `UI:A`: the component is installed.
- **Factors:** Autonomy 1.0, the sub-agent acts on the instruction "bypassing the orchestrator's safety controls". Tools 0.5, sub-agent tools are typically scoped by the orchestrator and the class is message passing. Language 1.0, crafted natural language read as commands. Context 1.0, one agent's output arrives as the next agent's input. Non-Determinism 1.0, an LLM sub-agent interprets injected text with no boundary (3.6.3 scores 1.0). Opacity 1.0, attacker text is indistinguishable from orchestrator-intended output. Identity 0.5, the message is read as coming from the orchestrator, a claim of identity within a scope (3.6.3 scores 0.5). Multi-Agent 1.0, definitional. Persistence 0 (a single handoff; the text states no state), Self-Mod 0. **Sum 7.0.**
- **ThM:** Proof of Concept. Cohen et al. 2024 (the worm propagates between GenAI agents) and Greshake et al. 2023 demonstrate; no in-the-wild source. Old value 0.75.
- **Mitigation:** none. Old value 1.
- **Result:** AARS 1.1543, **9.5 CRITICAL** (was 5.9 MEDIUM).
- **Uncertain:** which system is the vulnerable one. Taking the sub-agent as vulnerable with no subsequent impact gives base 8.5 and the same 9.5. It falls to HIGH with ThM by old value (8.9) and with every factor 0.5 lower (8.8).

### AVE-2026-00024 Supply Chain - Content Type Mismatch

- **Anchor:** Agent Supply Chain and Dependency Risk (3.6.8), sum 6.5.
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, base 7.5 (library 7.5, FIRST 7.5). Stored vector `AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` (9.0). Impact as the anchor: "arbitrary executable content runs under the guise of a benign skill file". `AT:P` because a loader must execute the file as code; `UI:A` because the user installs the skill.
- **Factors:** Autonomy 1.0 (the file is loaded and run without review, as 3.6.8). Tools 1.0 (code runs with the host's privileges, as 3.6.8). Opacity 1.0 ("invisible to text-pattern scanners"; the extension hides the content). Persistence 0.5 (the file stays while the skill is installed; outside the agent's memory). Language 0 (byte-level mismatch, no natural-language step). Context 0. Non-Determinism 0 (a binary executes deterministically; 3.6.8 scores 1.0 for probabilistic backdoor triggers, which this class does not state). Identity 0 (3.6.8 scores 1.0 for inheriting the agent's identity; Table 2 scores a fixed identity 0; see U4). Multi-Agent 0 (a single file; no spread to other agents stated). Self-Mod 0. **Sum 3.5** (anchor 6.5).
- **ThM:** Unreported. The references (CWE-434, ATLAS AML.T0010, CWE-20) classify; none demonstrates a skill-file content-type mismatch. Old value 1.
- **Mitigation:** none (a classifier and an allowlist are advised; none is cited as default-on). Old value 1.
- **Result:** AARS 0.4375, **7.9 HIGH** (was 6.8 MEDIUM).
- **Uncertain:** the ThM tier. With the specification's default (PoC) the score is 8.3 HIGH. With `AT:N` and `UI:N` the base is 9.3 and the score 9.4 CRITICAL (a band change); with `AT:N` alone 8.6 and 8.8 HIGH.

### AVE-2026-00039 Covert Channel - Steganographic Data Exfiltration

- **Anchor:** Agent Goal and Instruction Manipulation (3.6.10), 0.5, 0, 1, 1, 1, 1, 1, 0, 0, 1 (sum 6.5). A weak anchor: the class is exfiltration, not a change of goal.
- **Vector:** `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`, base 5.9 (library 5.9, FIRST 5.9). Stored vector `AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` (7.0). Disclosure only: nothing is changed or lost. `AC:H` and `AT:P` because the encoding must survive the model's compliance and a channel to the attacker must exist (the description: output is reviewed by humans and the network is monitored; trifecta `external_comms`). `UI:A`: the component is installed. No propagation is stated.
- **Factors:** Autonomy 1.0, the agent encodes and emits with no co-sign (the point is that human review sees benign output). Tools 0.5, read tools and the output channel. Language 0.5, natural language sets the encoding but the exploit drives output formatting, not tool execution. Context 0.5, the secrets present in context are one narrow source. Non-Determinism 0.5, the model must follow an explicit encoding rule. Opacity 1.0, "output looks benign to a human reviewer" and content-level exfiltration "has no detection surface at all". The rest 0. **Sum 4.0.**
- **ThM:** Unreported. CWE-514, CWE-385 and the OWASP LLM sensitive-information page classify; none demonstrates. Old value 0.75.
- **Mitigation:** none (detection ideas only). Old value 1.
- **Result:** AARS 0.8200, **6.7 MEDIUM** (was 4.9 MEDIUM).
- **Uncertain:** the most fragile record. It is HIGH with ThM PoC (7.5), every factor 0.5 higher (7.5), the stored vector's base (7.6) or the stored base (8.8). It is LOW (3.7) if `VC` is `L` because a covert channel's bandwidth is small (base 2.1). `AC:L` instead of `AC:H` gives the same base (5.9).

### AVE-2026-00044 Prompt injection via poisoned async task result

- **Anchor:** Agent Goal and Instruction Manipulation (3.6.10), sum 6.5; also Tool Misuse (3.6.1), sum 9.0.
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`, base 9.1 (library 9.1, FIRST 9.1). Stored vector `AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` (8.9). `AT:P`: the product uses async task queues (a deployment condition the description names). `AC:L`: no defence is beaten. `PR:N`: the attacker controls the result delivery mechanism, not an account on the agent. The next action is attacker-steered (`VC:H/VI:H`). Subsequent systems `N`: the description states no propagation; the downstream effect of the cited incident is evidence for ThM and is not scored here (including it gives base 9.4).
- **Factors:** Autonomy 1.0, the agent acts on the result in a later turn, and "the temporal gap ... bypasses synchronous safety checks". Tools 1.0, the steered action uses the agent's broad tools. Language 1.0, "imperative language" in the payload. Context 1.0, the result is read as trusted context. Non-Determinism 1.0, an LLM follows injected text with weak guardrails (as 3.6.1). Opacity 1.0, injected content is treated as trusted completed-task context and the gap hides its origin. Persistence 0.5, the poisoned result persists in the queue until read. Identity 0.5, it is read as the output of a completed task, a claim of identity within a scope. Multi-Agent 0.5, the task goes to a worker or service. Self-Mod 0.5, the result steers the agent's next goal, once (as 3.6.1). **Sum 8.0.**
- **ThM:** Attacked. Clinejection (Adnan Khan, February 2026) is documented exploitation in the wild (credential theft and a tampered npm package). The record's own notes say its delivery was a synchronous workflow event and not the async queue, so the evidence is for a sibling entry surface of the same missing boundary; AVE raised `thm` to 1 on that basis on 2026-09-27, and that is kept. Old value 1.
- **Mitigation:** none (schemas and signing are advised; none is cited in place). Old value 1.
- **Result:** AARS 0.7200, **9.8 CRITICAL** (was 8.1 HIGH).
- **Uncertain:** the ThM tier rests on a sibling surface. With PoC the score is the same, 9.8, because the base is 9.1; the base is the floor.

### AVE-2026-00046 MCP tool hook hijacking

- **Anchor:** Agentic AI Tool Misuse (3.6.1), sum 9.0.
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L`, base 9.3 (library 9.3, FIRST 9.3). Stored vector `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` (10.0, equal to the stored base). Changes: `UI:A` (the component is installed) and `VA/SA:L` and not `H` (the hook "may drop them silently": partial loss of function). `SC/SI:H` kept: the intercepted calls belong to other skills and system tools and reach downstream services (the description). A base of 10.0 would give an uplift of 0 whatever the factors.
- **Factors:** Autonomy 1.0, the hook intercepts all later calls with no co-sign. Tools 1.0, it intercepts every tool call, including system tools. Language 1.0, the skill instructs the agent in natural language to register the hook. Context 1.0, the hook sees all tool traffic. Non-Determinism 0.5, the hook is deterministic once registered; registration depends on the agent following the instruction. Opacity 1.0, "the agent continues to believe it is calling the legitimate tool". Persistence 0.5, the hook lasts the session. Identity 0.5, it stands in for the legitimate handler. Multi-Agent 0.5, it affects other components' calls. Self-Mod 1.0, it alters the agent's tool dispatch ("tools, control flow"). **Sum 8.0.**
- **ThM:** Unreported. CWE-601, CWE-918, the MCP security best practices and the OWASP MCP Top 10 (Tool Poisoning) describe the area; none demonstrates hook interception. The writeup says the 1.0 "reflects ... an in-the-wild threat maturity", and the record cites no incident. Old value 1.0.
- **Mitigation:** none (denying hook registration is advised; none is cited default-on). Old value 1.
- **Result:** AARS 0.2800, **9.6 CRITICAL** (was 9.2 CRITICAL).
- **Uncertain:** the ThM tier. If an in-the-wild source is cited, ThM 1.00 gives 9.9. Without subsequent impact the base is 8.6 and the score 9.2, still CRITICAL.

### AVE-2026-00058 Deceptive skill trigger or activation-scope manipulation

- **Anchor:** Agentic AI Tool Misuse (3.6.1), sum 9.0. A weak anchor.
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`, base 5.1 (library 5.1, FIRST 5.1). Stored vector `AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N` (2.3). The class is "a reach-amplifier" (the record's own notes): over-broad invocation, whose harm depends on what the skill then does, hence `L/L`. `AC:L`: the misleading description beats no defence (the stored vector's `AC:H/AT:P` has no stated reason). `UI:A`: the skill is installed.
- **Factors:** Autonomy 0.5, implicit invocation without the user's intent, while the invoked skill's actions still pass normal confirmations. Tools 0.5, the skill's declared tools, scoped. Language 1.0, natural-language triggers and description decide routing. Context 0.5, one declared source, the manifest. Non-Determinism 0.5, LLM routing varies, bounded by the manifest. Opacity 0.5, the manifest is readable but why a skill was invoked is not traceable. The rest 0. **Sum 3.5.**
- **ThM:** Unreported. CWE-451 classifies and the Cisco skill-scanner page lists a category. Old value 0.75.
- **Mitigation:** partial 0.83. A scanner flags the category but is not validated against adversarial use. Old value 0.83.
- **Result:** AARS 0.8575, **4.9 MEDIUM** (was 3.1 LOW).
- **Uncertain:** the vector. `AC:H` gives base 2.1 and 2.9 LOW; the stored vector's base (2.3) gives 3.0 LOW. This is the one pilot record that can fall to LOW; at 4.9 it is 0.9 above the edge.

### AVE-2026-00063 Human approval gate bypassed via declarative configuration

- **Anchor:** Agent Access Control Violation (3.6.2), 1, 1, 1, 1, 0.5, 1, 1, 1, 0.5, 0 (sum 8.0).
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N`, base 7.2 (library 7.2, FIRST 7.2). Stored vector `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N` (9.3). The class is an enabler: it removes a control, and the harm is what the removed gate would have stopped, so `VI:H` (the integrity of the control and of the actions it guards) with `VC:L/VA:L`. `UI:P`: the nearest documented instance (CVE-2026-33068) needs the user only to open a repository.
- **Factors:** Autonomy 1.0, the class removes the human co-sign. Tools 1.0, the gate guards high-risk actions (shell, writes, network). Opacity 0.5, the flag is readable in configuration but nothing signals its use ("a reviewer inspecting only the component's declared instructions would never see it"). Persistence 0.5, a committed configuration persists outside the agent's memory. Language 0 ("no accompanying instruction text at all"), Context 0, Non-Determinism 0, Identity 0, Multi-Agent 0, Self-Mod 0. **Sum 3.0.**
- **ThM:** Proof of Concept. The advisory for CVE-2026-33068 (GHSA-mmgp-wc2j-qcv7) describes the exploit ("a malicious repository could set `permissions.defaultMode` to `bypassPermissions` in its committed `.claude/settings.json`"). The record calls it the nearest instance and not an exact match; the advisory states no exploitation. Old value 1.
- **Mitigation:** partial 0.83. The vendor fixed the nearest instance (2.1.53), not the class. Old value 0.83.
- **Result:** AARS 0.8148, **6.7 MEDIUM** (was 4.8 MEDIUM).
- **Uncertain:** 0.3 below the HIGH edge. It is HIGH with `VC:H` (base 8.7, 7.5), with mitigation none (8.0), with the stored vector's base (7.9) or with every factor 0.5 higher (7.6).

### AVE-2026-00066 Hallucinated skill-name squatting (HalluSquatting)

- **Anchor:** Agent Supply Chain and Dependency Risk (3.6.8), sum 6.5.
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, base 8.7 (library 8.7, FIRST 8.7). The stored vector is invalid (`UI:R` is a CVSS 3.1 value); the stored base is 9.0. Impact as the anchor (installed content executes: "malware", "botnet formation"). `UI:P`: the victim makes an ordinary request and the interaction holds no attacker content. `AT:N`: the hallucination is the mechanism. Subsequent systems `N`: the description is about distribution across victims, not propagation from one (all `H`, as the stored vector had, gives 9.4).
- **Factors:** Autonomy 1.0, the agent fetches, clones or installs with no co-sign (fingerprint). Tools 1.0, installing uses shell and package tools. Language 1.0, an ordinary natural-language request is resolved to a name. Non-Determinism 0.5, the hallucination is predictable and transferable, not deterministic (the record's own 0.25 is off the 0, 0.5, 1 scale and goes to the nearest point, ties up). Opacity 1.0, the model's belief that the resource exists is not auditable and squatted content looks legitimate. Persistence 0.5, an installed package persists outside the agent's memory (as 3.6.8). Context 0 (model memory, as 3.6.8), Identity 0 (see U4), Multi-Agent 0, Self-Mod 0. **Sum 5.0.**
- **ThM:** Proof of Concept. arXiv 2607.07433 demonstrates up to 85% success in repository cloning and up to 100% in skill installation against production applications; arXiv 2607.12340 measures the hallucinated names; no real campaign is reported. Old value 0.9.
- **Mitigation:** none (registry checks and allowlists are advised; none is in place). Old value 1.
- **Result:** AARS 0.6305, **9.3 CRITICAL** (was 6.2 MEDIUM).
- **Uncertain:** `UI:N` gives base 9.3 and 9.6. This also replaces the invalid vector.

## Sensitivity

Score (and band) under each alternative, other inputs as in the pilot. A star marks a band different from the pilot's.

| Alternative | 00001 | 00019 | 00020 | 00024 | 00039 | 00044 | 00046 | 00058 | 00063 | 00066 |
|---|---|---|---|---|---|---|---|---|---|---|
| **Pilot** | 9.8 C | 9.0 C | 9.5 C | 7.9 H | 6.7 M | 9.8 C | 9.6 C | 4.9 M | 6.7 M | 9.3 C |
| Base from the stored vector | 9.8 C | 9.8 C | 9.8 C | 9.2 C* | 7.6 H* | 9.8 C | 10.0 C | 3.0 L* | 7.9 H* | invalid |
| Base from the stored `cvss_base` | 9.5 C | 9.4 C | 9.6 C | 8.8 H | 8.8 H* | 9.6 C | 10.0 C | 5.9 M | 7.4 H* | 9.5 C |
| ThM PoC for every record | 9.8 C | 9.0 C | 9.5 C | 8.3 H | 7.5 H* | 9.8 C | 9.8 C | 5.6 M | 6.7 M | 9.3 C |
| ThM mapped from the old value | 9.8 C | 8.1 H* | 8.9 H* | 8.4 H | 6.7 M | 9.8 C | 9.9 C | 4.9 M | 6.7 M | 9.3 C |
| Mitigation none for every record | 9.8 C | 9.0 C | 9.5 C | 7.9 H | 6.7 M | 9.8 C | 9.6 C | 6.0 M | 8.0 H* | 9.3 C |
| Every factor 0.5 lower | 9.5 C | 7.9 H* | 8.8 H* | 7.7 H | 6.1 M | 9.4 C | 9.4 C | 4.3 M | 6.2 M | 9.0 C |
| Every factor 0.5 higher (cap 1) | 9.9 C | 9.6 C | 9.8 C | 8.4 H | 7.5 H* | 10.0 C | 9.7 C | 5.9 M | 7.6 H* | 9.7 C |

Band changes per alternative: stored vector 4 (of the 9 valid), stored base 2, ThM PoC 1, ThM by old value 2, mitigation none 1, factors lower 2, factors higher 2. **Six records change band at least once** (00019, 00020, 00024, 00039, 00058, 00063). Four never do (00001, 00044, 00046, 00066).

The corpus estimate used before this pilot (stored base, the eight factors v0.8 shares with AVE, ThM mapped by definition) agrees with the pilot's band for 6 of the 10.

## Plain-language check

The test: a class that sounds severe and a class that sounds narrow should not both be CRITICAL without a reason.

- **CRITICAL (6).** 00001: whoever controls a URL can rewrite a reviewed component's behaviour at will, with the agent's privileges. 00046: a component can silently sit between the agent and every tool it calls. 00066: an ordinary request leads the agent to install attacker-controlled code. 00044: an injected task result steers the agent's next action, and a real incident exists. 00020: one agent's output is taken as another's instructions. 00019: a poisoned memory steers the agent in every later session. These are classes where the attacker gets broad control of what the agent does, so CRITICAL has a reason in each. Two are marginal: 00019 is exactly on the edge (9.0) and 00020 is 0.5 above it.
- **HIGH (1).** 00024: an executable is disguised as a skill file. If it is loaded it is code execution, but the ThM is Unreported (the cited sources demonstrate nothing), so it stays below CRITICAL; with the specification's default it is 8.3, still HIGH.
- **MEDIUM (3).** 00039 leaks data through a channel with an explicit set of conditions and no effect on integrity or availability. 00063 removes a safety control but does nothing by itself: the harm is what the missing control then permits. 00058 only widens when a skill is invoked. None sounds as severe as the six, and none is CRITICAL.
- **No LOW.** 00058 was LOW and is now MEDIUM, because a base of 5.1 is a floor under it: with its own Factor_Sum, ThM and mitigation, 00058 stays LOW only for a base of 3.6 or less. The record's own notes say its base and factors sit lower than the direct-injection classes, and it is the lowest-scoring class in the pilot.
- **One rank inversion, and what the specification says about it.** 00044 (9.8) outscores 00046 (9.6), although 00046 intercepts every tool call and 00044 steers one action. The cause is the ThM tier (Attacked against Unreported). Section 3.2 of the specification says scores within the same band are equivalent for prioritisation and should not be ranked by decimal, so by the specification's own guidance there is no inversion; the conformance statement keeps that reading and AVE tooling should not rank by decimal within a band.
- **Where the check fails.** The six CRITICAL classes sit between 9.0 and 9.8, separated by a few tenths that section 3.2 says not to rank on, and at a Factor_Sum of 6.5 or more every base of 7.0 or more scores 8.9 or higher. That follows from the equation (the conformance statement's section 5.4), not from the pilot's choices.

## What the pilot changed in the statement

1. **Persistence.** The first pass scored a committed configuration (00063) 1.0 and installed components 0.5, following OWASP's 3.6.2 and 3.6.8 inconsistently. The statement now reserves 1.0 for the agent's own memory or retained state, and 00063 was re-scored (Persistence 0.5, 6.7 MEDIUM instead of 6.8).
2. **Subsequent systems.** The literal reading of 3.1.1 set `SC:H/SI:H` for every steering class, with bases near 9.4. OWASP's other nine examples do not, and the statement now scores them only for propagation the class states (decision D2).
3. **Context.** Adopted from draft PR #401's rule: 1.0 when runtime content carries the exploit, 0.5 for one static source, 0 when independent of what the agent reads. It decided 00001, 00020 and 00044.

Separately, the S01 task's `aivss_v08.py` was found to misround 36 of 19,089 grid inputs (see the statement's section 3). No pilot score was affected, because all pilot scores were computed in exact decimal arithmetic.

## Limits

- Ten records, one assessor, no independent second assessment. The vectors and the factors are judgements; section "Sensitivity" shows how much a different judgement can move a band.
- The ten are not a sample: six were named, two chosen to cover bands, two to cover entry classes. Their frequencies must not be scaled up to the 89 records.
- Coverage is partial (see the selection rule): one `mcp_server`, no `agent` component, 8 of 13 entry classes.
- The ThM tiers rest on the references each record cites today. Four of the ten (00024, 00039, 00046, 00058) cite nothing that demonstrates the class; the tier would change if a primary source is found (the quality queue has the 22 records that have none).
- Nothing was checked against NVD or against a vendor's own CVSS vector for the nearest instances (for example CVE-2026-33068).
- The vectors were derived before decision D17 was approved (2026-11-05) and are not re-derived here. Its parts 2 and 4 (the reasonable worst case, and subsequent systems by security domain) may change some of them; S03a re-derives them. The pilot's value now is as evidence of how much the outcome moves, not as scores to apply.

## Reproduction

The data file `docs/audits/aivss-v0.8-pilot.json` holds, for each record, the vector, the base score, the ten factors, ThM, Mitigation_Factor, Factor_Sum, AARS, the score and the band, in Appendix A's shape; it validates against that schema as transcribed from the specification. To recompute: score each `vector_string` with both CVSS v4.0 implementations named above; compute `AARS = (10 - base) x (factor_sum / 10) x threat_multiplier` and `score = RoundHalfUp((base + AARS) x mitigation_factor, 1)` in decimal arithmetic (the statement's section 3 has the reference form). The exact arithmetic is `scripts/aivss_v08.py`, with its tests in `tests/test_aivss_v08.py` (part of this change). The CVSS scoring harness, the sensitivity script and the Appendix A validator used here are not part of this change.
