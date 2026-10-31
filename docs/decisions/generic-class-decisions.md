# Generic-class decisions

Decided by the maintainer on 2026-10-31, recorded here for issue #410. No record is changed by this document: it states what was decided and why, so that the pull requests that apply each decision can point at it.

## What this covers

The capability-vulnerability audit ([`docs/audits/capability-vulnerability-audit.md`](../audits/capability-vulnerability-audit.md)) classified 16 of 80 records as generic vulnerabilities (classification E): an existing CWE already names the weakness, so a record's claim to be a distinct AVE class rests on an agentic-specific distinction. The audit's own summary lists the 16 (line 2058). Thirteen are full seven-question sections; 00040, 00053 and 00060 are in the audit's compact section, a single line marked `**E**`, so a parser that reads only the full sections finds 13 and misses them.

Discussion [#234](https://github.com/orgs/aveproject/discussions/234) has been open since 2026-08-29 on 00052, 00053 and 00060. On 2026-10-08 the maintainer proposed deprecating them, checked against the records (00052 and 00060 cite CWE-78, 00053 cites CWE-22, each says in its own text that it is an implementation flaw), and left it open for objections until 15 October. The cfgaudit crosswalk's author replied that none of the three is mapped to a cfgaudit rule, so nothing changes for them. The discussion had not been decided.

| Record | Title | Audit decision, confidence | Decision |
|---|---|---|---|
| 00004 | Arbitrary code execution via shell pipe injection in agentic component | JUSTIFY, HIGH | JUSTIFY |
| 00005 | Recursive file system destruction via destructive command injection in agentic component | JUSTIFY, HIGH | JUSTIFY |
| 00033 | Unsafe Deserialization or Eval Instruction | JUSTIFY, HIGH | JUSTIFY |
| 00035 | Environment or Sensor Data Manipulation | JUSTIFY, MEDIUM | JUSTIFY-IF-WRITTEN |
| 00040 | Insecure Output - Unescaped Injection into Downstream System | JUSTIFY, no confidence stated | JUSTIFY |
| 00047 | Hardcoded credentials in agent component - API keys and secrets exposed in skill files | JUSTIFY, HIGH | JUSTIFY |
| 00049 | HTTP Host Header Injection via Agent-Initiated Request (BadHost) | JUSTIFY, LOW | DEFER |
| 00052 | Command injection via unsanitized tool-call parameter in MCP server implementation | JUSTIFY, LOW | REJECT |
| 00053 | Path traversal via unsanitized path parameter in MCP resource/file-handler implementation | JUSTIFY, LOW | REJECT |
| 00054 | Code-execution sandbox escape via JavaScript prototype-chain traversal | JUSTIFY, LOW | DEFER |
| 00060 | STDIO transport shell injection via unsanitized tool call parameters | JUSTIFY, MEDIUM | REJECT |
| 00061 | TLS certificate verification disabled in agent component configuration | DEPRECATE-OR-JUSTIFY, LOW | REJECT |
| 00062 | Unpinned dependency version allowing supply chain substitution | JUSTIFY-OR-MERGE, LOW | DEFER |
| 00072 | MCP server bound to all network interfaces with no authentication step (NeighborJack) | JUSTIFY, MEDIUM | JUSTIFY-IF-WRITTEN |
| 00073 | Telemetry or API endpoint redirect via static configuration value | JUSTIFY, HIGH | JUSTIFY |
| 00075 | Bytecode poisoning: compiled .pyc cache diverges from its own reviewed .py source | JUSTIFY, HIGH | JUSTIFY |

- **JUSTIFY** (7): the record stays and its `vulnerability_rationale` states the agentic-specific distinction. 00004, 00005, 00033 and 00040 also need a primary source found.
- **JUSTIFY if written** (2): 00035 and 00072 stay only if their records state the agentic distinction and answer the audit's Q6 (would a deterministic program with the same flaw have essentially the same vulnerability?). If they are not written, they are rejected.
- **DEFER** (3): 00049, 00054 and 00062 stay as they are, deferred on 2026-10-31. Before the 2.0.0 release each either states the distinction or is rejected (00062 may instead be merged into an active record).
- **REJECT** (4): 00052, 00053, 00060 and 00061 get `status: rejected`, through one public decision on #234. The pull request that changes their status opens a week after that decision is posted.

## The shared rationale

The weakness these records name is conventional, and the audit says so: its Q6 answer for 00004 is that a deterministic program which pipes untrusted configuration into a shell has the same flaw. What makes them AVE classes is the channel the weakness arrives through. The attacker's input is not code that a program runs. It is natural-language content, such as a skill body, a manifest or a configuration value, that an agent reads and treats as an instruction or as context. Tools built to find the same weakness in code, such as SAST and secret scanners, do not read that channel, so the flaw stays invisible to them until the agent has acted on it.

A record on this footing says that the mechanism is conventional, names the channel, and says what a code-oriented tool misses. This text is meant to be copied into each record's `vulnerability_rationale` and extended with the record's own point.

It fits 00004, 00005 and 00033 in full. 00047 and 00075 use its second half (tools built for code do not look where the weakness sits) but each rests mainly on a stated argument of its own, given under the record. 00040 and 00073 rest on their own arguments and use the shared text only for the framing.

## The records

### AVE-2026-00004: Arbitrary code execution via shell pipe injection in agentic component

> Component instructs the agent to pipe remote content into a shell interpreter (curl|bash, wget|sh, eval(requests.get(...))).

- **Audit:** lines 679 to 717, classification E, decision JUSTIFY, confidence HIGH.
- **Weakness it names:** Command injection (CWE-78 territory; the record also cites CWE-77) delivered as `curl | bash` style directives in natural-language instructions.
- **The audit's agentic-specific distinction:** Stated in the record and held up by the audit: SAST finds command injection in code, not in natural-language instructions that produce the same effect once an agent follows them. The mechanism is conventional; the channel that evades conventional tooling is the agentic part.
- **Concrete or only asserted:** Concrete, and already in the record.
- **Decision:** JUSTIFY. The audit's Q6 answer cuts against novelty, but the record already names its real distinction, so it stays as a separate class and is not merged into generic CWE-78. The shared rationale applies in full.
- **Next step:** Add the shared rationale to `vulnerability_rationale`. The references are CWE-78, CWE-77, an OWASP Top 10 page and the record's own file, so a primary source has to be found (`find_primary_source`).
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-owasp-mcp.md`, `cfgaudit-to-ave.md`, `clawscan-to-ave.md`, `skillspector-to-ave.md`.

### AVE-2026-00005: Recursive file system destruction via destructive command injection in agentic component

> Component instructs the agent to execute recursive deletion commands on broad filesystem paths or system directories.

- **Audit:** lines 718 to 752, classification E, decision JUSTIFY, confidence HIGH.
- **Weakness it names:** Destructive command patterns (`rm -rf /` class) in natural-language setup or cleanup instructions.
- **The audit's agentic-specific distinction:** The same natural-language-delivery argument as 00004, already stated. The audit also keeps it apart from 00004 because the impact differs: irrecoverable data loss with no code-execution requirement, a severity and detection distinction and not only a label.
- **Concrete or only asserted:** Concrete, inherited from 00004 with one added distinction.
- **Decision:** JUSTIFY. Structurally near-identical to 00004, which the audit flagged for a cross-record pass to confirm the two are worth keeping apart. The audit leaned yes on the impact difference, and so does this decision. If that pass later finds them redundant, the route is a merge into 00004, not a rejection.
- **Next step:** Shared rationale plus the impact distinction. A primary source is needed: the references are CWE-78, CWE-20, an OWASP LLM Top 10 project page and the record's own file.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-owasp-mcp.md`, `cfgaudit-to-ave.md`, `clawscan-to-ave.md`, `skillspector-to-ave.md`.

### AVE-2026-00033: Unsafe Deserialization or Eval Instruction

> Component instructs the agent to deserialize untrusted data using insecure methods (pickle, yaml.load, eval) or to evaluate dynamic code strings received from external or user-controlled sources, enab (as quoted here, cut off at 200 characters; repaired in #414, see "Not in the audit" below)

- **Audit:** lines 753 to 783, classification E, decision JUSTIFY, confidence HIGH.
- **Weakness it names:** Unsafe deserialization or eval (CWE-502 and CWE-94) instructed in natural language: `pickle.loads`, unguarded `yaml.load`, `eval` or `exec` on untrusted strings.
- **The audit's agentic-specific distinction:** The same argument and standard of evidence as 00004 and 00005; it is the third member of the family.
- **Concrete or only asserted:** Concrete, inherited.
- **Decision:** JUSTIFY. Consistent treatment with the family: it stays, on the same justification.
- **Next step:** Shared rationale. A primary source is needed: the references are CWE-502, CWE-94, an OWASP Top 10 page and the record's own file.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-opencre-pilot-DRAFT.md`, `ave-to-opencre-pilot-mapping-READABLE.md`, `ave-to-owasp-mcp.md`, `clawscan-to-ave.md`, `skillspector-to-ave.md`.

### AVE-2026-00035: Environment or Sensor Data Manipulation

> Component instructs the agent to fabricate, alter, or suppress sensor readings, environment observations, or system state reports to deceive operators or downstream agents.

- **Audit:** lines 118 to 161, classification E, decision JUSTIFY, confidence MEDIUM.
- **Weakness it names:** Telemetry and sensor integrity (CWE and ICS territory): no provenance or integrity check between a tool's real output and what is reported to a decision-maker.
- **The audit's agentic-specific distinction:** Real but not written down. The audit says the Q6 test cuts against the record as it stands, because a deterministic reporting pipeline with the same integrity gap has essentially the same vulnerability. What is agentic is narrower: a natural-language-driven relay can be told, in plain English, to misreport, without the hardware or firmware compromise that conventional telemetry spoofing needs.
- **Concrete or only asserted:** Real but unwritten: nothing in the record's text states it.
- **Decision:** JUSTIFY-IF-WRITTEN. It stays only if the record states that distinction and answers Q6 in its own words. As written it cannot be told apart from the generic telemetry-integrity class that CWE already covers.
- **Next step:** In its batch, write the instructable-fabrication distinction and the Q6 answer into `vulnerability_rationale`. If they cannot be written honestly, reject it.
- **Cited in crosswalks:** `ave-to-owasp-mcp.md`.

### AVE-2026-00040: Insecure Output - Unescaped Injection into Downstream System

> Component instructs the agent to produce output that will be directly interpreted by a downstream system (SQL database, HTML renderer, shell) without escaping or sanitisation, enabling classic injecti (as quoted here, cut off at 200 characters; repaired in #414, see "Not in the audit" below)

- **Audit:** lines 1659 to 1669, classification E, decision JUSTIFY, confidence not stated (compact entry).
- **Weakness it names:** Classic injection (CWE-79, CWE-89, CWE-116 territory) through agent output passed unescaped to a downstream interpreter (SQL, HTML, shell).
- **The audit's agentic-specific distinction:** The audit's compact entry gives one line: the agentic amplification is the trust elevation that backend systems grant an agent compared with raw user input, which draws less scrutiny.
- **Concrete or only asserted:** Concrete in the audit's line, but a compact verdict is not a seven-question pass, and the record's own text (an instruction to produce output that is interpreted without escaping) does not say it.
- **Decision:** JUSTIFY. The trust-elevation point is a distinction a deterministic program does not have, and it is specific to an agent acting as a trusted intermediary. It stays.
- **Next step:** In its batch, write the full seven-question pass, put the trust-elevation distinction in `vulnerability_rationale`, and find a primary source: its references are CWE-79, CWE-116, an OWASP LLM Top 10 page and the record's own file.
- **Cited in crosswalks:** `ave-to-owasp-mcp.md`, `skillspector-to-ave.md`.

### AVE-2026-00047: Hardcoded credentials in agent component - API keys and secrets exposed in skill files

> Skill file contains a high-entropy string adjacent to a credential keyword such as api_key, secret, token, password, or a known key format prefix such as sk- or Bearer. The credential is a literal value, not an environment variable reference or secrets manager path.

- **Audit:** lines 784 to 823, classification E, decision JUSTIFY, confidence HIGH.
- **Weakness it names:** Hardcoded secrets in source (CWE-798).
- **The audit's agentic-specific distinction:** Stated in the record and held up by the audit: a credential in a skill file sits in the same context window an LLM reads, so a prompt-injection payload elsewhere in that context can instruct the agent to read and exfiltrate it. A deterministic program reading the same file has no such boundary.
- **Concrete or only asserted:** Concrete, and already in the record.
- **Decision:** JUSTIFY. A conventional root cause with a real, stated amplification that a secrets-scanner finding would not capture. It stays, and it rests on this argument more than on the shared one.
- **Next step:** Add the amplification to `vulnerability_rationale`; the shared text supplies only the framing. It already has references beyond taxonomy pages.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-opencre-pilot-DRAFT.md`, `ave-to-opencre-pilot-mapping-READABLE.md`, `ave-to-owasp-ai-exchange.md`, `ave-to-owasp-mcp.md`, `cfgaudit-to-ave.md`, `clawscan-to-ave.md`.

### AVE-2026-00049: HTTP Host Header Injection via Agent-Initiated Request (BadHost)

> Component sets or overwrites the HTTP Host header on outbound requests to a value that does not match the declared target endpoint's natural host. The injected host points to attacker infrastructure. Pattern also manifests as X-Forwarded-Host, X-Original-URL, or Forwarded header manipulation that causes server-side request routing to an unintended destination.

- **Audit:** lines 824 to 867, classification E, decision JUSTIFY, confidence LOW.
- **Weakness it names:** HTTP Host-header attack, a well-documented web-security class (the audit cites PortSwigger's research).
- **The audit's agentic-specific distinction:** None stated. The audit calls it the weakest-justified record of its group. It names a plausible distinction that is not written down: an agent often builds request parameters, headers included, from content it has just processed, so an attacker-controlled header value is reachable through indirect prompt injection and does not need direct access to the client.
- **Concrete or only asserted:** Unwritten, plausible.
- **Decision:** DEFER. Without that argument the record reads as a port of a known web class, and the audit named merge or deprecate as the reasonable alternative. It is deferred, not rejected, so that the argument can be written if it holds.
- **Next step:** Deferred on 2026-10-31. Before the 2.0.0 release either the record states the injection-reachability argument, with evidence, or it is rejected.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-owasp-mcp.md`, `clawscan-to-ave.md`, `skillspector-to-ave.md`.

### AVE-2026-00052: Command injection via unsanitized tool-call parameter in MCP server implementation

> MCP tool handler code passes a caller-supplied tool-call parameter value directly into a shell or system-command execution function without sanitization, executing arbitrary OS commands under the server process's privileges -- independent of any agent instruction or prompt content.

- **Audit:** lines 868 to 912, classification E, decision JUSTIFY, confidence LOW.
- **Weakness it names:** OS command injection (CWE-78) in an MCP server's own tool handler.
- **The audit's agentic-specific distinction:** None at the mechanism level. The audit says it is not an agentic vulnerability in any behavioral sense, and the record itself says the attack is independent of any agent instruction or prompt content. The only argument is a coverage one: prompt-injection scanners, which dominate this space, cannot find it, because there is no instruction text to match.
- **Concrete or only asserted:** Asserted only, and as a coverage argument, not a mechanism.
- **Decision:** REJECT. The audit called this its hardest call and asked whether the coverage argument is enough for a distinct record, or whether the record belongs with general AppSec tooling that cross-references AVE. The decision is that it is not enough: swap the model for a deterministic program and the mechanism is unchanged, and CWE-78 names it.
- **Next step:** Rejected through the decision on #234; `rejection_reason` is that comment's URL. Its references (a ZDI advisory, an NVD entry and a Snyk advisory) stay on the record.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-owasp-ai-exchange.md`, `ave-to-owasp-mcp.md`, `cfgaudit-to-ave.md`, `skillspector-to-ave.md`. SkillSpector's crosswalk notes it as pending deprecation and records no mapping; cfgaudit has it only in its gaps section.

### AVE-2026-00053: Path traversal via unsanitized path parameter in MCP resource/file-handler implementation

> MCP resource or file-handler tool's own path-validation code fails to canonicalize and contain a caller-supplied path or URL parameter, allowing directory-traversal sequences to read or write files and resources outside the tool's declared scope.

- **Audit:** lines 1741 to 1752, classification E, decision JUSTIFY, confidence LOW.
- **Weakness it names:** Path traversal (CWE-22) in an MCP resource or file handler.
- **The audit's agentic-specific distinction:** None beyond the coverage argument. The audit's compact entry poses the same open question as for 00052 (coverage argument against genuine behavioral distinction) and gives the same verdict, JUSTIFY at low confidence.
- **Concrete or only asserted:** Asserted only.
- **Decision:** REJECT. The same class of mechanism as 00052, a caller-supplied value reaching a sensitive sink in the tool's own code independent of any agent instruction, and the same answer.
- **Next step:** Rejected with 00052 through #234. Its references (three NVD entries) stay on the record.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-opencre-pilot-DRAFT.md`, `ave-to-opencre-pilot-mapping-READABLE.md`, `ave-to-owasp-ai-exchange.md`, `ave-to-owasp-mcp.md`, `cfgaudit-to-ave.md`. cfgaudit has it only in its gaps section.

### AVE-2026-00054: Code-execution sandbox escape via JavaScript prototype-chain traversal

> A code-execution tool's sandbox fails to contain a submitted payload that uses prototype-chain traversal to reach the host JavaScript or Python runtime, achieving code execution with host-level privileges outside the tool's declared execution boundary.

- **Audit:** lines 913 to 952, classification E, decision JUSTIFY, confidence LOW.
- **Weakness it names:** Sandbox escape through JavaScript prototype-chain traversal, a pre-LLM, well-studied containment-failure class.
- **The audit's agentic-specific distinction:** Not strongly stated. The record separates itself from 00042 (how malicious code gets in) by scope (what happens once code is running) but does not argue why an agent-execution sandbox is more exposed than any other. The audit names a plausible angle that is not in the record: LLM-generated code can trigger prototype-chain patterns without adversarial intent more often than human-written code, widening the practical trigger surface.
- **Concrete or only asserted:** Unwritten, plausible.
- **Decision:** DEFER. The angle is statable but unevidenced. It is deferred so that it can be written, with evidence, or the record rejected.
- **Next step:** Deferred on 2026-10-31. Before the 2.0.0 release the record states the distinction or is rejected.
- **Cited in crosswalks:** `ave-to-ast10.md`, `ave-to-owasp-mcp.md`.

### AVE-2026-00060: STDIO transport shell injection via unsanitized tool call parameters

> Tool call parameters containing shell metacharacters (backticks, pipes, semicolons, command substitution syntax) are passed to a host shell without escaping or parameterization, resulting in execution of attacker-controlled shell commands rather than the parameter being treated as inert string data.

- **Audit:** lines 1796 to 1808, classification E, decision JUSTIFY, confidence MEDIUM.
- **Weakness it names:** OS command injection (CWE-78) in shared MCP SDK STDIO transport code.
- **The audit's agentic-specific distinction:** A stronger argument than for 00052 and 00053, in the audit's words: the flaw lives in shared SDK code, so the blast radius spans every server built on an affected SDK. It remains a flaw independent of any agent instruction, and the audit gave only medium confidence.
- **Concrete or only asserted:** Stated, but it is an argument about reach, not about mechanism.
- **Decision:** REJECT. Reach is a severity argument. The mechanism test (swap the model for a deterministic program) gives the same flaw. 00060 is the strongest of the four rejections and the one most easily argued the other way, and the decision is to treat it with its two siblings, as #234 does. Its references are a vendor homepage, a CWE-78 page and its own file, so even on its merits it lacks a citable primary source.
- **Next step:** Rejected through #234. The record's credit (`researcher`) is part of the record and stays with it.
- **Cited in crosswalks:** `cfgaudit-to-ave.md`. cfgaudit has it only in its gaps section, where its note says the flaw needs analysis of the server's source and not a read of its launch configuration.

### AVE-2026-00061: TLS certificate verification disabled in agent component configuration

> Configuration explicitly sets a TLS verification bypass flag (verify=False, rejectUnauthorized: false, or equivalent) for the component's own outbound network calls, rather than relying on default, enforced certificate validation.

- **Audit:** lines 953 to 991, classification E, decision DEPRECATE-OR-JUSTIFY, confidence LOW.
- **Weakness it names:** TLS certificate verification disabled in a component's configuration (CWE-295, an insecure-configuration weakness).
- **The audit's agentic-specific distinction:** None stated, and the audit found none obvious: it calls this the weakest agentic-distinction candidate it saw. It names a plausible one that the record does not state: a tampered response over an unverified connection often becomes direct agent context that the model acts on, where a traditional application might only render it for a human to judge.
- **Concrete or only asserted:** Absent from the record; the plausible argument is unwritten.
- **Decision:** REJECT. The audit recommended either writing that argument or treating this as a CWE-295 crosswalk entry, not a standalone record. The decision is the second. It is the closest call of the four, but the record states no mechanism that CWE-295 does not already cover.
- **Next step:** Rejected through #234, which pings cfgaudit's author first, because 00061 is the one of the four that a crosswalk maps.
- **Cited in crosswalks:** `ave-to-opencre-pilot-DRAFT.md`, `ave-to-opencre-pilot-mapping-READABLE.md`, `ave-to-owasp-ai-exchange.md`, `cfgaudit-to-ave.md`, `skillspector-to-ave.md`. cfgaudit maps CFG075 to it and emits the id. SkillSpector's crosswalk cites it in rows SC7, TM1 and TM3.

### AVE-2026-00062: Unpinned dependency version allowing supply chain substitution

> A component's declared dependency references a mutable version specifier (a floating tag, a version range with no upper bound, an unpinned package name with no hash or lockfile entry) rather than a specific, content-addressed or exact-version reference.

- **Audit:** lines 992 to 1036, classification E, decision JUSTIFY-OR-MERGE, confidence LOW.
- **Weakness it names:** Unpinned dependency versions allowing supply-chain substitution (dependency-confusion territory).
- **The audit's agentic-specific distinction:** Not stated, and weaker than its neighbours 00074 (dead-anchor reclamation: the pin was correct when written) and 00066 (hallucinated-name squatting: the attack surface is the model's own hallucination), which cover the interesting edges. The audit's candidates are a merge into a broader agentic-supply-chain umbrella (with 00074, 00075, 00034 and 00066) or an explicit argument, such as agent-approved dependency changes moving faster and with less review than conventional ones.
- **Concrete or only asserted:** Unwritten, and weaker than its siblings.
- **Decision:** DEFER. The audit decision was JUSTIFY-OR-MERGE at low confidence. It is deferred so that the choice between an argument, a merge into an active record and a rejection is made once.
- **Next step:** Deferred on 2026-10-31. Before the 2.0.0 release it states the distinction, is merged (`merged_into` an active record) or is rejected. Its references are only taxonomy pages and its own file.
- **Cited in crosswalks:** `ave-to-maestro.md`, `cfgaudit-to-ave.md`, `skillspector-to-ave.md`. cfgaudit's crosswalk says this record closes the supply-chain pinning surface, so any outcome other than keeping it reaches cfgaudit.

### AVE-2026-00072: MCP server bound to all network interfaces with no authentication step (NeighborJack)

> An MCP server's declared args or env set its bind address to the wildcard 0.0.0.0 or [::] rather than a loopback address or an explicitly scoped, narrower interface, with no accompanying authentication requirement for incoming connections.

- **Audit:** lines 1037 to 1077, classification E, decision JUSTIFY, confidence MEDIUM.
- **Weakness it names:** Binding a server to all network interfaces with no authentication (CWE-284 territory), documented as the pattern called NeighborJack.
- **The audit's agentic-specific distinction:** Better justified than 00061 and 00062, and prevalence-based: MCP servers commonly ship with no authentication on the assumption that only a local, already-trusted caller can reach them, an assumption that binding to 0.0.0.0 silently breaks. The audit calls it an ecosystem argument and not a mechanism one, but a real and citable one.
- **Concrete or only asserted:** Stated, and prevalence-based.
- **Decision:** JUSTIFY-IF-WRITTEN. It stays only if the record states the prevalence argument and answers Q6 in its own words: it should say that the design assumption, and not the misconfiguration alone, is what makes this an AVE class.
- **Next step:** In its batch, write the argument and the Q6 answer into `vulnerability_rationale`, or reject it. Its references are only taxonomy pages and its own file, so a primary source is needed (`find_primary_source`).
- **Cited in crosswalks:** `cfgaudit-to-ave.md`, `skillspector-to-ave.md`.

### AVE-2026-00073: Telemetry or API endpoint redirect via static configuration value

> A component's committed configuration sets a telemetry exporter endpoint, a model/provider base URL, an MCP server URL, an agent_card_url, or an equivalent traffic-destination value to a host other than the component's own declared or default provider, or to a host reachable only over cleartext http://, with no accompanying instruction text and no content injected into the model's context.

- **Audit:** lines 1078 to 1117, classification E, decision JUSTIFY, confidence HIGH.
- **Weakness it names:** Configuration-based traffic redirection of endpoints specific to agentic systems: LLM provider base URLs, MCP server URLs and A2A agent-card URLs.
- **The audit's agentic-specific distinction:** Strong and well sourced: the record cites a real CVE (CVE-2026-21852) in which a redirected `ANTHROPIC_BASE_URL` leaked a user's API key, and the endpoint types exist only because the component is agentic.
- **Concrete or only asserted:** Concrete and cited. The audit calls it the best-justified record of its group.
- **Decision:** JUSTIFY. It stays as is. It rests on its own cited argument and not on the shared natural-language text.
- **Next step:** Add the argument to `vulnerability_rationale`, so that it is stated in the record and not only in the audit.
- **Cited in crosswalks:** `cfgaudit-to-ave.md`, `skillspector-to-ave.md`.

### AVE-2026-00075: Bytecode poisoning: compiled .pyc cache diverges from its own reviewed .py source

> A skill package contains a .pyc (or .pyo) file whose disassembled bytecode references dangerous primitives (os.system, subprocess, eval, exec, socket, urlopen, credential file paths such as .aws/credentials or .ssh/id_) that do not appear anywhere in its sibling .py source's own text, meaning the compiled artifact the interpreter will actually load and execute contains capability its reviewed source does not show.

- **Audit:** lines 1118 to 1166, classification E, decision JUSTIFY, confidence HIGH.
- **Weakness it names:** Bytecode poisoning: the interpreter prefers a compiled `.pyc` that diverges from its reviewed `.py` source (a general interpreter property, not agent-specific in mechanism).
- **The audit's agentic-specific distinction:** Strong and well sourced: the record frames it, citing research from the CSA AI Safety Initiative and Trail of Bits, as a technique for evading agent-skill scanners specifically, which document their own inability to analyze binary or encrypted code. It is already differentiated from 00057.
- **Concrete or only asserted:** Concrete and cited.
- **Decision:** JUSTIFY. It stays as is. It uses the second half of the shared rationale (tools built for code do not look where the weakness sits) and keeps its own sourced argument.
- **Next step:** Add the argument to `vulnerability_rationale`.
- **Cited in crosswalks:** `skillspector-to-ave.md`.

## The work queue

[`quality-queue.json`](quality-queue.json) has one entry per record (all 89):

| Field | Holds |
|---|---|
| `audit_classification`, `audit_decision` | the audit's classification (A to F) and its decision (RETAIN, CLARIFY, REFRAME, REWRITE, JUSTIFY, DEPRECATE-OR-JUSTIFY, JUSTIFY-OR-MERGE); null for 00081 to 00089, which were published after the audit |
| `audit_label` | the verdict group in the audit's summary |
| `has_taxonomy_fields` | whether the record carries `security_boundary`, `missing_control` and `vulnerability_rationale` (true only for 00081 to 00089) |
| `d7_decision` | the decision above, for the 16 generic-class records |
| `actions` | what the record needs, from the list below |
| `later_actions` | actions that wait for something, each with what it waits for (`after`); empty for most records |
| `needs_maintainer_approval` | the actions and later actions among `clarify_fingerprint`, `reframe_fingerprint`, `rewrite`, `rewrite_fingerprint` and `reject`. Fingerprint changes are content changes that the compatibility and mutation rules govern, so the work that applies the audit never makes them on its own |
| `batch` | a number, ten records per batch |

| Action | Means |
|---|---|
| `add_taxonomy_fields` | add `security_boundary`, `missing_control` and `vulnerability_rationale` from the audit. 45 audit sections are compact, so for those the fields come from the compact line and the batch flags any where it is too thin |
| `clarify_fingerprint`, `reframe_fingerprint`, `rewrite` | the audit decisions CLARIFY (23 records), REFRAME (2) and REWRITE (1) |
| `rewrite_fingerprint` | a later action: reword the fingerprint from the record's own sources (its references, description and audit entry), in a separate pull request after catalog release v1.3.0. For the seven records whose cut-off fingerprint was restored to an older, shorter sentence (see below) |
| `write_rationale` | JUSTIFY: state the agentic distinction in `vulnerability_rationale` (the shared text above, plus the record's own point) |
| `write_rationale_or_reject` | JUSTIFY if written: state it and answer Q6, or reject |
| `defer_decision` | DEFER: decide before the 2.0.0 release |
| `reject` | REJECT: set `status: rejected` and a `rejection_reason` linking the decision on #234; a week after that decision is posted |
| `find_primary_source` | the record's references are only taxonomy pages, homepages or links back to AVE (CWE, OWASP, ATLAS or ATT&CK pages; a bare site address; a `github.com/aveproject` or `aveproject.org` link). Rule 9 asks for at least one citable primary source |
| `verify_framework_mappings` | `owasp_asi`, `owasp_mcp`, `mitre_atlas` and `nist_ai_rmf` verified from the primary source, left to the schema 2.1.0 work (issue #178); listed so that the queue is complete. Records being rejected do not carry it |

**Batches.** Ten records per batch, in this order: the 64 records that need no decision (batches 1 to 7, in id order), the seven JUSTIFY records (batches 7 to 8), the two JUSTIFY-if-written records (batch 8), 00081 to 00089 (batches 8 to 9), then the three deferred records (batch 9, waiting for their deadline) and last the four rejected ones (batch 9, waiting until the decision on #234 is a week old). The last batch is therefore the one that cannot be done early.

**Primary sources.** Twenty-two records have references that are only taxonomy pages, homepages or links back to AVE: 00003, 00004, 00005, 00006, 00012, 00013, 00014, 00017, 00022, 00024, 00026, 00030, 00032, 00033, 00034, 00039, 00040, 00060, 00061, 00062, 00071, 00072. 00060 and 00061 are among them and are being rejected, so they carry no `find_primary_source`; the other twenty do. The list is computed from the references by the rule in the table, so it can be recomputed, and it matches the maintainer's own list of 22 by id.

**Not in the audit: truncated fingerprints.** Eight records had a `behavioral_fingerprint` that stopped mid-word at exactly 200 characters: 00023, 00026, 00029, 00030, 00033, 00038, 00039, 00040. The schema sets no length limit, and the pre-migration versions of the same records are complete sentences of 104 to 158 characters, so the cut first appeared in the AIVSS migration commits of 2026-05-12 and 2026-05-13 (#17 and #18), which replaced each short sentence with a longer one that was stored cut at 200 characters. The history holds only those two versions of each record, so the complete longer text was never committed. They were repaired in #414 (pull request #415): 00030 is completed to "backdoor", a word its description uses, and the other seven are restored to the sentence each had before the migration, because the cut text could not be completed from the record's own words. The restored sentences are shorter and older than the rewrites the migration meant to make, so the queue carries `rewrite_fingerprint` for those seven (00023, 00026, 00029, 00033, 00038, 00039, 00040) as a later action: reword each from its own sources, in a separate pull request after catalog release v1.3.0. 00033 and 00040 are among the sixteen generic-class records.

**Not in the queue.** `credit_correction`: the researcher-credit audit (`docs/audits/researcher-credit-audit.json`) is not in the repository yet, so no entry carries it. Score changes: none planned. Rewording a fingerprint or changing a score is a content change; each needs the maintainer's approval first.

## For the rejection pull request

- `rejection_reason` is the URL of the decision comment on #234, once it is posted; it is not known before then.
- cfgaudit maps CFG075 to AVE-2026-00061 (`cfgaudit-to-ave.md`, and `avemap.go` in cfgaudit), and emits that id in its JSON and SARIF output, so rejecting 00061 changes cfgaudit's output. Its author is asked on #234 how to handle the row. The crosswalk is theirs to change, and it is not changed before they answer.
- cfgaudit's crosswalk also says AVE-2026-00062 closes the supply-chain pinning surface, so a decision on 00062 reaches it too.
- `skillspector-to-ave.md` cites 00061 in rows SC7, TM1 and TM3, and 00052 in notes (TT5, AST4) that already say it is pending deprecation and record no mapping; the pull request moves those rows.
- Other crosswalk files that cite the four are listed under each record above.
