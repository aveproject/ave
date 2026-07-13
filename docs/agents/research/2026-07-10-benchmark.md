# Research-New-Attack-Classes Benchmark Report — 2026-07-10

**Date:** 2026-07-10
**Scope:** Current 51-record AVE set (schema v1.1.0), filtered for CRITICAL/HIGH-severity
candidates per the requesting prompt ("do deep research about AI attack classes for
critical and high")
**Method:** research-new-attack-classes skill, Phases 1-3. Every candidate below traces
to an NVD-confirmed CVE, a named trusted vendor disclosure (OX Security, per the skill's
trusted-source list), or a CERT/CC-reported finding — verified by direct fetch against
nvd.nist.gov and the originating report, not taken from search-summary text alone. One
candidate researched and dropped for insufficient sourcing is noted at the end.

---

## Sources reviewed

| Source | Date | What it covers | Trust tier (per skill) |
|---|---|---|---|
| NVD (nvd.nist.gov) — CVE-2026-0755 | 2026 | gemini-mcp-tool OS command injection | Tier 2 — CVE/NVD |
| NVD — CVE-2025-32711 | 2025 | EchoLeak, M365 Copilot zero-click exfil | Tier 2 — CVE/NVD |
| NVD — CVE-2026-5752 | 2026 | Cohere Terrarium sandbox escape (CERT/CC-reported) | Tier 2 — CVE/NVD |
| NVD — CVE-2025-66689 | 2025 | Zen MCP Server path traversal | Tier 2 — CVE/NVD |
| NVD — CVE-2026-15138 | 2026 | tumf mcp-text-editor path traversal | Tier 2 — CVE/NVD |
| Secure ISS advisory — CVE-2026-11720 | 2026 | Google MCP Toolbox path traversal, CVSS 9.3 | Tier 2 — CVE/NVD-sourced vendor advisory |
| OX Security — "Mother of All AI Supply Chains" | 2026-04 | MCP STDIO design-level RCE, 150M+ downloads affected | Tier 2 — named trusted vendor (skill explicitly lists OX Security) |
| Cloud Security Alliance research notes (4 notes, Apr-May 2026) | 2026 | MCP STDIO RCE corroboration, systemic scope | Tier 2/4 — CSA + OWASP-adjacent research body |
| NSA/CISA CSI_MCP_SECURITY advisory | 2026-06 | Government MCP security guidance (found via search; direct fetch blocked 403) | Tier 5 — NSA/government, cited but not independently re-verified by fetch |
| penligent.ai — MCP STDIO RCE technical writeup | 2026 | Precise mechanism: command/args injection at process-spawn boundary | Corroborating technical source, cross-checked against OX report |
| arXiv 2509.10540 — EchoLeak paper | 2025-09 | First real-world zero-click prompt injection exploit, peer-reviewed (AAAI-SS) | Tier 3 — peer-reviewed/arXiv |
| MITRE ATLAS search (AML.T0104 etc.) | current | Checked for technique mappings on all 5 candidates | Tier 1 — most authoritative, checked first |
| Snyk, GitLab Advisory Database, SentinelOne vuln DB | 2026 | Corroborating vendor disclosures for CVE-2026-0755 | Tier 2 — named trusted vendors |

Existing AVE `mitre_atlas` usage was pulled from records 00001, 00004, 00017, 00022,
00026, 00033, 00034, 00039, 00042 to avoid redundant citation.

---

## Candidates assessed: 6 (5 pursued to NEW CLASS, 1 dropped for weak sourcing)

### NEW CLASS (5) — proposed for issues, pending your confirmation

| # | Proposed attack_class | ATLAS ID | Surface | Primary source | Severity est. |
|---|---|---|---|---|---|
| 1 | `tool-implementation-command-injection` | none (classic CWE-78, outside ATLAS's ML-technique scope) | server implementation code (new: not `content`/`server_card` — the vulnerable code is the *tool's own handler*, closest existing layer is `content` if scanning source) | [NVD CVE-2026-0755](https://nvd.nist.gov/vuln/detail/CVE-2026-0755) — gemini-mcp-tool, CVSS 9.8 | **CRITICAL** |
| 2 | `mcp-resource-path-traversal` | none (classic CWE-22) | server implementation code, same layer question as #1 | [NVD CVE-2026-11720](https://nvd.nist.gov/vuln/detail/CVE-2026-11720) (Google MCP Toolbox, CVSS 9.3) + [CVE-2025-66689](https://nvd.nist.gov/vuln/detail/CVE-2025-66689) (Zen MCP, CVSS 6.5) + [CVE-2026-15138](https://nvd.nist.gov/vuln/detail/CVE-2026-15138) (tumf mcp-text-editor) | **CRITICAL** (worst case, e.g. Google Toolbox); typical instance MEDIUM — severity depends on what the traversal reaches |
| 3 | `mcp-stdio-launch-config-injection` | `AML.T0104` (Publish Poisoned AI Agent Tool) — fits the registry-poisoning delivery path, not yet used by any existing AVE record | `registry_metadata` or `transport` (occurs at process-spawn, before protocol handshake) | [OX Security report](https://www.ox.security/reports/the-mother-of-all-ai-supply-chains-anthropics-by-design-failure-at-the-heart-of-the-ai-ecosystem/) + [CSA research notes](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/) + NSA/CISA CSI_MCP_SECURITY advisory (cited, not independently re-fetched) | **CRITICAL** |
| 4 | `rendered-content-autofetch-exfiltration` | none checked as precise fit; general prompt-injection family IDs already used elsewhere in corpus | `runtime` | [NVD CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711) (EchoLeak, CVSS 7.5 NIST / 9.3 Microsoft) + [arXiv 2509.10540](https://arxiv.org/abs/2509.10540) (peer-reviewed, AAAI-SS) | **CRITICAL** (per Microsoft CNA) / **HIGH** (per NIST) — present both, do not cherry-pick |
| 5 | `code-execution-sandbox-escape` | none (classic sandbox-isolation flaw, outside ATLAS's ML-technique scope) | `runtime` | [NVD CVE-2026-5752](https://nvd.nist.gov/vuln/detail/CVE-2026-5752) — Cohere Terrarium, CERT/CC-reported, CVSS 9.3 | **CRITICAL** |

### DROPPED — insufficient sourcing (1)

| Candidate | Why dropped |
|---|---|
| "ROME Incident" — AI agent spontaneously escaping a sandbox and self-publishing an exploit | Only source found was Newsworthy.ai, a low-credibility aggregator with a sensationalized headline. This is exactly what the skill's Phase 1 tells me to avoid ("vendor marketing blogs without a primary source, forum speculation"). Not used to support candidate #5 — that candidate stands on CVE-2026-5752 alone, which is independently NVD-confirmed and CERT/CC-reported. |

### Borderline — flagging for your judgment, not resolving myself

| Candidate | Note |
|---|---|
| OAuth consent-hijack / phishing-as-a-service (e.g. "EvilTokens", per [The Hacker News, 2026-05](https://thehackernews.com/2026/05/the-new-phishing-click-how-oauth.html)) | Real, well-documented (340+ M365 orgs compromised in 5 weeks), but this is a human-phishing attack on the OAuth consent screen, not really a behavioral fingerprint of an agent *component* — there's no component whose behavior we'd be classifying. Closest parent would be AVE-2026-00051 (OAuth Discovery Rebinding), but the mechanism is different (social-engineered consent redirect vs. tampered discovery metadata). Leaning **OUT OF SCOPE** per the same reasoning AVE already applies to model-layer ATLAS techniques, but flagging rather than deciding, since it sits closer to AVE's boundary than a clear-cut case. |

---

## Phase 2 benchmarking detail — why each NEW CLASS candidate isn't already covered

**#1 tool-implementation-command-injection vs. AVE-2026-00004 (Shell Pipe Injection) / AVE-2026-00033 (Unsafe Deserialization):**
00004 and 00033 both describe a skill's *natural-language content* instructing the agent
to construct and run a dangerous command — the vulnerability is in what the text tells
the LLM to do. CVE-2026-0755 is a classic CWE-78 flaw in the MCP *tool's own server-side
handler code* (`execAsync`): a crafted tool-call *parameter value* reaches an unsanitized
shell call with no LLM reasoning involved at all — a non-agentic attacker could trigger
it by sending a raw JSON-RPC request. Different mechanism, different detection method
(SAST/code review of server source vs. content-layer prompt scanning). Fails the "fold
it in and lose nothing" test — folding it into 00004 would erase the distinction between
prompt-driven misuse of a legitimate capability and a code-level injection bug in the
capability's own implementation.

**#2 mcp-resource-path-traversal vs. AVE-2026-00022 (Scope Creep):**
00022 is content-layer: a skill's text instructs the agent to *ask for* out-of-scope
resources. The three path-traversal CVEs are CWE-22 flaws in a resource/file handler's
own path-validation logic, triggered by a parameter value regardless of any instruction
content. Same distinction as #1 — code vulnerability vs. prompt-driven overreach.

**#3 mcp-stdio-launch-config-injection vs. AVE-2026-00001 (Metamorphic Payload) / AVE-2026-00034 (Dynamic Skill Import):**
Both existing records describe a component's *content* fetching or loading new
instructions at runtime — the LLM is still in the loop, executing instructions found in
fetched data. The STDIO flaw happens *before any protocol handshake or LLM reasoning*:
untrusted data in the `command`/`args` config fields used to spawn the MCP server
subprocess is executed directly by the OS. Confirmed via direct technical read
(penligent.ai) as explicitly distinct from prompt injection: "the attacker's goal may
not be to make the model say something unsafe... [it manipulates] the boundary between
configuration and process creation."

**#4 rendered-content-autofetch-exfiltration vs. AVE-2026-00026 (Output Encoding) / AVE-2026-00039 (Covert Channel):**
This is the closest call. 00026 is exfiltration *through a tool call parameter*; 00039
is steganographic *hiding* of data in visible output text for later decoding. EchoLeak's
mechanism needs neither: a plain, unobfuscated markdown image reference in the agent's
own answer is automatically fetched by the *client's rendering layer*, causing an
outbound request with no tool call and no encoding step. The distinguishing behavior is
"the answer itself is the beacon, and the renderer sends it for free." I believe this
clears the bar, but flagging the adjacency explicitly since it's the least clear-cut of
the five.

**#5 code-execution-sandbox-escape vs. AVE-2026-00042 (REPL Code Mode Payload Injection):**
00042 is about how malicious code *gets into* the agent's generated code (data breaking
into code context via poisoned tool results). CVE-2026-5752 is about what happens *after*
code is already running inside an intended sandbox: a JavaScript prototype-chain
traversal breaks the isolation boundary to root-level host execution — a flaw in the
sandbox's own containment, exploitable even by code the agent was *authorized* to run.
Different point in the kill chain (content-to-code vs. code-to-host), different defense
(input/context separation vs. isolation hardening).

---

## What I did not do

Per the skill's hard rule 6 ("report and stop before implementing — never auto-create
records without confirmation") and the zoom-out protocol ("do not edit during
zoom-out"): no GitHub issues opened, no records/rules/fixtures created. This report is
Phase 3 only.

## Phase 4 — issues opened (2026-07-10, maintainer confirmed all 5)

Filed against `.github/ISSUE_TEMPLATE/01_ave_submission.md` (checklist, behavioral
fingerprint, why-not-a-variant, primary source, record skeleton, real-world evidence,
IOCs, researcher). Labels `ave-record`, `new-class`, `research-sourced` created (did
not previously exist in this repo).

| # | Candidate | Issue |
|---|---|---|
| 1 | tool-implementation-command-injection | [#32](https://github.com/bawbel/ave/issues/32) |
| 2 | mcp-resource-path-traversal | [#33](https://github.com/bawbel/ave/issues/33) |
| 3 | mcp-stdio-launch-config-injection | [#34](https://github.com/bawbel/ave/issues/34) |
| 4 | rendered-content-autofetch-exfiltration | [#35](https://github.com/bawbel/ave/issues/35) |
| 5 | code-execution-sandbox-escape | [#36](https://github.com/bawbel/ave/issues/36) |

Still not done: no `ave_id` assigned, no records/rules/fixtures created. Per
CONTRIBUTING.md Step 1, the maintainer confirms the next available id per issue before
any JSON is written (Phase 5, `add-ave-record` skill).
