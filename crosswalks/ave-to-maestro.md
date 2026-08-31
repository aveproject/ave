# AVE → MAESTRO crosswalk (pilot)

**Source:** AVE v1.1.0 — 80 records
**Target:** MAESTRO (Multi-Agent Environment, Security, Threat, Risk, & Outcome),
Cloud Security Alliance
**Verified against live source:** 2026-08-30

This is a deliberate pilot, not a full-corpus crosswalk: 6 AVE records mapped to
5 of MAESTRO's roughly 49 layer/threat combinations (7 layers, each with 6-8
named threats). The clearest, most unambiguous mechanism matches first, the
same pilot-first approach already used for the OpenCRE and OWASP GenAI
Crosswalk submissions.

## The versioning premise, checked before building anything

An earlier internal note treated a MAESTRO "v2" as a blocker for this
crosswalk. That premise was re-verified independently before starting:

- The CSA's own framework announcement carries no version marker anywhere in
  its text.
- `github.com/CloudSecurityAlliance/MAESTRO` (an AI-powered threat analyzer
  tool built on the framework, not a versioned specification repo for the
  framework itself) has zero tags and zero GitHub releases, despite being
  actively pushed to as recently as 2026-08-27.
- No search result, from any source, up to today mentions a "v2" or discrete
  numbered release of the framework.

MAESTRO evolves continuously through community contribution rather than
discrete versioning. The blocker did not exist, and this crosswalk was not
actually waiting on anything real.

## Mapping

| MAESTRO layer | Threat | AVE ids | Basis |
|---|---|---|---|
| Layer 3 - Agent Frameworks | Supply Chain Attacks (targeting dependencies) | AVE-2026-00062 | Direct. A mutable dependency reference lets the reviewed and executed artifact silently diverge after approval. |
| Layer 4 - Deployment and Infrastructure | Infrastructure-as-Code (IaC) Manipulation | AVE-2026-00071 | A declared config value (`DOCKER_HOST`, or a `-H`/`--host` flag) is manipulated to redirect the container daemon to attacker infrastructure. Not a compromised image, not orchestration-layer exploitation. |
| Layer 7 - Agent Ecosystem | Agent Goal Manipulation | AVE-2026-00007 | Direct, close to shared vocabulary already: AVE's own `attack_class` is "Prompt Injection - Goal Hijack." |
| Layer 7 - Agent Ecosystem | Agent Tool Misuse | AVE-2026-00006, AVE-2026-00068 | Two distinct mechanisms, same threat: wallet-tool abuse (00006) and CLI command composition through shared OS state (00068). Both are misuse of an already-authorized tool, not a boundary failure. |
| Layer 7 - Agent Ecosystem | Marketplace Manipulation | AVE-2026-00066 | Preemptive registration of names an LLM is statistically likely to hallucinate, on a public registry, with malicious content. |

## What was checked and rejected, not just what passed

- **AVE-2026-00006 (Cryptocurrency Drain)** was first considered for Layer 4's
  "Resource Hijacking." That MAESTRO threat is about hijacked compute or
  infrastructure resources (for example, cryptomining on stolen compute), not
  financial or wallet theft carried out through an already-authorized tool.
  Moved to Layer 7's "Agent Tool Misuse" instead, where the mechanism actually
  matches.
- **AVE-2026-00017 (Server Impersonation)** was considered for Layer 7's
  "Agent Impersonation" and excluded from this pilot. MAESTRO's threat
  concerns one *agent* impersonating another agent inside a multi-agent
  ecosystem. AVE-2026-00017 describes an MCP server — a tool or service, not
  itself an agent — impersonating a well-known official server. The
  trust-exploitation shape is similar; the entity type MAESTRO's own layer
  boundary is drawn around is not the same. Recorded as a gap rather than
  forced, the same discipline already applied to AVE-2026-00059/00065 in the
  OpenCRE pilot.
- **AVE-2026-00066** was considered for Layer 7's "Malicious Agent Discovery"
  before landing on "Marketplace Manipulation." "Malicious Agent Discovery"
  reads as agent-specific (a malicious agent surfaced by a directory or
  registry search); AVE-2026-00066's mechanism covers registry-squatting more
  broadly (packages, repos, or skills, not agents specifically), which
  "Marketplace Manipulation" names without narrowing to agents.

## Gaps

**In AVE, out of scope entirely:** Model Stealing / Model Extraction (Layer 1,
Layer 6) — AVE catalogs behavioral classes in agentic components, not attacks
on a foundation model's own weights or training process.

**In AVE, unresolved elsewhere:** Denial of Service on computationally
expensive queries (Layer 1) overlaps with an open internal question about a
possible resource-exhaustion/agentic-DoS gap in AVE's own corpus. That
question was not resolved as part of building this crosswalk; see the
trust-strategy roadmap.

**In MAESTRO:** no named threat currently covers non-agent component
impersonation (AVE-2026-00017); see above.

## Context for outreach

MAESTRO's creator, Ken Huang (CSA AI Safety Working Groups co-chair), also
created AST10 — the same person AVE already has an open crosswalk PR against
(`crosswalks/ave-to-ast10.json`, `kenhuangus/agentic-skills-top-10#10`,
currently stalled with no maintainer response). Worth knowing when framing any
MAESTRO outreach, not a reason for extra hesitancy beyond what any crosswalk
outreach already gets.

## Scope discipline

3 of 7 layers, 5 of roughly 49 named layer/threat combinations, 6 of 80 AVE
records. No claim is made about the other layers, threats, or records. More
can follow once this format is confirmed useful.

---

*Part of [AVE](https://aveproject.org)'s crosswalk set. See `ave-to-maestro.json`
for the machine-readable version.*
