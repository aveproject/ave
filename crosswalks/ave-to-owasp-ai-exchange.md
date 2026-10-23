# AVE → OWASP AI Exchange crosswalk (pilot)

**Source:** AVE v1.1.0, 87 records (commit `733974d4e29ce499caa766350a0ec6ee123ea3cf`)
**Target:** OWASP AI Exchange, OWASP Foundation
(commit `caf2e43bd8dd21666d2c08ddb532192ac255a248`, committed 2026-10-16)
**Verified against live source:** 2026-10-20

This is a deliberate pilot, not a full-corpus crosswalk: 13 AVE records
selected by a rule fixed *before* mapping, mapped at the mechanism level
against the Exchange's 25 permalinked threat items as they stand at the
pinned commit. 7 of 13 found a real correspondence (6 narrower, 1
related); 6 are honest no-fits, split between conventional/delegated (4)
and genuine gaps in the Exchange's current agentic coverage (2).

**Licence basis.** The target repository has no LICENSE file. CC0 1.0 is
stated twice in its content: `content/ai_exchange/content/charter.md`
and the overview's own Creative Commons attribution block. Recorded as
that, a licence stated in the content, not as a repository-level grant.

**Versioning.** The Exchange has no real version: its only tag is a
placeholder `v0.0.0`. It is, in its own words, an "open-source living
publication." This crosswalk is pinned by commit and will go stale as
the Exchange's content changes under it, matching the premise this
project's own `TRUST_STRATEGY.md` standing rules apply to every other
unversioned or continuously-evolving source.

**Not endorsed, not submitted.** This crosswalk is not endorsed by,
affiliated with, or submitted to OWASP or the AI Exchange. It lives only
in this repository, the same way `ave-to-maestro.json` does, and makes
no claim about ISO/IEC 27090 or prEN 18282: the Exchange's own public
statements about its contribution to those standards are the Exchange's
claims about itself, not something this crosswalk has read or
independently verified.

## Mapping

| AI Exchange threat | AVE id | Relationship | Basis |
|---|---|---|---|
| 2.2.2 Indirect prompt injection | AVE-2026-00007 | narrower | Sounds direct, is structurally indirect: the attacker is a third-party component author, not a live user, matching 2.2.2's own definition rather than 2.2.1's. |
| 2.3.1 Disclosure of sensitive data in model output | AVE-2026-00015 | narrower | Arrives via indirect injection, but the record's own subject is the confidentiality outcome (system prompt disclosure), which is 2.3.1's threat, not 2.2.2's delivery mechanism. |
| 2.2.2 Indirect prompt injection | AVE-2026-00020 | narrower | Checked against 2.2.3 Agent message structure manipulation first and rejected: 2.2.3 is scoped to structured protocol fields, explicitly not natural-language text content, which is what this record's mechanism is. |
| 2.2.2 Indirect prompt injection | AVE-2026-00018 | related | Shares only the injection-delivery dimension; the fabricated-tool-result outcome itself is not a named Exchange threat. 4.7 checked and rejected (conventional, not agent-reasoning-driven). |
| 2.2.2 Indirect prompt injection | AVE-2026-00044 | narrower | Clean instance with an async/temporal variant 2.2.2 does not name but does not exclude. |
| 2.2.2 Indirect prompt injection | AVE-2026-00069 | narrower | Modality-specific instance (image, not text). Scanner-evasion framing checked against 2.1.x Evasion and rejected: Evasion targets the model's own decision boundary, not a static scanner. |
| 2.2.2 Indirect prompt injection | AVE-2026-00002 | narrower | Checked against 2.2.3 for the same reason as AVE-2026-00020, rejected for the same reason: natural-language text field, not a structured-field forgery. |

## What was checked and rejected, not just what passed

- **AVE-2026-00020 and AVE-2026-00002**, both considered for **2.2.3
  Agent message structure manipulation**, both rejected for 2.2.2
  instead. 2.2.3's own text draws an explicit line between structured
  protocol fields and natural-language text content; both AVE records
  are the latter. This is the pilot's central finding: the Exchange's
  one dedicated agentic-protocol threat did not catch either agent-to-agent
  AVE record tested against it.
- **AVE-2026-00018**, considered for **4.7 Augmentation data
  manipulation**, rejected: 4.7 is a conventional at-rest/in-transit
  integrity attack, not an already-injected agent instructed to
  misreport its own output.
- **AVE-2026-00069's** scanner-evasion framing, considered for **2.1.x
  Evasion**, rejected: Evasion fools the model's own decision boundary;
  this record's evasion target is a static skill scanner, a different
  asset entirely.

## Gaps in AVE (Exchange threats this pilot did not search for, by design)

- **2.1.1-2.1.5 Evasion**, **3.1.1-3.2.3 development-time threats**,
  **2.3.2/2.4/4.2/4.3 model inversion, exfiltration, and direct
  runtime poisoning/leak**: all concern a foundation model's own
  training, weights, or inference properties directly, territory
  `ave-to-maestro.json`'s own `gaps_in_maestro` note already scopes out
  of AVE's current coverage. Not re-litigated here, same boundary.

## Gaps in the Exchange (pilot AVE records with no Exchange counterpart)

- **AVE-2026-00058** (deceptive skill trigger/activation-scope
  manipulation): no Exchange threat addresses skill or tool discovery
  and selection integrity, at any granularity. AI-specific, genuinely
  unrepresented, not a forced match.
- **AVE-2026-00078** (consensus poisoning, no quorum verification): no
  Exchange threat addresses multi-agent result corroboration. AI-specific,
  genuinely unrepresented.
- **AVE-2026-00052, AVE-2026-00053** (command injection and path
  traversal in an MCP server's own handler code): both records' own text
  states no LLM reasoning is required to trigger them. Conventional,
  explicitly delegated by the Exchange's own scope statement ("AI
  security = threats to AI-specific assets (AI Exchange) + threats to
  other assets (other resources)"), not a gap to fill.
- **AVE-2026-00061** (TLS certificate verification disabled): a
  declared configuration flag. Conventional, delegated.
- **AVE-2026-00047** (hardcoded credential in a skill file): a literal
  secret string. Conventional, delegated.

## Coverage

13 AVE records piloted, out of 87 published. 7 mapped (6 narrower, 1
related), landing on 2 of the Exchange's 25 threat items. 6 honest
no-fits (4 conventional/delegated, 2 genuine Exchange-side gaps). No
claim is made about the other 23 Exchange threat items or the ~74 AVE
records outside this pilot; a full-corpus pass was not attempted.
