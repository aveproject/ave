# AVE → OpenCRE pilot mapping — internal review draft, NOT submitted

**Companion artifacts, built from this draft's findings:**
`ave-to-opencre-pilot-mapping.csv` (the actual submittable rows, in
OpenCRE's own `CRE 0`–`CRE 4` + `AVE|name`/`id`/`hyperlink`/`description`
template column format) and `ave-to-opencre-pilot-mapping-READABLE.md`
(the same rows as a table, for review without opening a spreadsheet —
mirroring Otto Sulin's own two-file convention in issue #1016). Both
exist; **neither has been sent anywhere.**

**Trimmed to 3 records for the first submission** (decision made after
reviewing this draft): AVE-2026-00047, AVE-2026-00061, AVE-2026-00053 —
the three single-CRE, no-caveat correspondences. AVE-2026-00034 and
AVE-2026-00033 (candidates 4 and 5 below) are fully verified and held
for a follow-up round rather than dropped: 00034's strongest match came
with a 3-CRE proposal that adds real complexity for a first submission,
and 00033's mapping is knowingly partial-scope. Both sections are kept
in full below as the follow-up round's starting point, not removed.

**Status: draft, unreviewed by a second person, not sent anywhere.** This
document exists to be reviewed before any contact with OpenCRE, per the
explicit higher bar this integration was scoped at (propagation risk: a
wrong mapping into OpenCRE connects AVE to every standard already in the
hub — NIST, ISO, CWE, CAPEC, ASVS, OWASP's own portfolio — automatically,
since propagation is the entire mechanism OpenCRE exists to provide).

---

## Step 0 — verifying the entry point, before building anything on it

**The premise as given**: "Otto Sulin actively linking AISVS into OpenCRE"
as a named entry point, with his identity flagged in prior research as
unconfirmed (a Mastodon handle, username alone insufficient).

**What I checked, and found:**

1. **The claim doesn't exist in this repo's own `TRUST_STRATEGY.md`.**
   Grepped the full file and the entire repo (all file types, plus full
   git history) case-insensitively for `opencre`, `sulin`, and `aisvs`:
   zero matches, anywhere. `TRUST_STRATEGY.md` (rev 2026-07) discusses CWE
   outreach (`CWE AI Working Group outreach`, `CWE content contribution`)
   but never mentions OpenCRE as a hub, and never names anyone linking
   AISVS into it. This is a step past "unconfirmed" — the named source
   document doesn't contain the claim at all. I can't speak to whether
   this lead came from a conversation or analysis that happened outside
   this repo; I can only confirm what is and isn't written down here.

2. **The underlying real-world claim checks out independently, verified
   directly against GitHub, not assumed from the name match:**
   - GitHub user `ottosulin` is real: name "Otto Sulin", location
     Finland, account created 2014-01-06 (eleven-plus years old, not a
     throwaway), 89 followers, 24 public repos, bio "I like secure
     software" — https://github.com/ottosulin
   - He opened **[OWASP/OpenCRE#1016](https://github.com/OWASP/OpenCRE/issues/1016)**,
     "Add AISVS 1.0 mappings," created **2026-08-14** (yesterday relative
     to this review). It's a real, substantial, rigorous proposal: a
     completed CRE-mapping-template spreadsheet (two variants — one
     proposing 6 new CREs, one a "FORCED" fallback using zero new CREs),
     a readable per-chapter markdown table, and an explicit
     forced-mapping-rationale document walking through 4 deferred
     proposals he chose to force-fit rather than propose new CREs for,
     including one he flags as still a wrong fit even forced ("network
     isolation cannot stop GPU-memory side channels... withdrawing the
     proposal is a scoping decision, not a claim that the gap
     disappears"). This is not a plausible-sounding username match; it's
     a real, dated, attributable, high-quality piece of work, doing
     almost exactly the kind of thing this integration is scoping.
   - GitHub's commit-search API confirms zero commits by anyone named
     "Sulin" anywhere in OpenCRE's history — he has not merged anything.
     `author_association` on issue #1016 is `NONE`: **he is not an
     OpenCRE maintainer or collaborator.** He is an external contributor,
     currently awaiting the exact same "maintainer's second pair of
     eyes" review this pilot would also be awaiting. Reaching out to him
     is peer outreach to a fellow proposer with directly relevant,
     very-recent, very-similar experience of the actual process — useful
     for exactly that reason — but it is not a route to any kind of
     official OpenCRE blessing, and treating it as one would be a real
     mistake.

3. **A separate, confirmed, official general contact exists regardless**:
   `docs/CONTRIBUTING.md`'s own content-contribution section names
   `rob.vanderveer@owasp.org` as the direct contact for exactly this kind
   of submission ("send the file to rob.vanderveer@owasp.org... use that
   mail address for any questions"). Independently corroborated: the
   actual `CREmappingtemplate.xls` file downloaded from OpenCRE's own repo
   has `Author: Rob van der Veer` / `Last Saved By: Rob van der Veer` in
   its own document metadata. This is a real, verifiable, official
   maintainer-level contact, not a guess.

**Conclusion**: the trust-strategy document needs a correction (it
currently says nothing at all about OpenCRE, so there is a gap to fill,
not a wrong claim to fix), and outreach should be planned around the
confirmed official channel (`rob.vanderveer@owasp.org` / a GitHub issue,
per `CONTRIBUTING.md`), with Otto Sulin as a plausible, real, but
non-authoritative peer cc — not the entry point the original framing
implied.

---

## Step 1 — how CWE is actually represented in OpenCRE

Confirmed by reading `application/defs/cre_defs.py` (the actual data
model) and cross-checking against the live production API
(`www.opencre.org/rest/v1/...`), not assumed from the CWE analogy:

- **Two node types matter**: `CRE` (the hub node, id format `\d\d\d-\d\d\d`,
  e.g. `774-888`) and `Standard` (an external taxonomy entry, e.g. one
  specific CWE). A `Standard`'s own id is a composite:
  `<name>:<sectionID>:<section>:<hyperlink>:<version>` — for CWE,
  `name="CWE"`, `sectionID` is the literal CWE number (`"798"`), `section`
  is the CWE's own title text (`"Use of Hard-coded Credentials"`).
- **Granularity confirmed live**: individual CWE IDs, not top-level
  categories. Queried `CWE:798`, `CWE:22`, `CWE:502`, `CWE:295`, `CWE:668`,
  `CWE:829`, `CWE:290` directly against
  `www.opencre.org/rest/v1/standard/CWE/sectionid/{n}` — each is its own
  `Standard` node with its own real CWE title text and its own hyperlink
  straight to `cwe.mitre.org`.
- **Linkage is many-to-many, and this is the propagation mechanism named
  in this task's own framing, seen directly rather than assumed**: CRE
  `065-782` ("Ensure session timeout") is simultaneously linked to OWASP
  Proactive Controls C6, NIST 800-63 §7.2, WSTG-SESS-07, CWE-613, ASVS
  V3.3.2, and OWASP Cheat Sheets — one CRE, six standards, all connected
  to each other transitively through it. Conversely `CWE:16` alone links
  to 5 different CREs. A single AVE↔CRE link puts an AVE record in the
  same neighborhood as whatever else already links to that CRE, sight
  unseen at mapping time — which is exactly why each candidate below was
  checked against the *specific* CRE's own full link list, not just its
  name.
- Link type used for this kind of mapping is `LinkedTo` ("Linked To"),
  the default/plain association — not `PartOf`/`Contains` (hierarchy) or
  `Related` (cross-topic).

---

## Step 2 — five pilot candidates, each checked at the mechanism level

**Methodology correction, made mid-draft, kept visible rather than
silently fixed**: the first pass discovered every candidate CRE by
relaying through AVE's own existing CWE citation (AVE record → its
cited CWE → whatever CRE that CWE already links to). `docs/CONTRIBUTING.md`
explicitly names this exact shortcut and warns against it: *"We do not
recommend to use an existing mapping from the standard to another
standard that is already in OpenCRE (e.g. CWE). Typically, details get
lost that way."* Went back and independently re-derived each candidate
using OpenCRE's own `/rest/v1/text_search` against AVE's own mechanism
language directly (single-word queries — the live search endpoint
404s on multi-word phrases regardless of encoding, an API quirk, not a
content finding), *before* looking at what the CWE-routed answer had
been, then compared.

**Result: four of five held up unchanged under independent search. One
did not, and the independent method found something CWE-routing
structurally could not have** — documented as candidate 4 below, kept
as the clearest demonstration of exactly the risk CONTRIBUTING.md
names, not smoothed over.

### 1. AVE-2026-00047 (Hardcoded Credentials in Agent Component) → CWE-798 → CRE `774-888`

- **AVE mechanism** (from the record's own `behavioral_fingerprint`):
  "Skill file contains a high-entropy string adjacent to a credential
  keyword such as api_key, secret, token, password... a literal value,
  not an environment variable reference or secrets manager path."
- **CRE 774-888's own name**: "Do not store secrets in the code."
- **Correspondence**: direct, one-sentence match. AVE's behavioral
  fingerprint is a detection-shaped restatement of exactly what this CRE
  prohibits. No forcing needed.
- **Independent re-check**: `text_search?text=secret` surfaces `774-888`
  directly (alongside `223-780` "Secret storage," a DSOMM-sourced parent
  concept, not a competing leaf). Holds up.
- **Confidence: high.**

### 2. AVE-2026-00061 (TLS Certificate Verification Disabled) → CWE-295 → CRE `430-636`

- **AVE mechanism**: "sets a flag that disables TLS certificate
  verification for its own outbound connections... any network position
  capable of intercepting the connection can perform a
  machine-in-the-middle attack."
- **CWE-295 links to 8 CREs on OpenCRE**, most of them about OTP/MFA
  weaknesses (`354-753`, `816-631`, `646-227`, `168-186`, `404-126`) —
  a different failure mode sharing the same broad CWE. The one that
  actually matches is `430-636`, whose own name is: **"Verify TLS
  certificates and trust chain."**
- **Correspondence**: direct. This is the clearest illustration in this
  pilot of why "topic feels adjacent" isn't the bar — 7 of the 8 CREs
  linked under CWE-295 would have been a wrong mapping despite sharing
  the identical CWE citation.
- **Independent re-check**: `text_search?text=certificate` alone does
  *not* surface `430-636` in its top results (returns encryption-at-rest
  and session-token CREs instead — a noisy single-word query). Retried
  with `text_search?text=TLS`, which does surface `430-636` directly,
  alongside a cluster of other real TLS-related CREs (disabling
  insecure SSL/TLS versions, protocol fallback, algorithm strength,
  mutual auth). `430-636` remains the most precise of that cluster for
  AVE-2026-00061's specific mechanism (certificate/trust-chain
  verification being disabled, not cipher strength or protocol version).
  Holds up, with the caveat that the right search term mattered more
  than expected.
- **Confidence: high.**

### 3. AVE-2026-00053 (MCP Resource Path Traversal) → CWE-22 → CRE `675-168`

- **AVE mechanism**: "An MCP resource or file-handler tool's own
  path-validation logic fails to canonicalize a caller-supplied path...
  allowing directory-traversal sequences... to escape the tool's
  declared scope."
- **CRE `675-168`'s own name**, first glance, reads narrower than
  expected: "Sanitize filename metadata from untrusted origin if
  processing is required" — worth checking whether "filename metadata"
  means something narrower than path/URL traversal generally (e.g. file
  upload metadata specifically) before trusting it.
- **Checked its full link list directly**: linked to CWE-22 through
  CWE-40 (the entire MITRE path-traversal CWE family), CAPEC-126 "Path
  Traversal" plus four related CAPEC entries, five ZAP path-traversal
  scan rules, and its own ASVS anchor text spells out the real scope:
  *"Verify that user-submitted filename metadata is not used directly by
  system or framework filesystems and that a URL API is used to protect
  against path traversal."* "Filename metadata" is OpenCRE/ASVS's own
  phrase for "a user-controlled filename/path value" generally, not a
  narrower upload-specific concept. Confirmed correct scope.
- **Independent re-check**: `text_search?text=traversal` surfaces
  `675-168` as the top result, repeated across CWE-22/24/27/28 entries
  all pointing at the same CRE — the strongest, cleanest corroboration
  of any candidate in this pilot. Holds up.
- **Confidence: high, after the deeper check** (would have been
  "plausible but unverified" without it).

### 4. [HELD FOR FOLLOW-UP, not in this submission] AVE-2026-00034 (Dynamic Third-Party Skill Import) → CRE `307-507` (primary), CRE `777-470` and CRE `577-260` (secondary)

**This is the candidate the independent-search pass actually changed —
kept as the pilot's central finding, not edited away.**

- **AVE mechanism**: "Loading code from an external URL at runtime
  without verification... effectively delegates code execution to an
  attacker-controlled source." The record itself cites both CWE-829
  (Inclusion of Functionality from Untrusted Control Sphere) and CWE-494
  (Download of Code Without Integrity Check).
- **First pass (CWE-routed)** found `777-470` "Ignore/block execution
  logic from untrusted sources" and `577-260` "Enforce integrity check
  for externally hosted assets (eg SRI)," both via CWE-829's own linked
  CREs. Both are real, defensible matches — documented below as
  secondary.
- **Independent re-check**, run *without* looking at the CWE-829 answer
  first: `text_search?text=plugin` and `text_search?text=third-party`
  (drawn from AVE-2026-00034's own title, not its CWE citation) both
  surface **CRE `307-507`**, whose full name is *"Allow only trusted
  sources both build time and runtime; therefore perform integrity
  checks on all resources and code"* — and whose own ASVS anchor text is:
  *"The application must not load or execute code from untrusted
  sources, such as loading includes, modules, **plugins**, code, or
  libraries from untrusted sources or **the Internet**."* That is close
  to a verbatim restatement of AVE-2026-00034's own mechanism
  ("load the plugin from https://external.site/plugin.py").
- **`307-507` links to CWE-353** ("Missing Support for Integrity Check")
  — a *different* CWE than CWE-829/494, the ones AVE-2026-00034 itself
  currently cites. The CWE-routed first pass could not have found this
  CRE by construction: it only ever looks at CREs already reachable from
  a CWE the AVE record happens to name. This is the concrete instance of
  the exact risk `CONTRIBUTING.md` names — not a hypothetical, one that
  happened during this pilot's own first draft.
- **Resolution**: propose `307-507` as the primary link (single closest
  mechanism match, found independently of the record's own citations),
  and keep `777-470`/`577-260` as secondary/companion links — both are
  still real, defensible, and OpenCRE's own data model routinely
  supports one Standard linking to several CREs (`CWE:16` alone links to
  5). Also worth carrying back into AVE's own corpus separately from
  this pilot: AVE-2026-00034's own `references` could reasonably add
  CWE-353 alongside its existing CWE-829/494 citations, since this
  search surfaced a real angle on the mechanism AVE's own record
  doesn't currently name. Not done in this draft — flagged for a
  follow-up, kept out of scope here to avoid conflating the OpenCRE pilot
  with an unrelated AVE record edit.
- **Confidence: high on `307-507` specifically because it was found
  independently; still high but secondary on the other two.**
- **Second-pass review note**: `307-507`'s own full link list (13 links;
  the earlier fetch during drafting only printed the first 8) confirms
  CWE-353 is its *only* linked CWE — no CWE-829/494 present anywhere on
  it, so the "CWE-routing structurally could not have found this" claim
  above holds on the complete data, not a truncated sample. It also
  carries a `Related` (not `PartOf`) link to `613-285 Supply chain
  management` — the same node that sits in `577-260`'s own parent chain.
  OpenCRE's own graph already treats these two CREs as connected to each
  other, independent confirmation that proposing both together for one
  AVE record is coherent with the existing graph, not an arbitrary
  combination assembled for this pilot.

### 5. [HELD FOR FOLLOW-UP, not in this submission] AVE-2026-00033 (Unsafe Deserialization or Eval Instruction) → CWE-502 → CRE `736-554`

- **AVE mechanism**: "Deserializing untrusted data using unsafe methods
  like Python's `pickle.loads`, unguarded `yaml.load`, **or `eval`/`exec`
  on arbitrary strings**... When an agentic component instructs the model
  to perform these operations on externally-supplied data."
- **CWE-502 links to 3 CREs**: `831-563` "Avoid deserialization logic",
  `736-554` "Block serialization of content from untrusted clients",
  `762-616` "Secure serialized objects (e.g. integrity checks)". `736-554`
  is the closest single match — its own untrusted-origin framing mirrors
  AVE's "externally-supplied data" emphasis most directly.
- **Independent re-check**: `text_search?text=deserialization` surfaces
  both `831-563` and `736-554` directly (each appearing twice, once via
  ASVS, once via CWE-502 itself), with no third alternative surfacing
  and no eval/exec-specific CRE appearing under any search term tried.
  Both corroborates `736-554` and independently confirms the eval/exec
  gap noted below is real, not a search-effort gap.
- **The part I am flagging rather than smoothing over**: this AVE record
  bundles two related but genuinely distinct primitives — unsafe
  deserialization (a CWE-502 match) and unsafe `eval`/`exec` on dynamic
  strings (properly CWE-95, "Eval Injection," which I have not located
  or verified as an existing linked Standard in OpenCRE at all). Mapping
  the whole record to CWE-502/`736-554` is accurate for its
  deserialization half and silent about its eval/exec half. The honest
  move, matching the transparency Otto Sulin's own issue models
  explicitly (his own "FORCED-MAPPING-RATIONALE" document), is to submit
  this mapping labeled as partial-scope, not to either drop it or quietly
  overstate its coverage.
- **Confidence: high for the deserialization half; explicitly flagged as
  partial, not full-record, coverage.**

---

## Step 3 note on submission shape — a real process mismatch found, worth acting on before Step 5

This repo's existing `crosswalks/*.json` files (the AST10, cfgaudit,
ramparts, etc. crosswalks) all validate against this repo's own
`schema/crosswalk-1.0.0.schema.json` — a `source`/`target`/`mappings`/
`coverage` JSON shape built for PR-based submission into a target
project's own repo.

**That is not what OpenCRE actually wants.** Per `docs/CONTRIBUTING.md`
and confirmed by Otto Sulin's own real, current submission: the actual
artifact is the `CREmappingtemplate.xls`-derived spreadsheet (CRE
hierarchy in nested `CRE 0`–`CRE 4` columns, new-standard columns named
`<standard>|name`, `<standard>|id`, `<standard>|hyperlink`, optionally
`|description`), sent as a GitHub issue attachment or direct email, not
a PR against a mapping file in OpenCRE's own repo. **A crosswalk built in
this repo's usual JSON shape would not be usable as-is** and would need
to be rebuilt in OpenCRE's own template format before Step 5. Not done
in this draft — flagging it here so it's decided deliberately rather
than discovered midway through building the wrong artifact.

---

## What Step 4 (contribution mechanism) confirmed, for completeness

- Documented process: `docs/CONTRIBUTING.md`, "How can I contribute
  content" section. Get the template spreadsheet, fill in CRE-to-section
  correspondence, propose new CREs inline (`NEW|<name>` convention) where
  genuinely needed, send via GitHub issue attachment or email to
  `rob.vanderveer@owasp.org`. Public opencre.org additions get a
  maintainer check before going live — this is not a self-serve merge.
- `docs/CONTRIBUTING.md` also carries an explicit, pointed warning about
  low-effort/AI-generated submissions: *"we will be aggressively closing
  both issues and pull requests that link to issues not acknowledged by
  the maintainers"* and *"pull requests generated entirely by LLMs
  without proper validation are discouraged."* Directly relevant here —
  whatever goes out in Step 5 needs a human to have actually read and
  stood behind it first, not just this document existing.
- An alternate, "preferred" method exists for standards the source
  organization controls the text of: embed OpenCRE hyperlinks directly
  into the standard's own published text, with OpenCRE reading them
  automatically. Not applicable here — AVE doesn't control CWE's text,
  but worth remembering for AVE's *own* records being linked back *into*
  by someone else later.

---

## Not yet done (deliberately — Step 5 gate)

No contact has been made with OpenCRE, Otto Sulin, or Rob van der Veer.
This document is the Step 3 deliverable: 5 pilot mappings drafted, each
independently re-verified against OpenCRE's own text search rather than
only via CWE-routing (one real correction resulted — AVE-2026-00034),
evidence attached per mapping, two scope caveats flagged rather than
hidden (AVE-2026-00033's eval/exec gap; AVE-2026-00034's own missing
CWE-353 citation, out of scope for this document), one process-format
mismatch surfaced, then trimmed to the 3 cleanest single-CRE
correspondences (AVE-2026-00047, 00061, 00053) for the actual first
submission after a second review pass, with 00034 and 00033 held for a
deliberate follow-up round rather than dropped. The submission artifacts
(`ave-to-opencre-pilot-mapping.csv` / `-READABLE.md`) now carry only the
3-record trim; this document keeps all 5 candidates' full evidence,
since the held-back two are the follow-up round's starting point, not
discarded work.

Outreach (Step 5) still needs an explicit go-ahead — trimming the
record count is a decision about *what* to send, not a decision to
send it.
