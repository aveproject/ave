# AVE → OpenCRE pilot mapping — readable companion

For review without opening the spreadsheet. Full evidence and
methodology in `ave-to-opencre-pilot-DRAFT.md`; this table is the
`ave-to-opencre-pilot-mapping.csv` file's rows, laid out for reading.

**Trimmed to the 3 cleanest, most unambiguous correspondences for this
first pilot.** AVE-2026-00034 and AVE-2026-00033 were also fully
verified (see the DRAFT's §4 and §5) but held back for a follow-up
round rather than included here — 00034 because its strongest match
came with a 3-CRE proposal (one primary, two secondary) that adds real
complexity to a first submission, and 00033 because its mapping is
knowingly partial-scope (covers the record's deserialization half only,
not its eval/exec half). Both are real, defensible findings; neither is
dropped, just sequenced after this smaller batch gets feedback.

| AVE record | CRE (path → target) | Correspondence |
|---|---|---|
| [AVE-2026-00047](../records/AVE-2026-00047.json) — Hardcoded credentials in agent component | 636-660 Technical application security controls › 126-668 Secure data storage › 223-780 Secret storage › **774-888 Do not store secrets in the code** | Direct. AVE's own `behavioral_fingerprint` is a detection-shaped restatement of this CRE. |
| [AVE-2026-00061](../records/AVE-2026-00061.json) — TLS certificate verification disabled | 636-660 Technical application security controls › 278-646 Secure communication › 228-551 TLS › **430-636 Verify TLS certificates and trust chain** | Direct. Picked out of 8 CWE-295-linked CREs (most about OTP/MFA) as the one actually matching cert-validation-specific bypass. |
| [AVE-2026-00053](../records/AVE-2026-00053.json) — MCP resource path traversal | 636-660 Technical application security controls › 503-455 Input and output protection › 130-550 File handling › 451-082 File execution › **675-168 Sanitize filename metadata from untrusted origin if processing is required** | Direct, strongest independent corroboration in this pilot (top hit for "traversal" search, repeated across CWE-22/24/27/28). |

## Held for follow-up (not in this submission)

- **AVE-2026-00034** (Dynamic third-party skill import) → primary match
  CRE `307-507`, found via independent search rather than the record's
  own CWE-829 citation — the pilot's key methodology finding, still
  real and still verified. Two additional secondary CREs (`777-470`,
  `577-260`) also verified. Full detail in DRAFT §4.
- **AVE-2026-00033** (Unsafe deserialization or eval) → CRE `736-554`
  (+ secondary `831-563`), covering the deserialization half of the
  record's mechanism only. The eval/exec half has no verified OpenCRE
  match. Full detail in DRAFT §5.

## What's deliberately not in this table

- No new CRE proposals (`NEW|<name>` rows). Nothing in this pilot needed
  one — every candidate found a genuine, precise existing CRE.
