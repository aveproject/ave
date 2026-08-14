# AVE → OpenCRE pilot mapping — readable companion

For review without opening the spreadsheet. Full evidence and
methodology in `ave-to-opencre-pilot-DRAFT.md`; this table is the
`ave-to-opencre-pilot-mapping.csv` file's rows, laid out for reading.

| AVE record | CRE (path → target) | Correspondence |
|---|---|---|
| [AVE-2026-00047](../records/AVE-2026-00047.json) — Hardcoded credentials in agent component | 636-660 Technical application security controls › 126-668 Secure data storage › 223-780 Secret storage › **774-888 Do not store secrets in the code** | Direct. AVE's own `behavioral_fingerprint` is a detection-shaped restatement of this CRE. |
| [AVE-2026-00061](../records/AVE-2026-00061.json) — TLS certificate verification disabled | 636-660 Technical application security controls › 278-646 Secure communication › 228-551 TLS › **430-636 Verify TLS certificates and trust chain** | Direct. Picked out of 8 CWE-295-linked CREs (most about OTP/MFA) as the one actually matching cert-validation-specific bypass. |
| [AVE-2026-00053](../records/AVE-2026-00053.json) — MCP resource path traversal | 636-660 Technical application security controls › 503-455 Input and output protection › 130-550 File handling › 451-082 File execution › **675-168 Sanitize filename metadata from untrusted origin if processing is required** | Direct, strongest independent corroboration in this pilot (top hit for "traversal" search, repeated across CWE-22/24/27/28). |
| [AVE-2026-00034](../records/AVE-2026-00034.json) — Dynamic third-party skill import | 616-305 Development processes for security › 473-177 Deploy/build › **307-507 Allow only trusted sources both build time and runtime; therefore perform integrity checks on all resources and code** | **Primary.** Found via independent text search on the record's own language ("plugin", "third-party"), not via its cited CWE-829 — a different, more precise match than CWE-routing found. See DRAFT §4 for why this is the pilot's key finding. |
| ↳ same record, secondary link | 636-660 › 503-455 Input and output protection › 130-550 File handling › 451-082 File execution › **777-470 Ignore/block execution logic from untrusted sources** | Secondary. The original CWE-829-routed candidate — still real, kept as a companion link. |
| ↳ same record, secondary link | 616-305 › 613-285 Supply chain management › 613-287 Dependency integrity › **577-260 Enforce integrity check for externally hosted assets (eg SRI)** | Secondary. Matches the record's own remediation text (signature verification before load). |
| [AVE-2026-00033](../records/AVE-2026-00033.json) — Unsafe deserialization or eval | 636-660 › 503-455 Input and output protection › 836-068 Deserialization Prevention › **736-554 Block serialization of content from untrusted clients** | **Partial scope, flagged explicitly.** Covers the deserialization half of this record's mechanism only; the eval/exec-on-dynamic-strings half has no verified OpenCRE match (properly CWE-95, not confirmed present as a linked Standard). |
| ↳ same record, secondary link | 636-660 › 503-455 › 836-068 › **831-563 Avoid deserialization logic** | Secondary, broader framing of the same CWE-502 family. |

## What's deliberately not in this table

- No new CRE proposals (`NEW|<name>` rows). Nothing in this pilot needed
  one — every candidate found a genuine, precise existing CRE. Worth
  revisiting once the corpus mapping goes beyond this 5-record pilot;
  some AVE classes (multi-agent orchestration mechanisms, for instance)
  may have no appsec-era precedent to map onto at all.
- AVE-2026-00033's eval/exec gap and AVE-2026-00034's missing CWE-353
  citation are noted as open items in the DRAFT, not resolved here.
