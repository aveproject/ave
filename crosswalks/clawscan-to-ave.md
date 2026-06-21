# ClawScan → AVE crosswalk

**Source:** ClawScan (community, nickoc / sggolakiya) — 7 analyzer modules
**Target:** AVE v1.0.0 — 51 records
**Generated:** 2026-06-21
**Source:** https://github.com/nickoc/clawscan · https://clawscan.dev

ClawScan organises detection as 7 analyzer modules with rule IDs in
`module/ruleId` path notation. This table maps each rule to the AVE records
that cover the same behavioral class.

> **Updated 2026-06-21** for the 51-record set. The v1.1 migration added three
> records with direct, exact-match ClawScan rules: AVE-2026-00049 ↔
> `network/header-tamper`, AVE-2026-00050 ↔ `scripts/persistence`, and
> AVE-2026-00051 ↔ `network/oauth-misconfig`.

---

## Module: prompt-injection

ClawScan detects 10 categories of prompt injection in SKILL.md content.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| prompt-injection/roleHijack | AVE-2026-00007, AVE-2026-00009 | **AVE-2026-00007** | AVE-2026-00007 covers goal override; AVE-2026-00009 safety constraint removal / jailbreak. |
| prompt-injection/instructionOverride | AVE-2026-00002, AVE-2026-00009 | **AVE-2026-00002** | AVE-2026-00002 is the canonical tool description injection class. |
| prompt-injection/authoritySpoofing | AVE-2026-00014, AVE-2026-00030 | **AVE-2026-00030** | AVE-2026-00030 covers role claim privilege escalation; AVE-2026-00014 trust escalation via false authority. |
| prompt-injection/invisibleChars | AVE-2026-00029 | **AVE-2026-00029** | AVE-2026-00029 covers homoglyph and Unicode obfuscation. |
| prompt-injection/hiddenComment | AVE-2026-00010, AVE-2026-00029 | **AVE-2026-00010** | AVE-2026-00010 covers hidden instruction concealment. |
| prompt-injection/dataExfilPrompt | AVE-2026-00003, AVE-2026-00013, AVE-2026-00026 | **AVE-2026-00003** | AVE-2026-00003 credential exfil; AVE-2026-00013 PII exfil; AVE-2026-00026 tool output encoding exfil. |
| prompt-injection/privilegeEscalation | AVE-2026-00012, AVE-2026-00045 | **AVE-2026-00045** | AVE-2026-00045 cross-app escalation; AVE-2026-00012 permission escalation via false claim. |
| prompt-injection/conversationManipulation | AVE-2026-00025, AVE-2026-00023 | **AVE-2026-00025** | AVE-2026-00025 conversation history injection; AVE-2026-00023 context window manipulation. |

---

## Module: skill-md

SKILL.md content analysis for suspicious patterns.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| skill-md/fakePrerequisites | AVE-2026-00001, AVE-2026-00034 | **AVE-2026-00034** | AVE-2026-00034 covers dynamic skill import at runtime; AVE-2026-00001 external instruction fetch. |
| skill-md/hiddenMarkdown | AVE-2026-00010 | **AVE-2026-00010** | AVE-2026-00010 covers hidden instruction concealment. |
| skill-md/externalBinaryLink | AVE-2026-00001, AVE-2026-00008 | **AVE-2026-00001** | AVE-2026-00001 covers external instruction fetch; AVE-2026-00008 persistence via self-replication. |

---

## Module: scripts

Script file analysis for malicious code patterns.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| scripts/reverseShell | AVE-2026-00004, AVE-2026-00005 | **AVE-2026-00004** | AVE-2026-00004 shell pipe injection; AVE-2026-00005 destructive command execution. **Partial gap:** Reverse shell as a class is partially covered but AVE focuses on skill instruction patterns rather than bundled script payloads. |
| scripts/downloadExecute | AVE-2026-00001, AVE-2026-00034 | **AVE-2026-00001** | AVE-2026-00001 external instruction fetch; AVE-2026-00034 dynamic skill import. |
| scripts/persistence | AVE-2026-00008, AVE-2026-00050 | **AVE-2026-00008** | AVE-2026-00008 covers persistence and self-replication. AVE-2026-00050 (Parasitic Toolchain) added: registered tool hooks that persist across session restarts are a runtime-layer persistence mechanism, the agentic-runtime equivalent of a cron job or startup entry. |
| scripts/evalExecAbuse | AVE-2026-00033 | **AVE-2026-00033** | AVE-2026-00033 covers unsafe deserialization and eval instruction. |

---

## Module: network

Network destination detection: blocklisted IPs, webhook exfil endpoints, suspicious TLDs, header tampering, OAuth misconfiguration, content-type spoofing.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| network/blocklistedIP | AVE-2026-00003, AVE-2026-00026 | **AVE-2026-00003** | AVE-2026-00003 credential exfiltration; AVE-2026-00026 tool output exfiltration. Network destination matching is a detection signal, not a behavioral class. |
| network/webhookExfil | AVE-2026-00003, AVE-2026-00026 | **AVE-2026-00026** | Webhook exfil is a delivery mechanism for the data exfiltration class. |
| network/suspiciousTLD | AVE-2026-00001 | **AVE-2026-00001** | Suspicious TLD is an IOC for external instruction fetch or exfiltration classes. |
| network/header-tamper | AVE-2026-00049 | **AVE-2026-00049** | Direct, exact match. AVE-2026-00049 (HTTP Host Header Injection / BadHost) is precisely this rule's target class -- a component overrides the Host header (or X-Forwarded-Host / X-Original-URL) on an outbound request to redirect it, along with any carried credentials, to an attacker-controlled server. |
| network/oauth-misconfig | AVE-2026-00051 | **AVE-2026-00051** | Direct, exact match. AVE-2026-00051 (OAuth Discovery Rebinding) is precisely this rule's target class -- the server's OAuth discovery document (authorization_endpoint, token_endpoint, jwks_uri) is poisoned to point at attacker infrastructure rather than the legitimate authorization server. |
| network/type-spoof | AVE-2026-00024 | **AVE-2026-00024** | AVE-2026-00024 covers content type mismatch (executable payload disguised as a skill file), detected primarily via the Magika engine. |

---

## Module: credentials

Credential and secret detection.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| credentials/sshKey | AVE-2026-00047 | **AVE-2026-00047** | AVE-2026-00047 covers hardcoded credentials in agent components. |
| credentials/apiToken | AVE-2026-00047 | **AVE-2026-00047** | AVE-2026-00047 covers hardcoded credentials. |
| credentials/browserCookie | AVE-2026-00003, AVE-2026-00047 | **AVE-2026-00003** | Cookie theft as an exfiltration target maps to AVE-2026-00003. |
| credentials/openclawConfig | AVE-2026-00047 | **AVE-2026-00047** | AVE-2026-00047 hardcoded credentials. |

---

## Module: obfuscation

Payload obfuscation detection.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| obfuscation/base64Exec | AVE-2026-00033, AVE-2026-00039 | **AVE-2026-00033** | AVE-2026-00033 unsafe deserialization/eval; AVE-2026-00039 covert steganographic exfil. |
| obfuscation/hexEncoding | AVE-2026-00039 | **AVE-2026-00039** | AVE-2026-00039 covert channel / steganographic exfiltration. |
| obfuscation/minifiedCode | AVE-2026-00024 | **AVE-2026-00024** | AVE-2026-00024 covers content type mismatch / disguised skill files. **Partial gap:** Minified code obfuscation as a standalone class is not yet a distinct AVE record. |

---

## Module: typosquatting

Levenshtein distance comparison against top skills.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| typosquatting/nameDistance | AVE-2026-00017, AVE-2026-00029 | **AVE-2026-00017** | AVE-2026-00017 covers MCP server impersonation; AVE-2026-00029 homoglyph and Unicode obfuscation. |

---

## The 3 new records — exact rule matches

Unlike most AVE↔ClawScan mappings, which involve some interpretation, all three
v1.1 records have a direct, exact-match ClawScan rule:

| AVE record | ClawScan rule | Match type |
|---|---|---|
| AVE-2026-00049 — HTTP Host Header Injection | `network/header-tamper` | Exact |
| AVE-2026-00050 — Parasitic Toolchain | `scripts/persistence` | Strong (runtime persistence mechanism) |
| AVE-2026-00051 — OAuth Discovery Rebinding | `network/oauth-misconfig` | Exact |

This is the strongest possible evidence for a crosswalk entry — these aren't
categories generalised to fit; the rule and the record describe the identical
mechanism.

---

## Gaps

| ClawScan rule | Gap |
|---|---|
| scripts/reverseShell | Reverse shell payloads in bundled scripts are malware artifacts. AVE covers the instruction that causes execution -- the compiled payload itself is out of scope. |
| obfuscation/minifiedCode | Code obfuscation without content type mismatch has no current AVE record. Partially covered by AVE-2026-00024. |

---

## Coverage summary

| | |
|---|---|
| ClawScan modules mapped | 7 of 7 |
| ClawScan rules documented | 21 |
| Rules with full AVE coverage | 19 |
| Rules with partial gaps | 2 |
| AVE records referenced | 25 |

---

*Machine-readable version: [clawscan-to-ave.json](clawscan-to-ave.json)*