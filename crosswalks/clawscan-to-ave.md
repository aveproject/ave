# ClawScan → AVE crosswalk

**Source:** ClawScan (community, nickoc / sggolakiya) — 7 analyzer modules
**Target:** AVE v1.0.0 — 48 records
**Generated:** 2026-06-18
**Source:** https://github.com/nickoc/clawscan · https://clawscan.dev

ClawScan organises detection as 7 analyzer modules with rule IDs in
`module/ruleId` path notation. This table maps each rule to the AVE records
that cover the same behavioral class.

---

## Module: prompt-injection

ClawScan detects 10 categories of prompt injection in SKILL.md content.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| prompt-injection/roleHijack | AVE-2026-00007, 00009 | **AVE-2026-00007** | Goal override instruction, jailbreak via safety constraint removal |
| prompt-injection/instructionOverride | AVE-2026-00002, 00009 | **AVE-2026-00002** | Tool description injection (canonical), jailbreak instruction |
| prompt-injection/authoritySpoofing | AVE-2026-00014, 00030 | **AVE-2026-00030** | Role claim privilege escalation, trust escalation via false authority |
| prompt-injection/invisibleChars | AVE-2026-00029 | **AVE-2026-00029** | Homoglyph and Unicode obfuscation |
| prompt-injection/hiddenComment | AVE-2026-00010, 00029 | **AVE-2026-00010** | Hidden instruction concealment, Unicode obfuscation |
| prompt-injection/dataExfilPrompt | AVE-2026-00003, 00013, 00026 | **AVE-2026-00003** | Credential exfil, PII exfil, tool output encoding exfil |
| prompt-injection/privilegeEscalation | AVE-2026-00012, 00045 | **AVE-2026-00045** | Cross-app escalation, permission escalation via false claim |
| prompt-injection/conversationManipulation | AVE-2026-00023, 00025 | **AVE-2026-00025** | Conversation history injection, context window manipulation |

---

## Module: skill-md

SKILL.md content analysis for suspicious patterns.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| skill-md/fakePrerequisites | AVE-2026-00001, 00034 | **AVE-2026-00034** | Dynamic skill import at runtime, external instruction fetch |
| skill-md/hiddenMarkdown | AVE-2026-00010 | **AVE-2026-00010** | Hidden instruction concealment |
| skill-md/externalBinaryLink | AVE-2026-00001, 00008 | **AVE-2026-00001** | External instruction fetch, persistence via self-replication |

---

## Module: scripts

Script file analysis for malicious code patterns.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| scripts/reverseShell | AVE-2026-00004, 00005 | **AVE-2026-00004** | Shell pipe injection, destructive command execution. **Partial gap** — reverse shell payloads in bundled scripts are malware artifacts partially outside AVE scope. |
| scripts/downloadExecute | AVE-2026-00001, 00034 | **AVE-2026-00001** | External instruction fetch, dynamic skill import |
| scripts/persistence | AVE-2026-00008 | **AVE-2026-00008** | Persistence and self-replication |
| scripts/evalExecAbuse | AVE-2026-00033 | **AVE-2026-00033** | Unsafe deserialization and eval instruction |

---

## Module: network

Network destination detection.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| network/blocklistedIP | AVE-2026-00003, 00026 | **AVE-2026-00003** | Credential exfil, tool output exfil. Network destination is an IOC, not a class. |
| network/webhookExfil | AVE-2026-00003, 00026 | **AVE-2026-00026** | Tool output exfiltration encoding, credential exfil. Discord/Telegram webhook = exfil delivery mechanism. |
| network/suspiciousTLD | AVE-2026-00001 | **AVE-2026-00001** | External instruction fetch. Suspicious TLD is an IOC. |

---

## Module: credentials

Credential and secret detection.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| credentials/sshKey | AVE-2026-00047 | **AVE-2026-00047** | Hardcoded credentials in agent component |
| credentials/apiToken | AVE-2026-00047 | **AVE-2026-00047** | Hardcoded credentials in agent component |
| credentials/browserCookie | AVE-2026-00003, 00047 | **AVE-2026-00003** | Credential exfiltration, hardcoded credentials |
| credentials/openclawConfig | AVE-2026-00047 | **AVE-2026-00047** | Hardcoded credentials in agent component |

---

## Module: obfuscation

Payload obfuscation detection.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| obfuscation/base64Exec | AVE-2026-00033, 00039 | **AVE-2026-00033** | Unsafe deserialization/eval, covert steganographic exfil |
| obfuscation/hexEncoding | AVE-2026-00039 | **AVE-2026-00039** | Covert channel / steganographic exfiltration |
| obfuscation/minifiedCode | AVE-2026-00024 | **AVE-2026-00024** | Content type mismatch / disguised skill files. **Partial gap** — minification without type mismatch is not yet a distinct AVE record. |

---

## Module: typosquatting

Levenshtein distance comparison against top skills.

| ClawScan rule | AVE id(s) | Primary | Notes |
|---|---|---|---|
| typosquatting/nameDistance | AVE-2026-00017, 00029 | **AVE-2026-00017** | MCP server impersonation, homoglyph and Unicode obfuscation |

---

## Gaps

| ClawScan rule | Gap |
|---|---|
| scripts/reverseShell | Reverse shell payloads in bundled scripts are malware artifacts. AVE covers the instruction that causes execution — the compiled payload itself is out of scope. |
| obfuscation/minifiedCode | Code obfuscation without content type mismatch has no current AVE record. Partially covered by AVE-2026-00024. |

---

## Coverage summary

| | |
|---|---|
| ClawScan modules mapped | 7 of 7 |
| ClawScan rules documented | 19 |
| Rules with full AVE coverage | 17 |
| Rules with partial gaps | 2 |
| AVE records referenced | 24 |

---

*Machine-readable version: [clawscan-to-ave.json](clawscan-to-ave.json)*