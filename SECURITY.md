# Security Policy

## Reporting a vulnerability in Bawbel tooling

**Do not open a public GitHub issue for security vulnerabilities in Bawbel
software (scanner, PiranhaDB, ave-site).**

Email: **bawbel.io@gmail.com**
Subject: `SECURITY: [component] [brief description]`

We will acknowledge within 48 hours and work with you on coordinated
disclosure.

---

## Reporting a new agentic vulnerability (new AVE record)

If you have found a real-world vulnerability in an MCP server, skill file,
plugin, or other agentic component — that is a candidate for a new AVE
record, not a Bawbel security report.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full submission process.

For critical or pre-disclosure submissions:
Email **bawbel.io@gmail.com** subject: `AVE CRITICAL: [brief description]`

---

## Disclosure policy

AVE follows coordinated disclosure for all records.

| Situation | Window |
|---|---|
| Standard component publisher | 90 days from notification |
| CRITICAL severity (AIVSS ≥ 9.0) | 14 days — active exploitation risk |
| Unresponsive publisher | Disclosure proceeds after 14 days of no response |
| Registry operators | Notified simultaneously with publishers; encouraged to quarantine affected components during the window |

All published AVE records are freely accessible in this repository,
at [ave.bawbel.io](https://ave.bawbel.io), and via the PiranhaDB API.
No redacted or partial disclosures.

---

## Scope

| | |
|---|---|
| [bawbel/ave](https://github.com/bawbel/ave) | AVE standard — records and schema |
| [bawbel/ave-site](https://github.com/bawbel/ave-site) | ave.bawbel.io website |
| [bawbel/scanner](https://github.com/bawbel/scanner) | CLI scanner (reference implementation) |
| [api.piranha.bawbel.io](https://api.piranha.bawbel.io) | PiranhaDB threat intel API |
| [bawbel.io](https://bawbel.io) | Bawbel website |

---

## Researcher recognition

Researchers who responsibly disclose a vulnerability in Bawbel tooling, or
who submit an accepted AVE record, receive permanent attribution in the
`researcher` field of the published record. That attribution is immutable —
once published, it stays forever.