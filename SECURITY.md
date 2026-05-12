# Security Policy

## Reporting a Vulnerability in Bawbel or AVE

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **bawbel.io@gmail.com**
Subject line: `SECURITY: [bawbel-scanner or ave] [brief description]`

We will acknowledge your report within 48 hours and work with you on
coordinated disclosure.

---

## Reporting a New Agentic Vulnerability (New AVE Record)

If you have found a real-world vulnerability in an MCP server, skill file,
or other agentic component, that is a candidate for a new AVE record.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the submission process.

Email for critical or pre-disclosure submissions:
**bawbel.io@gmail.com** subject: `AVE CRITICAL: [brief description]`

---

## Disclosure Policy

Bawbel follows coordinated disclosure for all AVE records.

**Component publishers:** 90-day notification window before public disclosure.

**Critical severity (AIVSS 9.0+):** 14-day window due to active exploitation
risk.

**Unresponsive publishers:** If no response after 14 days of notification,
disclosure proceeds.

**Registry operators:** Notified simultaneously with publishers and encouraged
to quarantine affected components during the disclosure window.

**Community:** All published AVE records are freely accessible in this
repository and via [PiranhaDB](https://api.piranha.bawbel.io). No redacted
or partial disclosures.

---

## Scope

This security policy covers:

- [bawbel/bawbel-scanner](https://github.com/bawbel/bawbel-scanner): the CLI scanner
- [bawbel/ave](https://github.com/bawbel/ave): the AVE specification and records
- [api.piranha.bawbel.io](https://api.piranha.bawbel.io): the PiranhaDB API
- [bawbel.io](https://bawbel.io): the Bawbel website and documentation

---

## Researcher Recognition

Security researchers who responsibly disclose vulnerabilities in Bawbel
or submit accepted AVE records receive permanent attribution and are
eligible for a thank-you bounty.