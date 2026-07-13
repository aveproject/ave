# AVE-in-SARIF Convention v1.0

This document specifies how AVE findings travel as SARIF (Static Analysis Results Interchange Format, OASIS Standard v2.1.0) so they reach the GitHub Security tab and CI systems without any extra integration work.

A scanner that emits correct AVE-in-SARIF gets GitHub Security tab integration for free.

---

## Background

SARIF is the interchange format consumed by:

- **GitHub Advanced Security** — Security tab, code scanning alerts, PR annotations
- **VS Code** — Problems panel via the SARIF Viewer extension
- **Azure DevOps, GitLab, Semgrep, CodeQL** — native SARIF import
- **CI pipelines** — artifact storage, quality gates

AVE records are static vulnerability definitions. A scanner (e.g. bawbel/scanner) produces one SARIF `result` per detection that references an AVE record by `ave_id`. The schema model maps cleanly to SARIF's `rule` / `result` split.

---

## Required SARIF fields for AVE findings

### rules block — static record data (one entry per AVE record)

Each AVE record that produced at least one detection must appear in `run.tool.driver.rules`:

| SARIF field | AVE source | Notes |
|---|---|---|
| `rules[].id` | `ave_id` | e.g. `"AVE-2026-00001"` |
| `rules[].name` | `attack_class` | e.g. `"external_instruction_fetch"` |
| `rules[].shortDescription.text` | `title` | human-readable title |
| `rules[].fullDescription.text` | `description` | full paragraph description |
| `rules[].helpUri` | `"https://ave.bawbel.io/registry.html#<ave_id>"` | deep link to registry |
| `rules[].properties.severity` | `severity` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `rules[].properties.aivss_score` | `aivss.aivss_score` | float, e.g. `9.3` |
| `rules[].properties.owasp_mcp` | `owasp_mcp` | array of MCPNN strings |
| `rules[].properties.mitre_atlas` | `mitre_atlas` | array of AML.Txxxx strings (if present) |

### results block — per-detection data (one entry per finding)

Each detection instance is a SARIF `result`:

| SARIF field | AVE source | Notes |
|---|---|---|
| `result.ruleId` | `ave_id` | must match a `rules[].id` |
| `result.message.text` | `behavioral_fingerprint` + match location | e.g. `"External URL fetch in tool description at line 12"` |
| `result.level` | severity mapping (see below) | `"error"`, `"warning"`, or `"note"` |
| `result.locations[].physicalLocation` | scanner-determined | file path + region (line/column) |
| `result.properties.confidence` | **per-detection float** | assigned by scanner; NOT from the AVE record |
| `result.properties.evidence_kind` | `evidence_kind_default` | scanner may override per-detection |
| `result.properties.evidence_stage` | runtime-determined | `"static_detection"`, `"runtime_observed"`, etc. |
| `result.properties.owasp_mcp` | `owasp_mcp` | repeated on result for tooling that ignores the rules block |
| `result.properties.mitre_atlas` | `mitre_atlas` | repeated if present |

---

## Severity mapping

| AVE severity | SARIF level | GitHub Security tab label |
|---|---|---|
| CRITICAL | `"error"` | Critical |
| HIGH | `"error"` | High |
| MEDIUM | `"warning"` | Medium |
| LOW | `"note"` | Low |

GitHub Security tab maps `error` to High/Critical, `warning` to Medium, and `note` to Low/Informational.

---

## Key rule: confidence is per-finding, never per-rule

SARIF `run.tool.driver.rules` carries **static record data** — fields that come directly from the AVE record JSON.

SARIF `result.properties.confidence` carries the **per-detection confidence** — a float computed by the scanner at scan time, informed by `confidence_baseline` from the AVE record but adjusted for the specific detection context.

**Never put `confidence` in the `rules` block.** An AVE record declares `confidence_baseline` (what the scanner should start from), not actual confidence (what the scanner assigned). Putting a static confidence on the rule misleads GitHub and CI tooling into treating every detection at the same confidence regardless of evidence strength.

---

## SARIF taxonomies block

Include an AVE taxonomy entry alongside the `runs` array so that tools can cross-reference findings against the full AVE record set:

```json
"taxonomies": [
  {
    "name": "AVE",
    "version": "1.0.0",
    "releaseDateUtc": "2026-06-18",
    "informationUri": "https://ave.bawbel.io",
    "downloadUri": "https://api.piranha.bawbel.io/records",
    "organization": "Bawbel Security Research",
    "shortDescription": {
      "text": "Agentic Vulnerability Enumeration — behavioral vulnerability classes for agentic AI components"
    },
    "taxa": [
      {
        "id": "AVE-2026-00001",
        "name": "Supply Chain - Metamorphic Payload via External Config Fetch",
        "helpUri": "https://ave.bawbel.io/registry.html#AVE-2026-00001"
      }
    ]
  }
]
```

Add one taxon per AVE record that appears in the scan results. Scanners may include the full 48-record taxa list to enable filtering even for records with zero findings.

---

## Example: minimal valid SARIF output

One finding for AVE-2026-00001 (external instruction fetch) against a hypothetical skill file:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "bawbel-scanner",
          "version": "1.0.0",
          "informationUri": "https://github.com/bawbel/scanner",
          "rules": [
            {
              "id": "AVE-2026-00001",
              "name": "external_instruction_fetch",
              "shortDescription": {
                "text": "Supply Chain - Metamorphic Payload via External Config Fetch"
              },
              "fullDescription": {
                "text": "A skill or MCP component fetches instructions or configuration from an external URL at runtime, allowing an attacker who controls that URL to inject arbitrary directives into the agent's execution context."
              },
              "helpUri": "https://ave.bawbel.io/registry.html#AVE-2026-00001",
              "properties": {
                "severity": "CRITICAL",
                "aivss_score": 9.3,
                "owasp_mcp": ["MCP03", "MCP09"],
                "mitre_atlas": ["AML.T0010", "AML.T0043"]
              }
            }
          ]
        }
      },
      "taxonomies": [
        {
          "name": "AVE",
          "version": "1.0.0",
          "informationUri": "https://ave.bawbel.io",
          "taxa": [
            {
              "id": "AVE-2026-00001",
              "name": "Supply Chain - Metamorphic Payload via External Config Fetch"
            }
          ]
        }
      ],
      "results": [
        {
          "ruleId": "AVE-2026-00001",
          "level": "error",
          "message": {
            "text": "Tool description fetches instructions from an external URL at runtime. An attacker controlling the URL can inject arbitrary directives. Matched pattern: `requests.get(` at line 14."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "skills/data-fetcher.md",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 14,
                  "startColumn": 1,
                  "endLine": 14,
                  "endColumn": 60
                }
              }
            }
          ],
          "properties": {
            "confidence": 0.91,
            "evidence_kind": "tool_description_pattern",
            "evidence_stage": "static_detection",
            "owasp_mcp": ["MCP03", "MCP09"],
            "mitre_atlas": ["AML.T0010", "AML.T0043"]
          }
        }
      ]
    }
  ]
}
```

---

## Field placement summary

| Data | Goes in `rules[]` | Goes in `result` |
|---|---|---|
| `ave_id` | `rules[].id` | `result.ruleId` |
| `title` | `rules[].shortDescription.text` | — |
| `description` | `rules[].fullDescription.text` | — |
| `behavioral_fingerprint` | — | `result.message.text` (with location) |
| `severity` | `rules[].properties.severity` | — (drives `result.level`) |
| `aivss_score` | `rules[].properties.aivss_score` | — |
| `confidence` | **never** | `result.properties.confidence` |
| `evidence_kind_default` | — | `result.properties.evidence_kind` |
| `owasp_mcp` | `rules[].properties.owasp_mcp` | `result.properties.owasp_mcp` |
| `mitre_atlas` | `rules[].properties.mitre_atlas` | `result.properties.mitre_atlas` |

---

## GitHub Security tab integration checklist

For findings to appear correctly in the GitHub Security tab:

- [ ] SARIF file uploaded via `github/codeql-action/upload-sarif@v3` or equivalent
- [ ] `result.level` set correctly per severity mapping above
- [ ] `result.locations[].physicalLocation.artifactLocation.uri` is a repo-relative path
- [ ] `result.ruleId` matches a `rules[].id` in the same run
- [ ] `run.tool.driver.name` is stable across runs (GitHub de-duplicates by tool name + ruleId + location)
- [ ] `result.properties.confidence` present (GitHub displays it in the finding detail)
- [ ] `rules[].helpUri` set (GitHub links "Learn more" to this URL)

---

## Versioning

This convention is versioned alongside the AVE schema. The current version is **AVE-in-SARIF v1.0**, corresponding to AVE schema v1.0.0.

Breaking changes (new required fields, removed fields, changed semantics) increment the major version and are announced with a 30-day notice period. Additive changes (new optional `result.properties.*` fields) are non-breaking and do not increment the version.
