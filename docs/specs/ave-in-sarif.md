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

## Two ways to carry the AVE id

A result names its AVE class in one of two forms. Both are conformant, and a consumer reads either.

| | Form A: the AVE id is the rule id | Form B: the tool keeps its own rule id |
|---|---|---|
| `result.ruleId` | the `ave_id`, e.g. `AVE-2026-00001` | the tool's own rule id, e.g. `example-rule-7` |
| `rules[].id` | the `ave_id` | the same tool rule id |
| `result.properties.ave_id` | not needed | the `ave_id` (required) |
| `rules[].properties.ave_id` | not needed | the `ave_id` (required) |

Form A suits a scanner whose rules are AVE classes. Form B suits a scanner whose rules are finer than AVE classes, or exist beyond AVE: several of its rules can name one class, and its own rule ids stay stable for its own users. In either form a result's `ruleId` matches a `rules[].id` in the same run, and everything else in this document applies unchanged.

A consumer reading ids takes `result.ruleId` when it is an AVE id, and otherwise `result.properties.ave_id`. [`scripts/ave_conformance.py`](../../scripts/ave_conformance.py) does exactly this, and judges an output against both forms (see the [implementer guide](ave-implementer-guide.md#check-your-output)).

---

## Required SARIF fields for AVE findings

### rules block — static record data (one entry per AVE record)

Each AVE record that produced at least one detection must appear in `run.tool.driver.rules` (form B: the tool's rule that produced it, carrying the id in `properties.ave_id`):

| SARIF field | AVE source | Notes |
|---|---|---|
| `rules[].id` | `ave_id` | e.g. `"AVE-2026-00001"`; in form B the tool's own rule id |
| `rules[].properties.ave_id` | `ave_id` | form B only: the AVE class this rule reports |
| `rules[].name` | `attack_class` | e.g. `"external_instruction_fetch"` |
| `rules[].shortDescription.text` | `title` | human-readable title |
| `rules[].fullDescription.text` | `description` | full paragraph description |
| `rules[].helpUri` | `"https://aveproject.org/registry.html#<ave_id>"` | deep link to registry |
| `rules[].properties.severity` | `severity` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `rules[].properties.aivss_score` | `aivss.aivss_score` | float, e.g. `9.3` |
| `rules[].properties.owasp_mcp` | `owasp_mcp` | array of MCPNN strings |
| `rules[].properties.mitre_atlas` | `mitre_atlas` | array of AML.Txxxx strings (if present) |
| `rules[].properties.owasp_asi` | `owasp_asi` | array of ASINN strings (if present) |
| `rules[].properties.nist_ai_rmf` | `nist_ai_rmf` | array of NIST AI RMF function-category strings (if present) |

### results block — per-detection data (one entry per finding)

Each detection instance is a SARIF `result`:

| SARIF field | AVE source | Notes |
|---|---|---|
| `result.ruleId` | `ave_id` | form A; in form B the tool's own rule id. Either way it must match a `rules[].id` in the same run |
| `result.properties.ave_id` | `ave_id` | form B only: required, and the same as the rule's |
| `result.message.text` | `behavioral_fingerprint` + match location | e.g. `"External URL fetch in tool description at line 12"` |
| `result.level` | severity mapping (see below) | `"error"`, `"warning"`, or `"note"` |
| `result.locations[].physicalLocation` | scanner-determined | file path + region (line/column) |
| `result.properties.confidence` | **per-detection float** | assigned by scanner; NOT from the AVE record |
| `result.properties.evidence_kind` | `evidence_kind_default` | scanner may override per-detection |
| `result.properties.evidence_stage` | runtime-determined | `"static_detection"`, `"runtime_observed"`, etc. |
| `result.properties.owasp_mcp` | `owasp_mcp` | repeated on result for tooling that ignores the rules block |
| `result.properties.mitre_atlas` | `mitre_atlas` | repeated if present |
| `result.properties.owasp_asi` | `owasp_asi` | repeated if present |
| `result.properties.nist_ai_rmf` | `nist_ai_rmf` | repeated if present |
| `result.properties.verification_basis` | `verification_basis` | optional; present only where the source record carries a derived value (4 of 86 records as of this revision). A string, one of `substrate_intercepted`/`substrate_reconstructed`/`artifact_intercepted`/`artifact_reconstructed`. Tells a consumer whether this finding's basis could be forged by the artifact itself, finer-grained than `confidence_baseline` alone. Do not infer absence as "low confidence"; most records simply haven't had it derived yet. |

### run properties: which catalog the scan used (recommended)

One set per run, in the run's property bag, so that a finding can be checked later against the same records. All three come from the manifest of the record set the scanner loaded (`ave-records.manifest.json` on a catalog release, or `dist/ave-records-latest.manifest.json`):

| SARIF field | AVE source | Notes |
|---|---|---|
| `runs[].properties.ave_catalog` | manifest `release` | the catalog release tag, e.g. `"v1.2.0"`; `"latest"` when the scanner loaded `dist/ave-records-latest.json`, whose manifest has no `release` |
| `runs[].properties.ave_schema_version` | manifest `schema_version` | e.g. `"1.2.0"` |
| `runs[].properties.ave_records_sha256` | manifest `sha256` | SHA-256 of the records file; the only identifier of a `latest` snapshot, since a release tag can be downloaded again and `latest` cannot |

These are catalog data, not record data: they never go on `rules[]` or on a `result`. The [implementer guide](ave-implementer-guide.md#what-to-put-in-your-output) covers the same fields for output that is not SARIF.

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
    "version": "1.2.0",
    "releaseDateUtc": "2026-10-29",
    "informationUri": "https://aveproject.org",
    "downloadUri": "https://github.com/aveproject/ave/releases/download/v1.2.0/ave-records.json",
    "organization": "AVE Project",
    "shortDescription": {
      "text": "Agentic Vulnerability Enumeration — behavioral vulnerability classes for agentic AI components"
    },
    "taxa": [
      {
        "id": "AVE-2026-00001",
        "name": "Metamorphic payload via external config fetch",
        "helpUri": "https://aveproject.org/registry.html#AVE-2026-00001"
      }
    ]
  }
]
```

Add one taxon per AVE record that appears in the scan results. Scanners may include the full taxa list for all published records to enable filtering even for records with zero findings.

`version` is the catalog release the scan used, without its `v` (the same release as `runs[].properties.ave_catalog`), `releaseDateUtc` is that release's publication date, and `downloadUri` is that release's `ave-records.json`. A scanner tracking `dist/ave-records-latest.json` has no release to name: it omits `version` and `releaseDateUtc`, and uses `https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json` as `downloadUri`.

---

## Example: minimal valid SARIF output

One finding for AVE-2026-00001 (metamorphic payload via external config fetch) against a hypothetical skill file:

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
              "name": "Supply Chain - Metamorphic Payload",
              "shortDescription": {
                "text": "Metamorphic payload via external config fetch"
              },
              "fullDescription": {
                "text": "A skill or MCP component fetches its instructions from an external URL at runtime. The fetched content replaces the original instructions, allowing an attacker to change the component's behavior after it passes a security review. The attack is invisible to static scanners because the malicious payload does not exist at scan time."
              },
              "helpUri": "https://aveproject.org/registry.html#AVE-2026-00001",
              "properties": {
                "severity": "HIGH",
                "aivss_score": 8.0,
                "owasp_mcp": ["MCP04", "MCP06"],
                "mitre_atlas": ["AML.T0011", "AML.T0081"],
                "owasp_asi": ["ASI01", "ASI04"],
                "nist_ai_rmf": ["MAP-1.5", "MEASURE-2.5", "MANAGE-1.3"]
              }
            }
          ]
        }
      },
      "taxonomies": [
        {
          "name": "AVE",
          "version": "1.2.0",
          "informationUri": "https://aveproject.org",
          "taxa": [
            {
              "id": "AVE-2026-00001",
              "name": "Metamorphic payload via external config fetch"
            }
          ]
        }
      ],
      "results": [
        {
          "ruleId": "AVE-2026-00001",
          "level": "error",
          "message": {
            "text": "Component contains instructions to fetch and execute remote content, replacing its own behavioral instructions at runtime. Matched pattern: `requests.get(` at line 14."
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
            "confidence": 0.88,
            "evidence_kind": "multi_engine",
            "evidence_stage": "static_detection",
            "owasp_mcp": ["MCP04", "MCP06"],
            "mitre_atlas": ["AML.T0011", "AML.T0081"],
            "owasp_asi": ["ASI01", "ASI04"],
            "nist_ai_rmf": ["MAP-1.5", "MEASURE-2.5", "MANAGE-1.3"]
          }
        }
      ],
      "properties": {
        "ave_catalog": "v1.2.0",
        "ave_schema_version": "1.2.0",
        "ave_records_sha256": "92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390"
      }
    }
  ]
}
```

---

## Example: form B

The same finding from a scanner that keeps its own rule ids. Only the rule id and the two `ave_id` properties differ from the example above; the run properties and the taxonomy are the same.

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "example-scanner",
          "version": "1.0.0",
          "rules": [
            {
              "id": "example-rule-7",
              "name": "Instructions fetched from a URL",
              "properties": {
                "ave_id": "AVE-2026-00001"
              }
            }
          ]
        }
      },
      "taxonomies": [
        {
          "name": "AVE",
          "version": "1.2.0",
          "informationUri": "https://aveproject.org",
          "taxa": [
            {
              "id": "AVE-2026-00001",
              "name": "Metamorphic payload via external config fetch"
            }
          ]
        }
      ],
      "results": [
        {
          "ruleId": "example-rule-7",
          "level": "error",
          "message": {
            "text": "Component fetches its instructions from a URL at runtime, at line 14."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "skills/data-fetcher.md"
                },
                "region": {
                  "startLine": 14
                }
              }
            }
          ],
          "properties": {
            "ave_id": "AVE-2026-00001",
            "confidence": 0.88,
            "evidence_stage": "static_detection"
          }
        }
      ],
      "properties": {
        "ave_catalog": "v1.2.0",
        "ave_schema_version": "1.2.0",
        "ave_records_sha256": "92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390"
      }
    }
  ]
}
```

---

## Field placement summary

| Data | Goes in `rules[]` | Goes in `result` |
|---|---|---|
| `ave_id` | `rules[].id` (form B: `rules[].properties.ave_id`) | `result.ruleId` (form B: `result.properties.ave_id`) |
| `title` | `rules[].shortDescription.text` | — |
| `description` | `rules[].fullDescription.text` | — |
| `behavioral_fingerprint` | — | `result.message.text` (with location) |
| `severity` | `rules[].properties.severity` | — (drives `result.level`) |
| `aivss_score` | `rules[].properties.aivss_score` | — |
| `confidence` | **never** | `result.properties.confidence` |
| `evidence_kind_default` | — | `result.properties.evidence_kind` |
| `owasp_mcp` | `rules[].properties.owasp_mcp` | `result.properties.owasp_mcp` |
| `mitre_atlas` | `rules[].properties.mitre_atlas` | `result.properties.mitre_atlas` |
| `owasp_asi` | `rules[].properties.owasp_asi` | `result.properties.owasp_asi` |
| `nist_ai_rmf` | `rules[].properties.nist_ai_rmf` | `result.properties.nist_ai_rmf` |
| `verification_basis` | **never** | `result.properties.verification_basis` (if the record has one) |

The catalog the scan used goes on the run, not here: `runs[].properties.ave_catalog`, `ave_schema_version` and `ave_records_sha256`.

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

This convention has its own version, separate from the AVE schema's: **AVE-in-SARIF v1.0**. The two don't move in lockstep, because this document maps schema field *names* into SARIF, not a frozen schema snapshot. A record that validates against whatever the current AVE schema version is still maps the same way, as long as the field names and semantics this document references haven't changed.

Breaking changes to *this convention* (new required fields, removed fields, changed semantics) increment the major version and are announced with a 30-day notice period. Additive changes (new optional `result.properties.*` fields) are non-breaking and do not increment the version.

**Revision note (2026-10-01):** the worked example, `taxonomies` block, and properties tables had gone stale against the live schema and corpus without the version number moving, which is itself the failure mode this section exists to prevent. Checked and corrected: `downloadUri`/`organization` were pointing at Bawbel-branded infrastructure (`api.piranha.bawbel.io`, "Bawbel Security Research") rather than AVE's own real, independent API and identity; the worked example cited `AVE-2026-00001` with `owasp_mcp`/`mitre_atlas` values that no longer matched the live record; `owasp_asi` and `nist_ai_rmf` existed on records with no documented SARIF representation at all. All of that is corrected above. None of it was a breaking change under this section's own rule, so the version stays v1.0; what changed is this document matching reality again, not the convention's own shape.

**Revision note (2026-10-29):** added the recommended run properties `ave_catalog`, `ave_schema_version` and `ave_records_sha256`, which name the catalog release a scan used, now that releases are published with a manifest (`v1.2.0` onwards). Also stated what `taxonomies[].version`, `releaseDateUtc` and `downloadUri` hold, which this document had left unspecified: that same release's version, date and `ave-records.json`. Both examples moved from `1.1.0` to the `v1.2.0` release. The run properties are optional and no existing field was removed or changed, so the version stays v1.0.

**Revision note (2026-10-31):** added form B, a second way to carry the AVE id (a tool's own `ruleId`, with `properties.ave_id` on the rule and on each result), because a tool that emits AVE ids in SARIF today does exactly that. Form A is unchanged. No field changed meaning and every output that was conformant still is, so the version stays v1.0; a consumer that read only `result.ruleId` must now also read `properties.ave_id` to see form B's ids. The same change adds `scripts/ave_conformance.py`, which checks an output against both forms.
