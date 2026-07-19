# AVE Implementer Guide — Adding AVE IDs to Your Scanner

AVE assigns stable behavioral classification IDs to agentic AI component flaws.
Adding an `ave_id` field to your scanner's finding output lets security teams
deduplicate findings across tools, link to full behavioral fingerprints and IOCs,
and report against a shared vocabulary. This guide covers three consumption patterns
depending on your environment.

---

## Which pattern to use

| Your environment | Recommended pattern |
|---|---|
| Cloud CI/CD, always-on internet | Pattern 1: Runtime API |
| Mixed or uncertain | Pattern 2: Bundled offline |
| Air-gapped or regulated (banking, defense, healthcare) | Pattern 2: Bundled offline or Pattern 3: ID-only |
| Enterprise SIEM resolves references downstream | Pattern 3: ID-only |

---

## Pattern 1 — Runtime API lookup

Scanner emits `ave_id` in its finding output and optionally calls the PiranhaDB API
at scan time to enrich with the full record.

**API endpoint:** `GET https://api.piranha.bawbel.io/ave/{ave_id}`

Returns: full record JSON including `behavioral_fingerprint`, `indicators_of_compromise`,
`remediation`, `owasp_mcp`, `mitre_atlas`, `aivss`.

```python
import httpx

def enrich_finding(ave_id: str) -> dict:
    resp = httpx.get(f"https://api.piranha.bawbel.io/ave/{ave_id}", timeout=5)
    resp.raise_for_status()
    return resp.json()

finding = {
    "rule_id": "your-rule-id",
    "ave_id": "AVE-2026-00002",
    "severity": "HIGH",
    # optional: enrich at scan time
    "ave_record": enrich_finding("AVE-2026-00002"),
}
```

**When to use:** developer machines, cloud CI/CD pipelines, SaaS tools with outbound
internet.

**When not to use:** air-gapped environments, regulated environments where outbound
calls to third-party APIs are blocked.

---

## Pattern 2 — Bundled offline record set

Download the full AVE record set at build/install time. Bundle it with your scanner.
At scan time, look up records locally.

**Offline artifact, always current, no release tag required:**
`https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json`

Regenerated automatically on every `records/` change on `develop`; see
`scripts/build-records.js`. A companion manifest at
`dist/ave-records-latest.manifest.json` carries `schema_version`,
`record_count`, and `generated_at` for a cheap sanity check before parsing
the full array. A versioned, frozen snapshot is also committed at each
schema transition (`dist/ave-records-v1.1.0.json`, later
`dist/ave-records-v1.2.0.json`, and so on) for anyone who deliberately
wants to pin to one point in time rather than track current; a
[GitHub Release](https://github.com/aveproject/ave/releases) attaches the
matching frozen file as a second distribution point when one is cut, not
the only one.

Format: JSON array of all active records (59 as of schema v1.1.0).

```python
import json
from pathlib import Path

# Load at startup
AVE_RECORDS = {
    r["ave_id"]: r
    for r in json.loads(Path("ave-records-latest.json").read_text())
}

def lookup_ave(ave_id: str) -> dict | None:
    return AVE_RECORDS.get(ave_id)
```

**Sync strategy:** track `ave-records-latest.json` if you always want current
data, or pin to a specific `ave-records-v<version>.json` snapshot if you want
stability -- that file is frozen once written and never changes underneath
you. Either way, do not auto-update at runtime; re-fetch on your own release
cadence.

**When to use:** air-gapped environments, regulated environments, tools that cannot
make outbound calls, offline-first scanners.

---

## Pattern 3 — ID-only emission

Scanner emits `ave_id` in its finding output. No enrichment at scan time. The
consuming system (SIEM, dashboard, ticket system, SARIF viewer) resolves the ID when
connectivity is available.

This is the most air-gap-friendly pattern because the scanner itself makes zero
network calls related to AVE.

**Example SARIF output** (the correct way to carry `ave_id` in SARIF):

```json
{
  "runs": [{
    "results": [{
      "ruleId": "your-rule-id",
      "properties": {
        "ave_id": "AVE-2026-00002",
        "ave_url": "https://aveproject.org/registry.html#AVE-2026-00002",
        "ave_api": "https://api.piranha.bawbel.io/ave/AVE-2026-00002"
      }
    }]
  }]
}
```

Full SARIF convention: [docs/specs/ave-in-sarif.md](ave-in-sarif.md)

**When to use:** any environment. Especially useful when the scanner runs in a
restricted environment but findings are reviewed in a connected dashboard.

---

## The mapping step

To emit AVE IDs, you need a mapping from your internal rule IDs to AVE IDs. Two
options:

**Option A: Build your own mapping table.** Use the crosswalk files in this repo as
reference:

- `crosswalks/skillspector-to-ave.json` — maps NVIDIA SkillSpector categories to AVE IDs
- `crosswalks/clawscan-to-ave.json` — maps ClawScan rule IDs to AVE IDs

These show the mapping format and rationale. Build an equivalent for your own rule IDs.

**Option B: Request a crosswalk.** Open an issue in this repo with your scanner's
detection categories. The maintainer will help map them to AVE IDs and publish the
crosswalk.

---

## Minimum viable integration

The smallest possible integration is adding one field:

```python
finding = {
    "rule_id": "prompt-injection/tool-description",
    "severity": "HIGH",
    "ave_id": "AVE-2026-00002",  # add this
}
```

That is it. The ID is stable and permanent. No other changes required. Your users get
cross-tool deduplication and links to the full behavioral record.

---

## Contact

Open an issue at [github.com/aveproject/ave](https://github.com/aveproject/ave) or email
aveproject.org@gmail.com.

Maintaining a scanner? Submit a crosswalk PR — we will help with the mapping.