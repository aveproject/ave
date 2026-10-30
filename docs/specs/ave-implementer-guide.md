# AVE Implementer Guide

AVE assigns stable ids to behavioral classes of flaws in agentic AI components.
Adding an `ave_id` to your tool's findings lets security teams deduplicate
findings across tools, link to each record's behavioral fingerprint and
indicators, and report against a shared vocabulary.

This guide covers how to get the records into your tool, how to keep them
current without depending on the network at scan time, and what your output
should say so that a finding can be reproduced later.

---

## Which pattern to use

| Your tool | Pattern | Network at scan time |
|---|---|---|
| CI scanner | [Bundle a pinned release](#pin-and-verify-a-release) and verify it at startup | None |
| Air-gapped or regulated environment | [Mirror a release](#air-gapped-use) on a connected host, verify it, transfer it, scan offline | None |
| A tool that only references ids | [Emit ids](#what-to-put-in-your-output) and [watch their status](#watching-status) | None |
| IDE, dashboard or assistant | [The API](#the-api), cached, with a bundled release as fallback | Lookups only |

Start from the offline patterns. The API at `api.aveproject.org` scales to zero,
runs at most one instance and allows 60 requests a minute per IP for each path.
That suits interactive lookups, but a scan should not depend on it. Mature
scanners work the same way: OSV-Scanner downloads its databases on a connected
host (`--download-offline-databases`) and then scans with `--offline` and no
network at all ([OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/)).

Whichever pattern you use, [mapping your rules to AVE ids](#map-your-rules-to-ave-ids)
comes first.

---

## Pin and verify a release

A catalog release is a [GitHub Release](https://github.com/aveproject/ave/releases)
tagged `vX.Y.Z`. It never changes after it is published, and carries three files:

- `ave-records.json`: every published record, whatever its status, except drafts.
- `ave-records.manifest.json`: what the release is (below).
- `SHA256SUMS`: checksums of both files.

The first two also carry a build provenance attestation, signed by the workflow
that built them. `v1.2.0` is the first release with these files.

Download a release and verify it. This needs network access, `curl`, `git`,
Python 3.8 or later and, for the last step, the [GitHub CLI](https://cli.github.com)
signed in to any GitHub account:

```bash
TAG=v1.2.0
mkdir -p "ave-$TAG"
for f in ave-records.json ave-records.manifest.json SHA256SUMS; do
  curl -fsSL -o "ave-$TAG/$f" "https://github.com/aveproject/ave/releases/download/$TAG/$f"
done

(cd "ave-$TAG" && sha256sum -c SHA256SUMS)
git -c advice.detachedHead=false clone -q --depth 1 --branch "$TAG" https://github.com/aveproject/ave ave-src
python3 ave-src/scripts/check_release_assets.py "ave-$TAG" --tag "$TAG" --git-dir ave-src
for f in ave-records.json ave-records.manifest.json; do
  gh attestation verify "ave-$TAG/$f" --repo aveproject/ave \
    --signer-workflow aveproject/ave/.github/workflows/catalog-release.yml
done
```

What each check proves:

- **`sha256sum -c`**: both files are the ones `SHA256SUMS` lists. This catches
  a damaged download. It cannot catch a forged release, because `SHA256SUMS`
  comes from the same place as the files.
- **`check_release_assets.py`**: the manifest describes the records file (its
  `sha256`, `record_count` and every record's `schema_version`), `release` is
  the tag, and `source_commit` is the commit the tag points at. It prints one
  line on success, for example `AVE v1.2.0: 89 records on schema 1.2.0, checksums
  match, source_commit a183155... (checked against the tag's commit).`
- **`gh attestation verify`**: the file was built by `catalog-release.yml` in
  `aveproject/ave`. This is the check that does not trust where you downloaded
  from. A file that differs by a single byte has no attestation and fails.

The manifest of `v1.2.0`:

```json
{
  "release": "v1.2.0",
  "schema_version": "1.2.0",
  "record_count": 89,
  "generated_at": "2026-10-29T04:51:04.844Z",
  "source": "https://github.com/aveproject/ave",
  "sha256": "92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390",
  "source_commit": "a18315536706365021b514ab940392ed0805897e"
}
```

| Field | Meaning |
|---|---|
| `release` | The tag. A release number is the catalog's own; it is not the schema version, and the two move independently. |
| `schema_version` | The schema every record in the release validates against. |
| `record_count` | The number of records in `ave-records.json`. |
| `sha256` | The SHA-256 of `ave-records.json`. |
| `source_commit` | The `aveproject/ave` commit the files were built from: the tagged commit. |
| `generated_at`, `source` | When, and from which repository, the files were built. |

If any check fails, do not use the files. Download them again; if the second
download fails the same way, report it privately to aveproject.org@gmail.com
with the command's output. Keep using the release you had.

### Verify again at startup

Ship the three files with your tool, or install them beside it, and check them
each time the tool starts, before it reads a single record. A file truncated in
packaging or replaced on disk then stops the tool instead of quietly changing
its findings:

```python
import hashlib
import json
from pathlib import Path


def load_ave_catalog(directory):
    """Load a pinned AVE release, refusing one that does not match its manifest."""
    directory = Path(directory)
    manifest = json.loads((directory / "ave-records.manifest.json").read_text())
    raw = (directory / "ave-records.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
        raise RuntimeError(f"{directory}/ave-records.json does not match its manifest")
    records = json.loads(raw)
    if len(records) != manifest["record_count"]:
        raise RuntimeError(f"{directory}/ave-records.json does not hold {manifest['record_count']} records")
    return {r["ave_id"]: r for r in records}, manifest


AVE_RECORDS, AVE_CATALOG = load_ave_catalog("ave-v1.2.0")
print(AVE_CATALOG["release"], len(AVE_RECORDS))  # v1.2.0 89
```

If it raises, fall back to the previous release if you keep one; otherwise stop
and say why. Keep `AVE_CATALOG`: your output reports it
([What to put in your output](#what-to-put-in-your-output)).

### Tracking latest instead

`dist/ave-records-latest.json` on `main` is rebuilt on every change to
`records/`. It has a manifest, `dist/ave-records-latest.manifest.json`, with
`schema_version`, `record_count`, `generated_at` and `sha256` but no `release`
or `source_commit`, and it has no attestation. It is the right input for a
[status check](#watching-status). As the record set a scanner ships, it trades
reproducibility for freshness: if you use it, check its `sha256` against its
manifest and report that `sha256` in your output, because nothing else
identifies a snapshot of `latest`.

---

## Air-gapped use

The same files, staged on a connected host and carried across:

1. **Stage.** On a connected host, run the commands in
   [Pin and verify a release](#pin-and-verify-a-release). They leave the three
   verified files in `ave-$TAG/`.
2. **Transfer** that directory by whatever your environment allows. The clone in
   `ave-src/` is not needed on the other side.
3. **Check again** on the offline host. `sha256sum -c SHA256SUMS` catches damage
   in transit. The attestation check needs the network, which is why it runs
   in step 1.
4. **Configure** your tool with a stable path, and move that path to the new
   release only after the check passes, so a half-copied release is never live.
5. **Refresh** on a stated cadence. Releases are cut when records have changed,
   at most monthly unless a correction is urgent
   ([scaling spec, section 6](scaling-and-governance.md#6-catalog-releases)), so
   checking monthly is enough. When the newest tag is newer than yours, repeat
   from step 1.
6. **Never fetch at scan time.** A scan reads the staged directory and nothing else.

```bash
# On the connected host, after the commands in "Pin and verify a release"
tar -czf "ave-$TAG.tar.gz" "ave-$TAG"

# On the offline host, after the transfer
AVE_DIR=/opt/ave
TAG=v1.2.0
tar -xzf "ave-$TAG.tar.gz" -C "$AVE_DIR"
(cd "$AVE_DIR/ave-$TAG" && sha256sum -c SHA256SUMS) && ln -sfn "ave-$TAG" "$AVE_DIR/current"
```

Your tool reads `$AVE_DIR/current`, and verifies it again at startup as above.
If the check fails, `current` still points at the previous release: keep it,
and stage the new one again.

The newest release, for step 5 (on the connected host):

```bash
curl -fsS https://api.github.com/repos/aveproject/ave/releases/latest | jq -r .tag_name
```

---

## What to put in your output

Each finding carries the `ave_id` it maps to. Each run carries the catalog it
used, so that a finding can be checked later against the same records:

| Where | What | Value |
|---|---|---|
| Each finding | `ave_id` | `AVE-2026-00002` |
| The run | catalog | The manifest's `release`, such as `v1.2.0`, or `latest` if you track `dist/ave-records-latest.json` |
| The run | schema version | The manifest's `schema_version` |
| The run | records SHA-256 | The manifest's `sha256` |

A release tag can be downloaded again at any time. `latest` cannot, which is
why the SHA-256 goes in too.

**SARIF.** Follow [AVE-in-SARIF](ave-in-sarif.md): `result.ruleId` is the
`ave_id`, each AVE record that produced a result has an entry in
`tool.driver.rules`, and the catalog goes in the run's property bag:

```json
{
  "runs": [{
    "properties": {
      "ave_catalog": "v1.2.0",
      "ave_schema_version": "1.2.0",
      "ave_records_sha256": "92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390"
    },
    "results": [{
      "ruleId": "AVE-2026-00002",
      "level": "error",
      "message": { "text": "Tool description contains directives aimed at the agent rather than describing the tool, at line 12" }
    }]
  }]
}
```

The spec has the full mapping, including the `rules` block, `taxonomies` and
which fields never belong on a rule.

**Your own JSON.** The same fields, under whatever names fit your format:

```json
{
  "ave_catalog": "v1.2.0",
  "ave_schema_version": "1.2.0",
  "ave_records_sha256": "92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390",
  "findings": [
    { "rule_id": "your-rule-id", "ave_id": "AVE-2026-00002", "severity": "HIGH" }
  ]
}
```

The smallest useful integration is the `ave_id` on each finding. The run-level
fields are what make it reproducible. For people, link each id to
`https://aveproject.org/registry.html#<ave_id>`.

---

## Watching status

An `ave_id` is never renumbered, reused or deleted. A record's status can still
change: schema 1.2.0 has `active`, `deprecated` and `draft`, and schema 1.3.0
([#104](https://github.com/aveproject/ave/issues/104)) added `merged` and
`rejected`. Schema 1.3.0 is in `dist/ave-records-latest.json`, but no catalog
release carries it yet (`v1.2.0` is on schema 1.2.0), so a tool tracking
`latest` can meet the new statuses before a pinned release can. A record that
leaves `active` stays in the published files with its full content. Treat any
status other than `active` as not active, and do not assume the list of
statuses is complete. No record has left `active` yet, but a tool that cites
ids should find out when one does.

Run a scheduled check against `dist/ave-records-latest.json`, which shows a
status change as soon as it is merged, before the next release. This workflow,
for your own repository, opens an issue when a cited id is not `active`. It
reads the ids from a file, `ave-ids.txt`; change that line to read them from
wherever your mapping lives. It follows cfgaudit's
[`check-ave-ids.yml`](https://github.com/cfgaudit/cfgaudit/blob/main/.github/workflows/check-ave-ids.yml)
([cfgaudit/cfgaudit#720](https://github.com/cfgaudit/cfgaudit/pull/720)), which
reads its ids from its own rule map.

```yaml
name: Check AVE ids

on:
  schedule:
    - cron: "0 8 * * 1"  # Mondays, 08:00 UTC
  workflow_dispatch:

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Check that every AVE id this tool cites is still active
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          ids=$(grep -oE 'AVE-[0-9]{4}-[0-9]{5}' ave-ids.txt | sort -u || true)
          if [ -z "$ids" ]; then
            echo "::error::no AVE ids found in ave-ids.txt"
            exit 1
          fi
          curl -fsSL -o ave-latest.json \
            https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json
          if ! jq -e 'type == "array" and length > 0' ave-latest.json > /dev/null; then
            echo "::error::dist/ave-records-latest.json is not a non-empty JSON array"
            exit 1
          fi

          for id in $ids; do
            status=$(jq -r --arg id "$id" 'map(select(.ave_id == $id))[0].status // "missing"' ave-latest.json)
            echo "$id: $status"
            if [ "$status" != "active" ]; then
              title="AVE update: $id is $status"
              open=$(gh issue list --state open --search "\"$title\" in:title" --json number --jq length)
              if [ "$open" = "0" ]; then
                gh issue create --title "$title" --body "\`$id\` is \`$status\` in aveproject/ave's published records. Read why, and whether another record replaces it: https://github.com/aveproject/ave/commits/main/records/$id.json. Then move or drop the rules that emit it."
              fi
            fi
          done
```

A `missing` id is a mistake in your mapping, since ids are never deleted (or a
draft, which the published files leave out).

When a cited id is no longer `active`:

- **`deprecated`**: superseded by a better understanding of the same class.
  [GOVERNANCE.md](../../GOVERNANCE.md) requires a note explaining why, and no
  field holds it, so read the record and the change that deprecated it (the
  link in the issue). If the note names a record to use instead, move your
  rules there; otherwise drop the mapping and say so in your documentation.
- **`merged`** (schema 1.3.0): a duplicate or sub-case of another record.
  `merged_into` names the surviving record; move your rules to it.
- **`rejected`** (schema 1.3.0): found not to be a distinct behavioral class.
  `rejection_reason` says why and links the public decision; drop the mapping.

---

## The API

`https://api.aveproject.org` serves the same records for lookups. Use the `/v1`
paths. The unversioned paths (`/records/{ave_id}` and so on) are aliases kept
for existing callers, with identical bodies and headers.

| Path | Returns |
|---|---|
| `GET /v1/` | Service status, `api_version`, `schema_version`, `record_count`, and a `catalog` object for the data it serves |
| `GET /v1/records` | Every record |
| `GET /v1/records/{ave_id}` | One record, or `404` for an unknown id |
| `GET /v1/records/{ave_id}/mitigation` | The record's `mitigation` object |
| `GET /v1/search?q=...` | Records whose title, description, attack class or behavioral fingerprint contains the term |
| `GET /v1/releases` | The catalog releases, and which of them can be pinned |

Every data response says which data answered it:

| Header | Value |
|---|---|
| `AVE-API-Version` | `1` |
| `AVE-Catalog` | `latest`, or the release tag when pinned |
| `AVE-Records-SHA256` | The SHA-256 of the record set that answered |
| `AVE-Schema-Version` | That record set's schema version |
| `AVE-Source-Commit` | The commit it was built from, on pinned releases |
| `ETag`, `Last-Modified` | For conditional requests |
| `Cache-Control` | `public, max-age=300` for `latest`; `public, max-age=86400, immutable` for a release |

Send an `ETag` back as `If-None-Match` and an unchanged answer is a `304` with
no body. Add `?release=vX.Y.Z` to any data path to pin it: the API downloads
that release and runs the same checks as `check_release_assets.py` before it
serves anything. An unknown tag is a `404`, and a release that fails the checks
is a `502` and is never served.

```bash
URL=https://api.aveproject.org/v1/records/AVE-2026-00001
curl -s -D - -o /dev/null "$URL"                      # AVE-* headers and an ETag
ETAG=$(curl -s -D - -o /dev/null "$URL" | tr -d '\r' | awk -F': ' 'tolower($1) == "etag" {print $2}')
curl -s -o /dev/null -w '%{http_code}\n' -H "If-None-Match: $ETAG" "$URL"   # 304
curl -s -D - -o /dev/null "$URL?release=v1.2.0"      # AVE-Catalog: v1.2.0
```

Limits to design around: 60 requests a minute per IP for each path (`429`
beyond that), one instance, and scale-to-zero, so the first request after a
quiet spell is slow. It answers `GET` only; `HEAD` is a `405`.

A cached lookup that falls back to the release you bundled:

```python
import httpx

API = "https://api.aveproject.org/v1"
_cache = {}  # ave_id -> (etag, record)


def lookup(ave_id, bundled):
    """One record: from the API when it answers, else the last copy, else the bundled release."""
    etag, record = _cache.get(ave_id, (None, None))
    try:
        resp = httpx.get(f"{API}/records/{ave_id}", headers={"If-None-Match": etag} if etag else {}, timeout=5)
    except httpx.HTTPError:
        return record or bundled.get(ave_id)
    if resp.status_code == 304:
        return record
    if resp.status_code == 200:
        _cache[ave_id] = (resp.headers.get("ETag"), resp.json())
        return _cache[ave_id][1]
    if resp.status_code == 404:
        return None
    return record or bundled.get(ave_id)  # 429 or 5xx: degrade, do not fail


record = lookup("AVE-2026-00001", AVE_RECORDS)  # AVE_RECORDS from load_ave_catalog above
```

---

## Schema versions

Every record states its `schema_version`, and every record in a release has the
release's `schema_version` (`check_release_assets.py` checks this). Validate a
record against the versioned schema it names,
`schema/ave-record-<schema_version>.schema.json` (JSON Schema 2020-12), never
against the alias `schema/ave-record.schema.json`, which moves to the newest
version:

```python
import json
from pathlib import Path

import jsonschema  # pip install jsonschema

records = json.loads(Path("ave-v1.2.0/ave-records.json").read_text())
validators = {}
for record in records:
    version = record["schema_version"]
    if version not in validators:
        schema = json.loads(Path(f"ave-src/schema/ave-record-{version}.schema.json").read_text())
        validators[version] = jsonschema.Draft202012Validator(schema)
    validators[version].validate(record)
print(f"{len(records)} records valid")  # 89 records valid
```

`ave-src` is the clone from [Pin and verify a release](#pin-and-verify-a-release).
Without a clone, fetch the file from the tag:
`https://raw.githubusercontent.com/aveproject/ave/v1.2.0/schema/ave-record-1.2.0.schema.json`.

A versioned schema file never changes once published, not even for a typo, and
neither do the `dist/ave-records-v<schema>.json` snapshots.
`schema/frozen-artifacts.json` holds their SHA-256s, and
`tests/test_frozen_artifacts.py` fails any change to them. A correction ships
in the next version.

---

## Map your rules to AVE ids

To emit AVE ids you need a table from your own rule ids to AVE ids.

**Build your own.** The crosswalks in [`crosswalks/`](../../crosswalks/)
(`<tool>-to-ave.json`, listed in the README's
[Framework crosswalks](../../README.md#framework-crosswalks)) show the format
and the reasoning for each mapping. Build the same for your rules. A rule with
no matching record stays unmapped; do not force it onto the nearest id.

**Ask for one.** Open an issue in this repository with your scanner's detection
categories, and the maintainer will help map them and publish the crosswalk.

---

## Records as enforcement input

The records are not only for scanning files after they are written. Their
`indicators_of_compromise` and `behavioral_fingerprint` are specific enough to
drive a check before an action runs.

[AVE-2026-00048](https://aveproject.org/registry.html#AVE-2026-00048) (unsafe
agent delegation chain) lists "Skill contains delegation instruction with full
access or inherit permissions language" and "Sub-agent spawned without explicit
tool allowlist in the delegation instruction" among its indicators. A gateway
between an agent and its ability to spawn sub-agents can check for exactly those
two conditions and block the spawn, or ask for confirmation, before it happens.

That is enforcement built on AVE, using the records as its input. AVE itself
does not enforce anything; see the README's
[What AVE is not](../../README.md#what-ave-is-not).

---

## Contact

Open an issue at [github.com/aveproject/ave](https://github.com/aveproject/ave) or email
aveproject.org@gmail.com.

Maintaining a scanner? Submit a crosswalk PR, and we will help with the mapping.
