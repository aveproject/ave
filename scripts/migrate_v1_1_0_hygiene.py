# What: applies the Section 4 hygiene fixes ahead of the v1.1.0 schema/field changes
#       (template-artifact strip, owasp_mcp sync + nested-field removal, field renames)
# Why:  the v1.1.0 migration script (Section 5) and schema diff (Section 3) assume a clean,
#       already-renamed corpus; running hygiene first keeps each step an independent, diffable PR
# How:  reads every records/*.json, applies 4.1 + 4.3 + 4.4 in place, rewrites only changed files
#       using the corpus's existing json.dumps(indent=2) formatting so diffs stay minimal
import json
import re
import sys
from pathlib import Path

RECORDS_DIR = Path("records")
TRAILING_DASH_RE = re.compile(r"\s*-{2,}\s*$")

# 4.1: fields known to carry authoring-template residue (trailing "---")
DASH_STRIP_FIELDS = ["description", "behavioral_fingerprint", "detection_methodology", "remediation"]
# 4.1: string-array fields known to carry empty/whitespace template placeholders
ARRAY_STRIP_FIELDS = ["indicators_of_compromise", "behavioral_vector"]

# 4.4: old field name -> new field name
RENAMES = [
    ("owasp_mapping", "owasp_asi"),
    ("mitre_atlas_mapping", "mitre_atlas"),
    ("nist_ai_rmf_mapping", "nist_ai_rmf"),
]

# 4.3: records where top-level owasp_mcp is a stale placeholder and the nested
# aivss.owasp_mcp_mapping holds the correct value that must be copied up first
OWASP_MCP_SYNC_IDS = {f"AVE-2026-{i:05d}" for i in range(41, 46)}


def strip_template_artifacts(record: dict) -> bool:
    changed = False
    for field in DASH_STRIP_FIELDS:
        val = record.get(field)
        if isinstance(val, str):
            stripped = TRAILING_DASH_RE.sub("", val).rstrip()
            if stripped != val:
                record[field] = stripped
                changed = True
    for field in ARRAY_STRIP_FIELDS:
        val = record.get(field)
        if isinstance(val, list):
            cleaned = [x for x in val if not (isinstance(x, str) and x.strip() == "")]
            if cleaned != val:
                if len(cleaned) == 0:
                    raise ValueError(f"{record['ave_id']}: stripping empties from {field} leaves it empty")
                record[field] = cleaned
                changed = True
    return changed


def sync_and_remove_owasp_mcp(record: dict) -> bool:
    changed = False
    aivss = record.get("aivss", {})
    nested = aivss.get("owasp_mcp_mapping")
    if record["ave_id"] in OWASP_MCP_SYNC_IDS:
        if not nested:
            raise ValueError(f"{record['ave_id']}: expected nested aivss.owasp_mcp_mapping to sync, found none")
        record["owasp_mcp"] = nested
        changed = True
    if "owasp_mcp_mapping" in aivss:
        del aivss["owasp_mcp_mapping"]
        changed = True
    return changed


def apply_renames(record: dict) -> bool:
    rename_map = dict(RENAMES)
    for old, new in RENAMES:
        if old in record and new in record:
            raise ValueError(f"{record['ave_id']}: both {old} and {new} present, refusing to overwrite")
    if not any(old in record for old in rename_map):
        return False
    renamed = {rename_map.get(k, k): v for k, v in record.items()}
    record.clear()
    record.update(renamed)
    return True


def migrate_record(path: Path) -> bool:
    record = json.loads(path.read_text())
    changed = False
    if strip_template_artifacts(record):
        changed = True
    if sync_and_remove_owasp_mcp(record):
        changed = True
    if apply_renames(record):
        changed = True
    if changed:
        path.write_text(json.dumps(record, indent=2) + "\n")
    return changed


def main() -> int:
    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print("No records found under records/", file=sys.stderr)
        return 1
    changed_count = 0
    for path in paths:
        if migrate_record(path):
            changed_count += 1
    print(f"Checked {len(paths)} records, updated {changed_count}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
