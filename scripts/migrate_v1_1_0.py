# What: Section 5 migration script — bumps every record to schema_version 1.1.0 and
#       inserts provenance_vector, trifecta_profile, and mitigation as null
# Why:  these three objects need to exist (even if unclassified) before the Section 6.2
#       enrichment pass can fill them in; explicit null distinguishes "migration ran,
#       pending enrichment" from a record that predates v1.1.0 entirely
# How:  idempotent per-record transform: bump schema_version, apply the 4.4 renames and
#       aivss.owasp_mcp_mapping deletion if a record hasn't been through the hygiene pass
#       yet, insert the three null objects if absent, validate against the target schema
#       before writing, and leave behavioral_vector/example_patterns untouched (Section 6)
import argparse
import json
import sys
from pathlib import Path

import jsonschema

RENAMES = [
    ("owasp_mapping", "owasp_asi"),
    ("mitre_atlas_mapping", "mitre_atlas"),
    ("nist_ai_rmf_mapping", "nist_ai_rmf"),
]
NEW_NULLABLE_FIELDS = ["provenance_vector", "trifecta_profile", "mitigation"]
TARGET_SCHEMA_VERSION = "1.1.0"


def apply_renames_if_needed(record: dict) -> None:
    rename_map = dict(RENAMES)
    if not any(old in record for old in rename_map):
        return
    renamed = {rename_map.get(k, k): v for k, v in record.items()}
    record.clear()
    record.update(renamed)


def remove_nested_owasp_mcp_mapping_if_present(record: dict) -> None:
    aivss = record.get("aivss", {})
    aivss.pop("owasp_mcp_mapping", None)


def insert_new_nullable_fields(record: dict) -> dict:
    after_key = "behavioral_vector" if "behavioral_vector" in record else "attack_class"
    to_insert = [f for f in NEW_NULLABLE_FIELDS if f not in record]
    if not to_insert:
        return record
    new_record = {}
    for k, v in record.items():
        new_record[k] = v
        if k == after_key:
            for f in NEW_NULLABLE_FIELDS:
                if f not in record:
                    new_record[f] = None
    for f in to_insert:
        if f not in new_record:
            new_record[f] = None
    return new_record


def migrate_record(record: dict) -> tuple[dict, bool]:
    before = json.dumps(record, sort_keys=True)
    apply_renames_if_needed(record)
    remove_nested_owasp_mcp_mapping_if_present(record)
    record = insert_new_nullable_fields(record)
    if record.get("schema_version") != TARGET_SCHEMA_VERSION:
        record["schema_version"] = TARGET_SCHEMA_VERSION
    after = json.dumps(record, sort_keys=True)
    return record, before != after


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_dir", default="records")
    parser.add_argument("--out", dest="out_dir", default="records")
    parser.add_argument("--schema", default="schema/ave-record-1.1.0.schema.json")
    args = parser.parse_args()

    in_dir = Path(args.in_dir)
    out_dir = Path(args.out_dir)
    schema = json.loads(Path(args.schema).read_text())
    validator = jsonschema.Draft202012Validator(schema)

    paths = sorted(in_dir.glob("AVE-*.json"))
    if not paths:
        print(f"No records found under {in_dir}", file=sys.stderr)
        return 1

    changed_count = 0
    for path in paths:
        record = json.loads(path.read_text())
        rid = record.get("ave_id", path.name)
        migrated, changed = migrate_record(record)

        errors = list(validator.iter_errors(migrated))
        if errors:
            print(f"ABORT {rid}: fails schema after migration:", file=sys.stderr)
            for e in errors:
                print(f"  {e.message} (at {'/'.join(str(p) for p in e.path) or '<root>'})", file=sys.stderr)
            return 1

        if changed:
            out_path = out_dir / path.name
            out_path.write_text(json.dumps(migrated, indent=2) + "\n")
            changed_count += 1

    print(f"Checked {len(paths)} records, updated {changed_count}. All validate against {args.schema}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
