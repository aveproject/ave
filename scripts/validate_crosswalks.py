# What: validates every file in crosswalks/ against schema/crosswalk-1.0.0.schema.json,
#       the same way scripts/validate_records.py validates records/ against the record
#       schema, plus two checks the schema cannot express on its own: that the $schema
#       a crosswalk declares is a schema this repository actually ships, and that every
#       AVE identifier a crosswalk cites resolves to a record in records/
# Why:  every crosswalk in this repository declares
#       https://aveproject.org/schema/crosswalk-1.0.0.schema.json and, until that file
#       existed, nothing validated any of them. A dangling $schema URL is worse than
#       none: it reads as validated. The identifier check is the other half -- a
#       crosswalk row pointing at an AVE id that was never published, or that was
#       renumbered before the immutability rule, is a broken mapping that no schema
#       pattern can catch, because the id is well-formed and simply does not exist.
# How:  jsonschema.Draft202012Validator with format checking enabled, so the date and
#       uri formats in the schema are enforced rather than annotated, over every
#       crosswalks/*.json; then a set membership test of every cited id against the
#       ave_id values in records/. jsonschema implements the date checker itself but
#       registers uri only when rfc3986-validator is installed, so that package is a
#       dev dependency here; without it "format": "uri" parses and then constrains
#       nothing, and the ^https?:// pattern beside it is the only thing refusing a
#       bad url.
import json
import sys
from pathlib import Path

import jsonschema

CROSSWALKS_DIR = Path("crosswalks")
RECORDS_DIR = Path("records")
SCHEMA_PATH = Path("schema/crosswalk-1.0.0.schema.json")


def known_ave_ids() -> set[str]:
    ids: set[str] = set()
    for path in sorted(RECORDS_DIR.glob("AVE-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        ave_id = record.get("ave_id")
        if isinstance(ave_id, str):
            ids.add(ave_id)
    return ids


def cited_ave_ids(node: object) -> set[str]:
    """Every value under an ave_id / primary_ave_id / ave_ids key, at any depth.

    Only these three keys are read. Prose fields mention identifiers too, and a
    substring sweep would flag a record named in a note as if it were a mapping
    target.
    """
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("ave_id", "primary_ave_id") and isinstance(value, str):
                found.add(value)
            elif key == "ave_ids" and isinstance(value, list):
                found.update(item for item in value if isinstance(item, str))
            found |= cited_ave_ids(value)
    elif isinstance(node, list):
        for item in node:
            found |= cited_ave_ids(item)
    return found


def check_schema(document: dict, validator: jsonschema.Draft202012Validator) -> list[str]:
    return [f"schema: {e.message} (at {'/'.join(str(p) for p in e.path) or '<root>'})"
            for e in validator.iter_errors(document)]


def check_declared_schema_is_shipped(document: dict) -> list[str]:
    declared = document.get("$schema")
    if not isinstance(declared, str):
        return []
    filename = declared.rsplit("/", 1)[-1]
    if not (Path("schema") / filename).is_file():
        return [f"$schema declares {declared}, which this repository does not ship "
                f"as schema/{filename}"]
    return []


def check_ave_ids_resolve(document: dict, published: set[str]) -> list[str]:
    # Only the record-format ids are checked. ave-to-ast10.json carries free text
    # under gaps_in_ast10[].ave_id ("all 56 records"), which is a prose value in a
    # field whose name suggests otherwise; it is left alone here rather than
    # reported as a dangling record.
    return [f"cites {ave_id}, which is not a record in {RECORDS_DIR}/"
            for ave_id in sorted(cited_ave_ids(document) - published)
            if ave_id.startswith("AVE-") and len(ave_id) == len("AVE-0000-00000")]


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    published = known_ave_ids()

    paths = sorted(CROSSWALKS_DIR.glob("*.json"))
    if not paths:
        print(f"FAIL: {CROSSWALKS_DIR}/ holds no .json files", file=sys.stderr)
        return 1

    failed = 0
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        problems = (check_schema(document, validator)
                    + check_declared_schema_is_shipped(document)
                    + check_ave_ids_resolve(document, published))
        if problems:
            failed += 1
            print(f"FAIL {path}")
            for problem in problems:
                print(f"  {problem}")
        else:
            print(f"ok   {path}")

    print(f"\n{len(paths) - failed}/{len(paths)} crosswalk(s) valid "
          f"against {SCHEMA_PATH}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
