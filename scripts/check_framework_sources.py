# What: reports which of a record's framework mapping fields (owasp_mcp,
#       owasp_asi, mitre_atlas, nist_ai_rmf) lack a corresponding
#       framework_sources entry recording what version of that framework
#       the mapping was made against. A soft warning by default; --strict
#       makes it a hard failure, intended for gating new record submissions
#       specifically, not the existing corpus.
# Why:  a mapping to an unratified or moving framework is undecidable
#       without this -- OWASP/www-project-mcp-top-10#52 documents two
#       independent projects (and, per crosswalks/ramparts-to-ave.json,
#       AVE and Ramparts specifically) assigning the same MCP category
#       number to unrelated categories, because each read the spec at a
#       different point while it was still moving. The 80 records that
#       predate this field are not retroactively required to carry it --
#       determining what each was actually mapped against is real,
#       per-record judgment and a separate backfill task (issue #245).
#       This check therefore defaults to --only-scoped use gating new
#       submissions; corpus-wide CI enforcement is deliberately deferred
#       until after the backfill, following the volume caution raised on
#       check_confidence_signal.py in #242 (one line to nine on 80
#       records; this field is unset on all 80, so an un-scoped corpus-wide
#       CI step today would immediately be noisier than that).
import argparse
import json
import sys
from pathlib import Path

RECORDS_DIR = Path("records")
FRAMEWORK_FIELDS = ("owasp_mcp", "owasp_asi", "mitre_atlas", "nist_ai_rmf")


def has_real_source(entry: dict) -> bool:
    """True when a framework_sources entry is a real, checkable pin rather
    than an empty or partial placeholder. An unpinnable declaration counts
    only with its read_date (the nearest thing an unversionable source has
    to a pin); anything else needs a version or commit alongside its
    read_date, matching the same pin_status vocabulary already used on
    crosswalk endpoints (schema/crosswalk-1.0.0.schema.json).
    """
    if not entry:
        return False
    if entry.get("pin_status") == "unpinnable":
        return bool(entry.get("read_date"))
    return bool((entry.get("version") or entry.get("commit")) and entry.get("read_date"))


def missing_sources(record: dict) -> list:
    """Framework fields this record carries a real mapping for for which
    framework_sources has no corresponding real entry.
    """
    sources = record.get("framework_sources") or {}
    missing = []
    for field in FRAMEWORK_FIELDS:
        if not record.get(field):
            continue
        if not has_real_source(sources.get(field)):
            missing.append(field)
    return missing


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Report AVE records whose framework mapping fields "
        "(owasp_mcp, owasp_asi, mitre_atlas, nist_ai_rmf) lack a "
        "corresponding framework_sources entry."
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="hard-fail on any checked record missing a framework_sources "
             "entry for a mapping it carries, intended for gating new "
             "record submissions rather than the existing corpus",
    )
    parser.add_argument(
        "--only", metavar="AVE_ID", action="append",
        help="check only the named record(s), e.g. for a new-record PR gate "
             "that shouldn't re-flag the other records",
    )
    args = parser.parse_args(argv)

    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print(f"No records found under {RECORDS_DIR}/", file=sys.stderr)
        return 2

    findings = {}
    for path in paths:
        record = json.loads(path.read_text(encoding="utf-8"))
        rid = record.get("ave_id", path.stem)
        if args.only and rid not in args.only:
            continue
        missing = missing_sources(record)
        if missing:
            findings[rid] = missing

    checked = len(args.only) if args.only else len(paths)
    if findings:
        label = "FAIL" if args.strict else "WARNING"
        detail = "; ".join(f"{rid} ({', '.join(fields)})" for rid, fields in findings.items())
        print(f"{label}: {len(findings)} of {checked} record(s) carry a framework "
              f"mapping with no corresponding framework_sources entry: {detail}")
        return 1 if args.strict else 0
    print(f"All {checked} checked record(s) have framework_sources coverage for "
          f"every framework mapping they carry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
