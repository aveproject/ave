# What: soft-warns on records where mutation_count is 1 or higher but
#       aivss.notes contains no discoverable mention of the ThM
#       decision made when that mutation was recorded. Does not verify
#       correctness, a script can't judge whether a cited source is
#       genuinely a PoC versus theoretical, only that a real,
#       in-record explanation exists for a human reviewer to check.
# Why:  when a record's mutation_count rises, the ThM decision (raised
#       or unchanged) belongs where a reader of the record JSON can see
#       it, not only in a commit message. This check introduces that
#       expectation; no earlier written requirement existed. It looks
#       for the explanation inside the record itself, where a reviewer
#       or a future contributor can actually see it.
import argparse
import json
import sys
from pathlib import Path

RECORDS_DIR = Path("records")
THM_KEYWORDS = ("thm", "mutation", "variant", "evidence tier", "poc")


def has_thm_trail(record: dict) -> bool:
    """True when a record with mutation_count >= 1 has some discoverable
    mention of the ThM/mutation reasoning in its own aivss.notes field.
    A keyword match, not a correctness check, surfaces the case for a
    human reviewer rather than passing judgment on the content itself.
    """
    mutation_count = record.get("mutation_count", 0)
    if not isinstance(mutation_count, int) or mutation_count < 1:
        return True  # nothing to check, no mutation recorded
    notes = (record.get("aivss", {}).get("notes") or "").lower()
    return any(k in notes for k in THM_KEYWORDS)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Soft-warn on records with mutation_count >= 1 that have "
        "no discoverable ThM-decision trail in their own aivss.notes field."
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="hard-fail instead of warning, intended for gating new or "
             "edited records specifically, not the existing corpus",
    )
    parser.add_argument(
        "--only", metavar="AVE_ID", action="append",
        help="check only the named record(s)",
    )
    args = parser.parse_args(argv)

    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print(f"No records found under {RECORDS_DIR}/", file=sys.stderr)
        return 2

    missing = []
    for path in paths:
        record = json.loads(path.read_text(encoding="utf-8"))
        rid = record.get("ave_id", path.stem)
        if args.only and rid not in args.only:
            continue
        if not has_thm_trail(record):
            missing.append(rid)

    checked = len(args.only) if args.only else len(paths)
    if missing:
        label = "FAIL" if args.strict else "WARNING"
        print(f"{label}: {len(missing)} of {checked} record(s) have "
              f"mutation_count >= 1 with no ThM-decision trail in "
              f"aivss.notes: {', '.join(missing)}")
        return 1 if args.strict else 0
    print(f"All {checked} checked record(s) with recorded mutations carry a ThM trail.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
