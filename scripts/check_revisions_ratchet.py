# What: compares every record a change adds or edits with its version at the merge base,
#       and fails when
#         1. the base version's revisions are not an exact prefix of the head version's
#            (an entry edited, reordered or removed, or the array dropped), or
#         2. severity, status or the derived verification_basis differs between the two and
#            the head has no new revisions entry that explains the change.
# Why:  validate_records.py reads one record at a time, so it cannot see an earlier entry
#       edited or deleted, or the array removed, and revisions is optional, so a record
#       that changed a value consumers gate on can carry no entry at all. AVE-2026-00044
#       went from MEDIUM to HIGH in #294 and AVE-2026-00074's derived verification_basis
#       moved in #299, each with only last_updated to show it (issue #382, design in #317).
#       Both gaps need the base version of the record, which only git has.
# How:  the records the change touches come from `git diff base...head` (three dots) and
#       each is read at the merge base and at head, both as committed, so commits that
#       landed on the base branch afterwards are not counted as the change's own, the same
#       shape as check_confidence_signal.py --ratchet-since and tests/test_frozen_artifacts.py.
#       The derived verification_basis is computed with write_verification_basis.derive for
#       both versions, never read from the stored field alone. An explanation is the new
#       entries (those after the base's own) for the field, forming an unbroken from/to chain
#       from the base value to the head value. For the derived basis two shapes count: an
#       entry on verification_basis itself, which vocabulary_member_added and
#       derivation_rule_changed need because no declaration changed, or an entry for each
#       declaration that changed (evidence_vantage, evidence_method, evidence_basis_engines),
#       which is how AVE-2026-00074 recorded its own. A new record, and one that was still a
#       draft at the base, has nothing consumers could have gated on and is exempt from rule 2.
#       Exit status: 0 clean, 1 a rule failed, 2 the change could not be read.
import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.write_verification_basis import derive  # noqa: E402

RECORDS_DIR = Path("records")

# The three values consumers gate on. severity and status are stored; the third is the
# verification_basis derived from the declarations in DERIVATION_INPUTS.
STORED_GATES = ("severity", "status")
DERIVATION_INPUTS = ("evidence_vantage", "evidence_method", "evidence_basis_engines")


# What: runs one git command and returns its stdout
# Why:  a ratchet that cannot read the change must say so, not report the change clean
# How:  subprocess in the current directory, RuntimeError carrying git's own message on failure
def git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {args[0]} exited {result.returncode}")
    return result.stdout


# What: the merge base and the records head adds or edits since it, as (status, base path, head path)
# Why:  the three-dot form counts only the change's own commits; against the moved tip of the
#       base branch, a branch would be blamed for everything that landed there after it forked
# How:  git merge-base, then git diff --name-status -M over records/, keeping added, modified
#       and renamed AVE-*.json files (a deleted record is the deletion policy's to refuse)
def changed_records(base: str, head: str) -> tuple[str, list[tuple[str, str, str]]]:
    merge_base = git("merge-base", base, head).strip()
    listing = git("diff", "--name-status", "-M", "--diff-filter=AMR", f"{base}...{head}", "--", str(RECORDS_DIR))
    changes = []
    for line in listing.splitlines():
        status, *paths = line.split("\t")
        old, new = paths[0], paths[-1]
        if Path(new).name.startswith("AVE-") and new.endswith(".json"):
            changes.append((status[0], old, new))
    return merge_base, sorted(changes, key=lambda change: change[2])


# What: one record as committed at a commit
# Why:  both versions are read from git objects so the check judges what is committed, not
#       whatever is in the working tree
# How:  git show <commit>:<path>, parsed as JSON; unreadable or invalid is a RuntimeError
def read_record(commit: str, path: str) -> dict:
    raw = git("show", f"{commit}:{path}")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"{path} at {commit[:12]} is not valid JSON: {err}") from err
    if not isinstance(record, dict):
        raise RuntimeError(f"{path} at {commit[:12]} is not a JSON object")
    return record


# What: whether entries hold an unbroken from/to chain for a field, from old to new
# Why:  several changes can land together (a promotion carries many pull requests), each
#       with its own entry, so the net change is explained by the chain, not by one entry
# How:  the entries naming the field, in order: the first's from is old, each from is the
#       previous to, and the last to is new
def chain_explains(entries: list, field: str, old, new) -> bool:
    chain = [e for e in entries if isinstance(e, dict) and e.get("field") == field]
    if not chain or chain[0].get("from") != old:
        return False
    if any(a.get("to") != b.get("from") for a, b in zip(chain, chain[1:])):
        return False
    return chain[-1].get("to") == new


# What: rule 1, the problems with how the head's revisions treat the base's
# Why:  an entry that can be edited or removed is not a history
# How:  the base's entries must equal the head's first entries, compared as parsed JSON so
#       reformatting is not an edit
def append_only_problems(label: str, base: dict, head: dict) -> list[str]:
    if "revisions" not in base:
        return []
    if "revisions" not in head:
        return [f"{label}: the revisions array was removed; revisions are append-only"]
    old, new = base["revisions"], head["revisions"]
    problems = [f"{label}: revisions[{i}] was edited; revisions are append-only"
                for i in range(min(len(old), len(new))) if old[i] != new[i]]
    if len(new) < len(old):
        gone = len(old) - len(new)
        problems.append(f"{label}: {gone} earlier revisions {'entry was' if gone == 1 else 'entries were'} removed; "
                        "revisions are append-only")
    return problems


# What: rule 2, the problems with a change to severity, status or the derived verification_basis
# Why:  these are the values a consumer gates on; a change to one that the record does not
#       itself state is the silent change #317 describes
# How:  for each value that differs between base and head, the head's new entries (those after
#       the base's own) must explain it; see the header for the two shapes the derived basis allows
def explanation_problems(label: str, base: dict, head: dict) -> list[str]:
    new_entries = (head.get("revisions") or [])[len(base.get("revisions") or []):]
    problems = []
    for field in STORED_GATES:
        old, new = base.get(field), head.get(field)
        if old != new and not chain_explains(new_entries, field, old, new):
            problems.append(
                f"{label}: {field} changed from {old!r} to {new!r} with no revisions entry for it: "
                f"append {{field: {field}, from: {old!r}, to: {new!r}, reason_code, date}}"
            )
    old, new = derive(base), derive(head)
    if old != new:
        stored = base.get("verification_basis")
        by_basis = any(chain_explains(new_entries, "verification_basis", start, new) for start in (old, stored))
        changed = [f for f in DERIVATION_INPUTS if base.get(f) != head.get(f)]
        missing = [f for f in changed if not chain_explains(new_entries, f, base.get(f), head.get(f))]
        if not by_basis and (missing or not changed):
            wanted = (f"one for each declaration that changed ({', '.join(missing)})" if missing
                      else "one for the declaration that changed")
            problems.append(
                f"{label}: the derived verification_basis changed from {old!r} to {new!r} with no "
                f"revisions entry for it: append an entry for verification_basis itself "
                f"(from {old!r} or the stored value {stored!r}, to {new!r}), or {wanted}"
            )
    return problems


# What: every problem one record's change has
# Why:  main() and the tests both call this, so a rule dropped from the pipeline fails a test
# How:  rule 1 when a base version exists; rule 2 unless the record is new or was a draft at
#       the base, since nothing consumers could have gated on existed yet
def record_problems(base: dict | None, head: dict, label: str | None = None) -> list[str]:
    label = label or head.get("ave_id", "<unknown id>")
    if base is None:
        return []
    problems = append_only_problems(label, base, head)
    if base.get("status") != "draft":
        problems += explanation_problems(label, base, head)
    return problems


# What: how many records changed since base, and every problem they have
# Why:  one entry point for the command line and the tests
# How:  changed_records, then each record at the merge base (absent when added) and at head
def inspect(base: str, head: str = "HEAD") -> tuple[int, list[str]]:
    merge_base, changes = changed_records(base, head)
    problems = []
    for status, old_path, new_path in changes:
        before = None if status == "A" else read_record(merge_base, old_path)
        after = read_record(head, new_path)
        problems += record_problems(before, after, after.get("ave_id", Path(new_path).stem))
    return len(changes), problems


def check(base: str, head: str = "HEAD") -> list[str]:
    return inspect(base, head)[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a record's revisions are edited or removed since BASE, or when "
        "severity, status or the derived verification_basis changed without a revisions entry "
        "(issue #382)."
    )
    parser.add_argument("--ratchet-since", metavar="REF", required=True,
                        help="the base branch or commit; records are compared with their version at its merge base with HEAD")
    parser.add_argument("--head", metavar="REF", default="HEAD",
                        help="the commit holding the change (default HEAD); a past commit lets the check be run on history")
    args = parser.parse_args(argv)
    try:
        checked, problems = inspect(args.ratchet_since, args.head)
    except RuntimeError as err:
        print(f"ERROR: could not list the records changed since {args.ratchet_since}, so none "
              f"was checked: {err}", file=sys.stderr)
        return 2
    if problems:
        failing = len({p.split(":")[0] for p in problems})
        print(f"FAIL: {len(problems)} problem(s) in {failing} of {checked} record(s) changed since "
              f"{args.ratchet_since}:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(f"Ratchet: {checked} record(s) changed since {args.ratchet_since}; revisions are append-only and "
          f"every change to severity, status or the derived verification_basis has its entry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
