# What: derives verification_basis for every record in records/ from the
#       record's own closed axes -- evidence_vantage, evidence_method, and the
#       vantage the evidence_basis_engines set implies -- and either writes the
#       derived value into the records (--write) or reports where a declared
#       value disagrees with it (the default). This is the producer half of
#       issue #98: scripts/check_confidence_signal.py reads what a record says
#       about its own confidence, and this decides what the record is entitled
#       to say.
# Why:  confidence_baseline is a float its author assigns, and a check that
#       reads it is still reading a self-report, only a better organised one.
#       What changes that is a producer stating structurally what it observed
#       rather than what it believed. So verification_basis is computed here and
#       never authored: an author who types one has it checked against this
#       derivation by validate_records.py and fails on a mismatch, which is the
#       same shape as a crosswalk endpoint declaring itself unpinnable while
#       pointing at a repository. A field an author can simply assert would be
#       the field issue #98 was opened about, wearing a better name.
# How:  each axis is a closed vocabulary composed by weakest input, taken from
#       the AEE predicate's basis/method split that this ports. A record's
#       vantage is the weaker of what its author declared and what its engine
#       set can reach: pattern, yara, semgrep, llm and magika all read content
#       the artifact produced, so they reach only `artifact`; sandbox observes
#       execution from outside it and external_authority asks a party outside it
#       entirely, so either reaches `substrate`. Method defaults to the weaker
#       value when absent, so silence is never read as a claim. The engine set
#       is a ceiling and the declaration is the claim, and the derived value is
#       the weaker of the two, which is what makes external_authority
#       load-bearing rather than decorative: before it existed, a record whose
#       finding came from an outside answer had its ceiling pinned at `artifact`
#       by an enum with no member for that rung, so no honest author could reach
#       `substrate` however the evidence was actually obtained. Adding the
#       member does not raise any record on its own -- an author still has to
#       state the vantage -- it makes the true statement available.
import argparse
import json
import sys
from pathlib import Path

RECORDS_DIR = Path("records")

# Engines that can reach a substrate vantage. Everything else in the enum reads
# content the observed artifact itself produced, and so is artifact-sourced
# however trusted the machinery reading it: the artifact could have written what
# the engine read without doing the thing the record claims. sandbox observes
# execution from outside the artifact; external_authority asks a party outside
# it. An engine absent from the enum entirely is not assumed to reach anything.
SUBSTRATE_ENGINES = frozenset({"sandbox", "external_authority"})

VANTAGE_VALUES = ("substrate", "artifact")
METHOD_VALUES = ("intercepted", "reconstructed")

# The weaker value of each axis, and the value a producer may always truthfully
# state. Absence reads as the floor, so a record that says nothing is never
# credited with the stronger claim.
FLOOR_VANTAGE = "artifact"
FLOOR_METHOD = "reconstructed"


def engine_vantage(record: dict) -> str:
    """The strongest vantage this record's engine set can reach.

    Composition is by weakest input everywhere else, but an engine list is a
    disjunction -- these are the engines capable of detecting the class, any one
    of which may be the one that did -- so the set reaches substrate when any
    member does. A non-list value reaches nothing: a malformed field is not
    evidence of a strong vantage, and reading it as one would let a typo raise a
    record's derived basis.
    """
    engines = record.get("evidence_basis_engines")
    if not isinstance(engines, list):
        return FLOOR_VANTAGE
    members = {e for e in engines if isinstance(e, str)}
    return "substrate" if members & SUBSTRATE_ENGINES else FLOOR_VANTAGE


def declared_vantage(record: dict) -> str:
    """What the producer declared, or the floor if it declared nothing legible.

    An unrecognised value is not treated as a new stronger rung. The vocabulary
    is closed; something outside it is a producer saying something this
    derivation cannot read, and the honest reading of that is the floor.
    """
    value = record.get("evidence_vantage")
    return value if value in VANTAGE_VALUES else FLOOR_VANTAGE


def declared_method(record: dict) -> str:
    value = record.get("evidence_method")
    return value if value in METHOD_VALUES else FLOOR_METHOD


def derived_vantage(record: dict) -> str:
    """The vantage this record is entitled to: the weaker of what its producer
    declared and what its engine set can reach.

    Named rather than left inline inside derive() because it is the answer to a
    question consumers ask on its own -- where was this observed from -- and a
    consumer that has to recover it by reading the front half of a composed
    string, or by re-deriving it from SUBSTRATE_ENGINES, is a second definition
    of the same predicate waiting to disagree with this one.
    """
    if engine_vantage(record) != "substrate":
        return FLOOR_VANTAGE
    return declared_vantage(record)


def derive(record: dict) -> str:
    """Compose the two axes into verification_basis, weakest input winning.

    The vantage is the weaker of what the producer declared and what its engines
    can reach, so a producer cannot raise its own basis by asserting a vantage
    its evidence has no way to occupy, and cannot be credited with one it did
    not claim. The result names the cell, not a score: it says where the
    observation was made from and how, and nothing about whether it was right.
    """
    return f"{derived_vantage(record)}_{declared_method(record)}"


def check_record(record: dict) -> list[str]:
    """Report a declared verification_basis that the derivation contradicts.

    Only the disagreement is reported. A record carrying no declaration is not a
    finding here -- the derivation stands on its own and --write will stamp it --
    and a record whose declaration matches has said something true.
    """
    declared = record.get("verification_basis")
    if declared is None:
        return []
    derived = derive(record)
    if declared == derived:
        return []
    return [
        f"verification_basis declares '{declared}' but the record's own axes derive "
        f"'{derived}' (evidence_vantage={record.get('evidence_vantage')!r}, "
        f"evidence_method={record.get('evidence_method')!r}, "
        f"evidence_basis_engines={record.get('evidence_basis_engines')!r}). "
        f"verification_basis is derived, not declared: fix the axes or drop the "
        f"declaration -- see issue #98."
    ]


def serialize(record: dict) -> str:
    return json.dumps(record, indent=2) + "\n"


def is_canonical(raw: str, record: dict) -> bool:
    """Whether the file on disk is byte-identical to this script's own output.

    Checked before writing, because a writer that reserialises is a writer that
    reformats: 73 of the 80 records currently on main differ from json.dumps at
    indent=2 in escaping or whitespace alone, so stamping a one-word field into
    them would produce a diff nobody can review and would hide the real change
    inside it. A record that fails this is refused rather than rewritten, which
    leaves the corpus canonicalisation -- already named as separate work in
    issue #98 -- as its own reviewable change instead of a side effect of this
    one.
    """
    return serialize(record) == raw


def record_paths() -> list[Path]:
    return sorted(RECORDS_DIR.glob("AVE-*.json"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive verification_basis from each record's closed evidence axes "
        "(issue #98). Reports declared values that disagree with the derivation; "
        "--write stamps the derived value into the records."
    )
    parser.add_argument(
        "--write", action="store_true",
        help="write the derived verification_basis into each record",
    )
    args = parser.parse_args(argv)

    paths = record_paths()
    if not paths:
        print(f"No records found under {RECORDS_DIR}/", file=sys.stderr)
        return 1

    mismatches = 0
    written = 0
    refused = 0
    for path in paths:
        raw = path.read_text(encoding="utf-8")
        record = json.loads(raw)
        rid = record.get("ave_id", path.name)

        if args.write:
            if not is_canonical(raw, record):
                print(f"{rid}: refusing to write, the file is not in this script's "
                      f"serialisation and stamping it would reformat the whole record. "
                      f"Canonicalise {path} first.", file=sys.stderr)
                refused += 1
                continue
            derived = derive(record)
            if record.get("verification_basis") != derived:
                record["verification_basis"] = derived
                path.write_text(serialize(record), encoding="utf-8")
                written += 1
                print(f"{rid}: verification_basis = {derived}")
            continue

        for problem in check_record(record):
            print(f"{rid}: {problem}")
            mismatches += 1

    if args.write:
        print(f"\n{written} record(s) updated out of {len(paths)}, "
              f"{refused} refused as non-canonical.")
        return 1 if refused else 0
    if mismatches:
        print(f"\n{mismatches} declared verification_basis value(s) contradicted by "
              f"the record's own axes.", file=sys.stderr)
        return 1
    print(f"All {len(paths)} records agree with their derived verification_basis.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
