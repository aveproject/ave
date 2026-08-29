# What: consumer-side confidence signal check for AVE records. Reads every
#       record in records/ and reports the ones whose self-reported
#       confidence_baseline sits at the high band while their derived
#       evidence basis sits at the floor, the exact shape issue #98 names:
#       "a float the record's author assigns ... the same shape whether the
#       underlying evidence is a formally disclosed CVE or a speculative
#       pattern match."
# Why:  confidence_baseline is self-reported today; nothing external verifies
#       it. A compliance team building workflows on AVE-classified findings
#       (the r/ai_governance angle in #98) needs to know which records'
#       confidence they can act on and which are declarations resting on
#       pattern-level inference alone. This check makes that distinction
#       computable without a schema change: it reads fields that already
#       exist on every record.
# How:  high = confidence_baseline >= HIGH_CONFIDENCE (0.85, matching the
#       schema's "high-signal" band). Floor = the evidence basis carries a
#       single engine member (regardless of which) or evidence_kind_default
#       is semantic_inference. A record in both sets is a "declared, not
#       structurally verified" signal. List ordering is normalized by
#       comparing engine sets, so the check sees 13 distinct bases where the
#       files write them 18 ways (issue #98 comment 2026-08-20). The check
#       is a soft warning: it prints findings and leaves the exit code
#       alone, the same shape as check_researcher_matches_disclosure in
#       validate_records.py. Escalation condition (per the thread): when
#       evidence_basis_engines carries a member for an external-authority
#       query and a re-run fires zero times on any record whose
#       detection_methodology names an authority probe, the field earns its
#       version bump.
import argparse
import json
import sys
from pathlib import Path

RECORDS_DIR = Path("records")

HIGH_CONFIDENCE = 0.85
FLOOR_KIND = "semantic_inference"

# Substrings in a record's detection_methodology that identify an
# external-authority probe: the case where the floor is an enum gap, not an
# overclaim (AVE-2026-00074). Deliberately specific terms only: bare
# "registry" or "domain" match ordinary static-scan prose (astrogilda's
# attack test, 2026-08-26) and a false attach is worse than a false flag.
AUTHORITY_PROBE_HINTS = (
    "api.github.com",
    "rdap",
    "github's users api",
    "package registry",
    "authoritative source",
    "provider fingerprint",
)


def is_floor_basis(record: dict) -> bool:
    """True when the record's evidence basis is at the floor: a single-engine
    set (regardless of which) or semantic_inference as the kind.

    The cardinality test is on the set, not the list: a duplicated member
    (["pattern", "pattern"], ["pattern", "PATTERN"]) is a single-engine
    basis wearing a list of length two, and must not dodge the floor
    (astrogilda's attack test, 2026-08-26).
    """
    engines = record.get("evidence_basis_engines") or []
    kind = record.get("evidence_kind_default") or ""
    if len(set(engines)) <= 1:
        return True
    return kind == FLOOR_KIND


def names_authority_probe(record: dict) -> bool:
    """True when the record's own detection methodology says the finding came
    from querying an external authority, i.e. the floor is an enum gap."""
    methodology = (record.get("detection_methodology") or "").lower()
    return any(h in methodology for h in AUTHORITY_PROBE_HINTS)


def confidence_signal(record: dict):
    """Return a human-readable signal string for a record whose declared
    confidence sits high while its basis sits at the floor, else None."""
    cb = record.get("confidence_baseline")
    if cb is None:
        return None  # absent confidence is a separate concern, not this check
    if cb < HIGH_CONFIDENCE or not is_floor_basis(record):
        return None
    engines = ", ".join(sorted(set(record.get("evidence_basis_engines") or [])))
    kind = record.get("evidence_kind_default") or "(none)"
    note = ""
    if names_authority_probe(record):
        note = (
            " NOTE: this record's detection_methodology names an external-authority "
            "probe (registry/RDAP/API); the floor here is an enum gap, not an "
            "overclaim. Expected to clear when evidence_basis_engines carries an "
            "external-authority member."
        )
    return (
        f"confidence_baseline {cb} sits at the high band while the derived basis "
        f"is at the floor (engines=[{engines}], evidence_kind_default={kind}). "
        f"Declared confidence without structural verification -- see issue #98."
        f"{note}"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Report AVE records whose self-reported confidence_baseline "
        "sits high while their derived evidence basis sits at the floor (issue #98)."
    )
    parser.add_argument(
        "--json", dest="as_json", action="store_true",
        help="emit findings as JSON for downstream tooling",
    )
    args = parser.parse_args(argv)

    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print(f"No records found under {RECORDS_DIR}/", file=sys.stderr)
        return 2

    findings = []
    for path in paths:
        record = json.loads(path.read_text())
        signal = confidence_signal(record)
        if signal:
            findings.append({"ave_id": record.get("ave_id", path.stem), "signal": signal})

    if args.as_json:
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    else:
        if findings:
            print(f"{len(findings)} record(s) with high confidence on a floor-level basis (soft warning):")
            for f in findings:
                print(f"- {f['ave_id']}: {f['signal']}")
        else:
            print(f"All {len(paths)} records have confidence consistent with their basis.")

    return 0  # soft warning: exit code untouched, same as check_researcher_matches_disclosure


if __name__ == "__main__":
    sys.exit(main())
