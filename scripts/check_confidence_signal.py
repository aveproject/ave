# What: consumer-side confidence signal check for AVE records. Reads every
#       record in records/ and, for each one whose self-reported
#       confidence_baseline sits in the high band, reports which weakness the
#       number is resting on. There are two, they are independent, and a record
#       may carry both, one or neither:
#         - a vantage floor -- the observation was made from a place the
#           observed artifact controls. Remedied by observing from a better
#           place.
#         - an independence floor -- the evidence rests on a single source.
#           Remedied by adding a second source.
#       This is the shape issue #98 names: "a float the record's author assigns
#       ... the same shape whether the underlying evidence is a formally
#       disclosed CVE or a speculative pattern match."
# Why:  confidence_baseline is self-reported today; nothing external verifies
#       it. A compliance team building workflows on AVE-classified findings
#       (the r/ai_governance angle in #98) needs to know which records'
#       confidence they can act on, and -- this is the part a single warning
#       could not tell them -- what would fix a record that they cannot.
#
#       This check predates verification_basis. It floored on engine-set
#       cardinality because when it was written no measure of vantage existed,
#       so "one engine" was the available proxy for "weak evidence". One exists
#       now, and running both predicates over the same field shows the proxy
#       was never approximating vantage at all. Four combinations, each with
#       evidence_vantage=substrate, evidence_method=intercepted and
#       confidence_baseline=0.9:
#
#         engines                          cardinality   derived basis
#         two, neither substrate-capable   silent        artifact_intercepted
#         one, substrate-capable           fires         substrate_intercepted
#         one, not substrate-capable       fires         artifact_intercepted
#         two, one substrate-capable       silent        substrate_intercepted
#
#       The first row is a record with a floor-level basis that the check let
#       through; the second is a record with the strongest basis available that
#       the check flagged. Neither predicate subsumes the other because they
#       measure different properties: cardinality measures CORROBORATION, how
#       many independent sources agreed, and the derivation measures VANTAGE,
#       where the observation was made from. A record can fail either without
#       failing the other, and the two are fixed by different work.
#
#       So neither retiring cardinality for the derivation nor OR-ing the two
#       together is the fix. The first drops the corroboration signal, which is
#       real. The second reports both faults under one string, which leaves a
#       consumer knowing a record is weak and not knowing which weakness it has
#       or what would clear it. This project names the thing that is wrong
#       rather than the bucket it falls in -- the same discipline
#       check_vulnerability_taxonomy.py applies to security_boundary and
#       missing_control -- so the check reports two findings and says which.
# How:  high band = confidence_baseline >= HIGH_CONFIDENCE (0.85, matching the
#       schema's "high-signal" band), tested once, in confidence_signals(),
#       because both findings are about a high number and neither is a finding
#       without one.
#
#       The vantage arm asks scripts/write_verification_basis.py for the
#       derived vantage rather than recomputing it. That import is the point:
#       a second predicate over the same field is precisely the defect this
#       split repairs, and validate_records.py already hard-fails a declared
#       verification_basis the derivation refutes, so the derivation is this
#       corpus's single answer to "where was this observed from". The check
#       derives even where a record carries a stamped verification_basis: the
#       stamp is what the author typed and the derivation is what the record's
#       axes support, and a consumer-side check reading the author's copy would
#       be reading a self-report, which is the complaint in #98 wearing a
#       better field name. Note that a record declaring no vantage derives the
#       floor -- silence is never credited as a claim, per the producer guide --
#       so this arm does fire on records that have simply not said. That is
#       correct and the message says so: stating the floor is free, and stating
#       it alongside 0.9 is the combination #98 was opened about.
#
#       The independence arm keeps the cardinality test, on the set rather than
#       the list, and now over the legible members only: a duplicated member is
#       one source wearing a list of length two (astrogilda's attack test,
#       2026-08-26) and a malformed member is not a source at all, the same
#       reading write_verification_basis.py gives a malformed engine field.
#       List ordering is normalised by comparing sets, so the check sees 13
#       distinct bases where the files write them 18 ways (issue #98 comment
#       2026-08-20).
#
#       The check is a soft warning: it prints findings and leaves the exit
#       code alone, the same shape as check_researcher_matches_disclosure in
#       validate_records.py. Escalation condition (per the thread): when
#       evidence_basis_engines carries a member for an external-authority
#       query and a re-run fires no vantage finding on any record whose
#       detection_methodology names an authority probe, the field earns its
#       version bump.
import argparse
import json
import sys
from pathlib import Path

# CI runs this file as `python scripts/check_confidence_signal.py`, which puts
# scripts/ on sys.path rather than the repository root, so the sibling module
# has to be reachable by the same name the tests import it under (pyproject
# sets pythonpath = ["."] for pytest). Adding the root explicitly makes both
# entry points resolve one module rather than each resolving a different one --
# the same fix validate_records.py already carries for the same import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.write_verification_basis import (  # noqa: E402
    FLOOR_VANTAGE,
    derive,
    derived_vantage,
    engine_vantage,
)

RECORDS_DIR = Path("records")

HIGH_CONFIDENCE = 0.85
FLOOR_KIND = "semantic_inference"

# The two findings, as the names a consumer branches on. They are separate
# because their remedies are separate: one is fixed by observing from somewhere
# else, the other by observing a second time from somewhere independent.
VANTAGE_FLOOR = "vantage_floor"
INDEPENDENCE_FLOOR = "independence_floor"

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


def names_authority_probe(record: dict) -> bool:
    """True when the record's own detection methodology says the finding came
    from querying an external authority, i.e. the floor is an enum gap."""
    methodology = (record.get("detection_methodology") or "").lower()
    return any(h in methodology for h in AUTHORITY_PROBE_HINTS)


def authority_probe_note(record: dict) -> str:
    """The exculpatory sentence for a record whose own methodology says an
    outside party was asked and answered, or "" for every other record.

    It belongs to the vantage finding alone. What it explains is why a record
    that did observe from outside the artifact still derives the artifact rung,
    and that is a statement about vantage vocabulary; the same record's
    independence finding, if it has one, is true on its own terms and is
    cleared by the same edit anyway, since adding the missing member also adds
    a second source.

    Two shapes, because the enum gap it was written for has since been closed
    for records that adopt the member. A record whose engine set still cannot
    reach substrate is the original case. A record whose set can, and which
    still derives the floor, is held there by its own silence rather than by
    the vocabulary, and telling it to add a member it already carries would
    send an author looking for a bug that is not there.
    """
    if not names_authority_probe(record):
        return ""
    if engine_vantage(record) == "substrate":
        return (
            " NOTE: this record's detection_methodology names an external-authority "
            "probe (registry/RDAP/API) and its evidence_basis_engines already carries "
            "a member that reaches substrate, so the vocabulary is not what holds this "
            "at the floor: the record has not declared evidence_vantage. Declaring it "
            "clears this finding."
        )
    return (
        " NOTE: this record's detection_methodology names an external-authority "
        "probe (registry/RDAP/API); the floor here is an enum gap, not an "
        "overclaim. Expected to clear when evidence_basis_engines carries an "
        "external-authority member."
    )


def vantage_floor_signal(record: dict, confidence: float):
    """The finding for a record whose evidence was obtained from a place the
    observed artifact controls, else None.

    Two things put a record here and both are reported, because an author
    fixing one wants to know the other is also holding it down. The derived
    vantage is the composed answer write_verification_basis.py publishes, so
    this arm and the corpus's own verification_basis can never disagree.
    evidence_kind_default of semantic_inference joins it rather than forming a
    finding of its own: an inference over meaning is a reading of content the
    artifact produced however good the reading, which is the same rung and the
    same remedy, and the arms here are divided by remedy.
    """
    causes = []
    remedies = []
    if derived_vantage(record) == FLOOR_VANTAGE:
        causes.append(f"derived verification_basis is {derive(record)}")
        remedies.append(
            "observe from somewhere the artifact can neither forge nor suppress -- a "
            "sandbox watching execution from outside it, or an external authority "
            "answering about it -- and state that on evidence_vantage"
        )
    if (record.get("evidence_kind_default") or "") == FLOOR_KIND:
        causes.append(f"evidence_kind_default is {FLOOR_KIND}")
        remedies.append(
            "ground the determination in something observed rather than inferred, and "
            "stamp the evidence_kind that names it"
        )
    if not causes:
        return None
    return (
        f"confidence_baseline {confidence} sits at the high band while the evidence "
        f"sits at the vantage floor: {'; '.join(causes)}. Remedy: "
        f"{'; '.join(remedies)}. Declared confidence without structural verification "
        f"-- see issue #98.{authority_probe_note(record)}"
    )


def independence_floor_signal(record: dict, confidence: float):
    """The finding for a record whose evidence rests on a single source, else
    None.

    Cardinality is the honest measure of corroboration and nothing else: how
    many independent sources had to agree before the class was called. It says
    nothing about where any of them observed from, which is why it is a finding
    of its own rather than a proxy for the vantage one.

    Counted over the set, and over the legible members of it. A duplicated
    member is one source wearing a list of length two (astrogilda's attack
    test, 2026-08-26), and a member that is not a string is not a source --
    the same reading write_verification_basis.py gives a malformed engine
    field, where a typo must not be allowed to raise what a record is credited
    with.
    """
    members = sorted({e for e in (record.get("evidence_basis_engines") or []) if isinstance(e, str)})
    if len(members) > 1:
        return None
    rests_on = (
        f"evidence_basis_engines names a single source ([{', '.join(members)}])"
        if members
        else "evidence_basis_engines names no legible source at all"
    )
    return (
        f"confidence_baseline {confidence} sits at the high band while {rests_on}. "
        f"Remedy: corroborate with a second, independent engine; a repeated member is "
        f"one source wearing a list of length two, and a malformed one is not a source. "
        f"Declared confidence without corroboration -- see issue #98."
    )


def confidence_signals(record: dict) -> list[dict]:
    """Every finding this record's declared confidence carries, in order, as
    {"finding": <name>, "signal": <prose>} pairs. Empty for a record whose
    confidence is absent, below the high band, or fully supported.

    A pair rather than a string because the two findings have different
    remedies, and a consumer that has to parse prose to tell them apart cannot
    route them. The names are the stable half; the prose is for a human.
    """
    confidence = record.get("confidence_baseline")
    if confidence is None:
        return []  # absent confidence is a separate concern, not this check
    if confidence < HIGH_CONFIDENCE:
        return []
    findings = []
    for name, arm in (
        (VANTAGE_FLOOR, vantage_floor_signal),
        (INDEPENDENCE_FLOOR, independence_floor_signal),
    ):
        signal = arm(record, confidence)
        if signal:
            findings.append({"finding": name, "signal": signal})
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Report AVE records whose self-reported confidence_baseline "
        "sits high while their evidence sits at the vantage floor, the "
        "independence floor, or both (issue #98)."
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
    flagged = set()
    for path in paths:
        record = json.loads(path.read_text())
        rid = record.get("ave_id", path.stem)
        for finding in confidence_signals(record):
            findings.append({"ave_id": rid, **finding})
            flagged.add(rid)

    if args.as_json:
        # count is findings and records is the records they fall on; a record
        # carrying both findings contributes two to one and one to the other,
        # so a consumer reading either number alone still reads it correctly.
        print(json.dumps(
            {"findings": findings, "count": len(findings), "records": len(flagged)},
            indent=2,
        ))
    else:
        if findings:
            print(f"{len(findings)} finding(s) across {len(flagged)} of {len(paths)} "
                  f"record(s) with high confidence on unsupported evidence (soft warning):")
            for f in findings:
                print(f"- {f['ave_id']} [{f['finding']}]: {f['signal']}")
        else:
            print(f"All {len(paths)} records have confidence consistent with their basis.")

    return 0  # soft warning: exit code untouched, same as check_researcher_matches_disclosure


if __name__ == "__main__":
    sys.exit(main())
