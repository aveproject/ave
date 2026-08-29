# What: validates every AVE record against the current schema plus the Section 8
#       invariants from the v1.1.0 migration (no stale field names, no leaked
#       enforcement config, no dual-empty behavioral_vector/example_patterns),
#       plus AIVSS score arithmetic and vendor-neutral language, added after a
#       hand-drafted batch of records caught real instances of exactly these
#       problems that nothing here checked, plus a declared verification_basis
#       that the record's own evidence axes contradict
# Why:  a malformed or drifted record breaks every downstream scanner that loads it,
#       and a free-text value in `mitigation` would let vendor-specific config
#       leak back into a standard that is supposed to stay vendor-neutral.
#       A stated aivss_score that doesn't match the record's own aarf/cvss_base/
#       thm/mitigation_factor is silently wrong severity data shipped to every
#       consumer of the corpus. A stray vendor product name is a neutrality
#       violation this project enforces everywhere else; records shouldn't be
#       the one place it's unchecked.
# How:  jsonschema.Draft202012Validator with format checking enabled against
#       schema/ave-record-1.1.0.schema.json (handles the draft-vs-active
#       conditional required set natively and enforces date-time / uri metadata),
#       plus a handful of checks the schema's additionalProperties:false already
#       implies but which deserve a readable, named failure message of their own.
#       verification_basis is a hard error rather than a warning because it is
#       derived rather than authored: a value disagreeing with the derivation is
#       not a judgement call needing a human glance, it is a statement the
#       record's own contents refute, and the whole point of carrying the field
#       is that the declaration can be falsified.
import json
import re
import sys
from pathlib import Path

import jsonschema

# CI runs this file as `python scripts/validate_records.py`, which puts scripts/
# on sys.path rather than the repository root, so the sibling module has to be
# reachable by the same name the tests import it under (pyproject sets
# pythonpath = ["."] for pytest). Adding the root explicitly makes both entry
# points resolve one module rather than each resolving a different one.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.write_verification_basis import check_record as check_verification_basis  # noqa: E402

RECORDS_DIR = Path("records")
SCHEMA_PATH = Path("schema/ave-record-1.1.0.schema.json")

OLD_FIELD_NAMES = ["owasp_mapping", "mitre_atlas_mapping", "nist_ai_rmf_mapping"]
MITIGATION_ENUMS = {
    "strategy": {
        "deny_by_default", "require_human_approval", "pin_integrity", "isolate_scope",
        "validate_input", "sanitize_output", "verify_identity", "sever_egress",
        "least_privilege", "provenance_label",
    },
    "enforcement_point": {
        "static_scan", "server_card_fetch", "runtime_proxy", "agent_framework",
        "downstream_system", "network_layer",
    },
    "trifecta_control": {
        "break_private_data", "break_untrusted_content", "break_external_comms", "not_applicable",
    },
}

VENDOR_BOILERPLATE_PATTERNS = [
    r"bawbel-scanner",
    r"bawbel-gate",
    r"bawbel\s+scan\b",
    r"piranha",
]


def check_schema(record: dict, validator: jsonschema.Draft202012Validator) -> list[str]:
    return [f"schema: {e.message} (at {'/'.join(str(p) for p in e.path) or '<root>'})"
            for e in validator.iter_errors(record)]


def build_validator(schema: dict) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )


def check_no_old_field_names(record: dict) -> list[str]:
    return [f"stale field name '{f}' still present (renamed in v1.1.0)"
            for f in OLD_FIELD_NAMES if f in record]


def check_no_nested_owasp_mcp_mapping(record: dict) -> list[str]:
    if "owasp_mcp_mapping" in record.get("aivss", {}):
        return ["aivss.owasp_mcp_mapping is present; it was removed in v1.1.0, top-level owasp_mcp is authoritative"]
    return []


def check_behavioral_vector_or_example_patterns(record: dict) -> list[str]:
    bv = record.get("behavioral_vector") or []
    ep = record.get("example_patterns") or []
    if not bv and not ep:
        return ["both behavioral_vector and example_patterns are empty"]
    return []


def check_mitigation_enums_only(record: dict) -> list[str]:
    mitigation = record.get("mitigation")
    if not isinstance(mitigation, dict):
        return []
    errors = []
    for field, allowed in MITIGATION_ENUMS.items():
        value = mitigation.get(field)
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        for v in values:
            if v not in allowed:
                errors.append(f"mitigation.{field} value '{v}' is not a recognized vendor-neutral enum")
    return errors


def check_aivss_arithmetic(record: dict) -> list[str]:
    """Recomputes aars and aivss_score from the record's own aarf, cvss_base,
    thm, and mitigation_factor fields, and confirms both the nested
    aivss.aivss_score and the top-level aivss_score field agree with it.
    A record that drifts here is shipping a severity number nobody
    actually derived from its own stated inputs."""
    aivss = record.get("aivss")
    if not isinstance(aivss, dict):
        return []
    aarf = aivss.get("aarf")
    if not isinstance(aarf, dict) or not aarf:
        return []

    errors = []
    aars = round(sum(aarf.values()), 4)
    stated_aars = aivss.get("aars")
    if aars != stated_aars:
        errors.append(f"aivss.aars mismatch: computed {aars}, record states {stated_aars}")

    required = ("cvss_base", "thm", "mitigation_factor")
    missing = [f for f in required if f not in aivss]
    if missing:
        errors.append(f"aivss missing scoring field(s): {', '.join(missing)}")
        return errors

    computed_score = round(((aivss["cvss_base"] + aars) / 2) * aivss["thm"] * aivss["mitigation_factor"], 1)
    stated_score = aivss.get("aivss_score")
    if computed_score != stated_score:
        errors.append(f"aivss.aivss_score mismatch: computed {computed_score}, record states {stated_score}")

    top_level_score = record.get("aivss_score")
    if top_level_score != stated_score:
        errors.append(f"top-level aivss_score ({top_level_score}) does not match aivss.aivss_score ({stated_score})")

    return errors


def check_no_vendor_boilerplate(raw_text: str) -> list[str]:
    lower = raw_text.lower()
    return [f"vendor-specific reference found: '{pattern}'"
            for pattern in VENDOR_BOILERPLATE_PATTERNS if re.search(pattern, lower)]


# Names that are AVE's own maintainers/cataloguers, not external
# researchers. Kept as a real, explicit list, not a heuristic guess.
INTERNAL_RESEARCHER_NAMES = {"saray chak", "bawbel security research team"}

# Words in a reference's own tag/text that signal it IS the primary
# external disclosure this record is based on, not just supporting
# context or a detection-implementation link.
DISCLOSURE_SIGNAL_WORDS = [
    "disclosure", "advisory", "cve", "vulnerability report",
    "responsible disclosure", "security research", "paper",
]


def check_researcher_matches_disclosure(record: dict) -> list[str]:
    """Soft warning only: flags records where `researcher` is an AVE
    maintainer name while `references` contains something that reads
    like the actual external disclosure this record is based on.
    Not a hard failure, some records are genuinely original AVE
    cataloguing with no single external discloser, this needs a human
    glance, not an auto-block. Caught the real AVE-2026-00060 /
    repo-forensics-sourced misattribution mistakes; see
    docs/specs/researcher-process.md for the full incident this check
    exists because of.
    """
    researcher = (record.get("researcher") or "").strip().lower()
    if researcher not in INTERNAL_RESEARCHER_NAMES:
        return []

    refs = record.get("references", [])
    for ref in refs:
        tag = (ref.get("tag") or "").lower()
        text = (ref.get("text") or "").lower()
        combined = tag + " " + text
        if any(word in combined for word in DISCLOSURE_SIGNAL_WORDS):
            return [
                f"researcher is '{record.get('researcher')}' (an AVE maintainer name), "
                f"but references includes an entry that reads as the primary external "
                f"disclosure ('{ref.get('tag', ref.get('text', ''))}'). Confirm this is "
                f"genuinely original AVE cataloguing, not a misattributed external source."
            ]
    return []


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = build_validator(schema)

    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print("No records found under records/", file=sys.stderr)
        return 1

    total_errors = 0
    for path in paths:
        raw_text = path.read_text()
        record = json.loads(raw_text)
        rid = record.get("ave_id", path.name)
        errors = (
            check_schema(record, validator)
            + check_no_old_field_names(record)
            + check_no_nested_owasp_mcp_mapping(record)
            + check_behavioral_vector_or_example_patterns(record)
            + check_mitigation_enums_only(record)
            + check_aivss_arithmetic(record)
            + check_no_vendor_boilerplate(raw_text)
            + check_verification_basis(record)
        )
        for e in errors:
            print(f"{rid}: {e}")
        total_errors += len(errors)

        warnings = check_researcher_matches_disclosure(record)
        if warnings:
            for w in warnings:
                print(f"WARNING [{record['ave_id']}]: {w}")
            # do not increment the failure counter, do not affect exit code

    if total_errors:
        print(f"\n{total_errors} error(s) across {len(paths)} records.", file=sys.stderr)
        return 1
    print(f"All {len(paths)} records valid against {SCHEMA_PATH}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
