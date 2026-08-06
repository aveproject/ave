# What: validates every AVE record against the current schema plus the Section 8
#       invariants from the v1.1.0 migration (no stale field names, no leaked
#       enforcement config, no dual-empty behavioral_vector/example_patterns),
#       plus AIVSS score arithmetic and vendor-neutral language, added after a
#       hand-drafted batch of records caught real instances of exactly these
#       problems that nothing here checked
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
#       implies but which deserve a readable, named failure message of their own
import json
import re
import sys
from pathlib import Path

import jsonschema

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
        )
        for e in errors:
            print(f"{rid}: {e}")
        total_errors += len(errors)

    if total_errors:
        print(f"\n{total_errors} error(s) across {len(paths)} records.", file=sys.stderr)
        return 1
    print(f"All {len(paths)} records valid against {SCHEMA_PATH}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
