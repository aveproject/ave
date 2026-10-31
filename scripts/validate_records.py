# What: validates every AVE record against the schema version it declares, plus the Section 8
#       invariants from the v1.1.0 migration (no stale field names, no leaked
#       enforcement config, no dual-empty behavioral_vector/example_patterns),
#       plus AIVSS score arithmetic and vendor-neutral language, added after a
#       hand-drafted batch of records caught real instances of exactly these
#       problems that nothing here checked, plus a declared verification_basis
#       that the record's own evidence axes contradict, plus the lifecycle rules
#       schema 1.3.0's statuses need beyond the schema (merged_into and
#       rejection_reason only on their own status, a link to the decision, a
#       merge target that exists and is active)
# Why:  a malformed or drifted record breaks every downstream scanner that loads it,
#       and a free-text value in `mitigation` would let vendor-specific config
#       leak back into a standard that is supposed to stay vendor-neutral.
#       A stated aivss_score that doesn't match the record's own aarf/cvss_base/
#       thm/mitigation_factor is silently wrong severity data shipped to every
#       consumer of the corpus. A stray vendor product name is a neutrality
#       violation this project enforces everywhere else; records shouldn't be
#       the one place it's unchecked.
# How:  jsonschema.Draft202012Validator with format checking enabled against
#       schema/ave-record-<schema_version>.schema.json, the file for the version
#       each record states (handles the draft-vs-active conditional required set
#       natively and enforces date-time / uri metadata); a missing or unknown
#       version is an error rather than a silent fallback to the newest schema,
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
SCHEMA_DIR = Path("schema")
# The alias always names the newest schema. Versioned files are looked up per
# record by schema_version; this path is for callers that want "the current one".
SCHEMA_PATH = SCHEMA_DIR / "ave-record.schema.json"
SCHEMA_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")

# The lowest score in each severity band, highest band first: CRITICAL 9.0 and
# above, HIGH 7.0 to 8.9, MEDIUM 4.0 to 6.9, LOW below 4.0 (README.md "AIVSS
# Scoring", the schema's severity description, CLAUDE.md hard rule 6).
SEVERITY_BANDS = (("CRITICAL", 9.0), ("HIGH", 7.0), ("MEDIUM", 4.0), ("LOW", 0.0))

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

# A rejection links the public decision behind it: a GitHub issue or discussion.
DECISION_LINK = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/(?:issues|discussions)/[0-9]+")

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


# What: the schema versions that have a versioned file under schema/
# Why:  the list in an "unknown version" message has to come from the files that
#       exist, or it goes stale the day a version is added
# How:  glob schema/ave-record-X.Y.Z.schema.json and sort numerically
def published_schema_versions(schema_dir: Path | None = None) -> list[str]:
    directory = SCHEMA_DIR if schema_dir is None else schema_dir
    found = []
    for path in directory.glob("ave-record-*.schema.json"):
        version = path.name[len("ave-record-"):-len(".schema.json")]
        if SCHEMA_VERSION_PATTERN.fullmatch(version):
            found.append(version)
    return sorted(found, key=lambda v: tuple(int(part) for part in v.split(".")))


# What: the validator for the schema version one record declares, or an error
# Why:  a record is judged by the frozen rules of the version it states, not by
#       whichever version is newest; a record naming a version that has no file
#       cannot be validated at all, and saying so beats guessing
# How:  look up schema/ave-record-<schema_version>.schema.json, build and cache
#       its validator; a missing, malformed or unpublished version returns an
#       error message and no validator
def validator_for_record(record: dict, cache: dict, schema_dir: Path | None = None):
    directory = SCHEMA_DIR if schema_dir is None else schema_dir
    version = record.get("schema_version")
    if not isinstance(version, str) or not SCHEMA_VERSION_PATTERN.fullmatch(version):
        return None, [f"schema_version {version!r} is missing or is not X.Y.Z, so the record cannot be validated"]
    key = (str(directory), version)
    if key not in cache:
        path = directory / f"ave-record-{version}.schema.json"
        if not path.is_file():
            known = ", ".join(published_schema_versions(directory)) or "none"
            return None, [f"schema_version '{version}' has no schema file {path} (published versions: {known})"]
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        cache[key] = build_validator(schema)
    return cache[key], []


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


def severity_for_score(score: float) -> str:
    """The severity band a score falls in."""
    return next(name for name, lowest in SEVERITY_BANDS if score >= lowest)


def check_severity_band(record: dict) -> list[str]:
    """Confirms severity, and aivss.aivss_severity where a record carries it,
    is the band aivss.aivss_score falls in. CLAUDE.md hard rule 6 and the schema
    both say the two must agree, and until this check nothing enforced it: a
    rescore that moved a score across a band edge could leave the label behind,
    and every consumer that gates on severity would read the old band. A record
    with no aivss score (a draft) has nothing to compare."""
    aivss = record.get("aivss")
    if not isinstance(aivss, dict):
        return []
    score = aivss.get("aivss_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return []

    expected = severity_for_score(score)
    errors = []
    severity = record.get("severity")
    if severity is not None and severity != expected:
        errors.append(f"severity {severity} does not match aivss.aivss_score {score}, which is {expected}")
    stated = aivss.get("aivss_severity")
    if stated is not None and stated != expected:
        errors.append(f"aivss.aivss_severity {stated} does not match aivss.aivss_score {score}, which is {expected}")
    return errors


FINGERPRINT_END = (".", "!", "?", ")", "]", '"', "'", "`")
FINGERPRINT_CUT_LENGTH = 200


def check_fingerprint_not_cut_off(record: dict) -> list[str]:
    """Confirms behavioral_fingerprint was not cut off. The schema sets no length
    limit, and the AIVSS migration (#17, #18) stored eight fingerprints cut at
    exactly 200 characters, mid-word ("... human oversight checkp"), so a
    fingerprint that stops mid-sentence reached every consumer without anything
    noticing. A fingerprint must end in sentence-ending punctuation or a closing
    bracket, quote or backtick, and must not be exactly 200 characters long, the
    length it was cut to. A missing or non-string value is the schema's to report."""
    text = record.get("behavioral_fingerprint")
    if not isinstance(text, str):
        return []
    text = text.rstrip()
    if not text:
        return []
    errors = []
    if not text.endswith(FINGERPRINT_END):
        errors.append(f"behavioral_fingerprint does not end in sentence-ending punctuation, so it looks cut off: ends '...{text[-25:]}'")
    if len(text) == FINGERPRINT_CUT_LENGTH:
        errors.append(f"behavioral_fingerprint is exactly {FINGERPRINT_CUT_LENGTH} characters, the length eight fingerprints were once cut to (#414); check it is whole")
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


def check_revision_order(record: dict) -> list[str]:
    """The schema checks each revisions entry's shape; it cannot check the
    array's order or its agreement with last_updated. Entries are appended in
    date order, so a date earlier than the one before it is a rewritten
    history, and a revision dated after last_updated means last_updated no
    longer names the record's latest change, which is the one signal a
    consumer had before this field existed (#317). This checks one record
    only: an earlier entry deleted or rewritten in place is visible only
    against the previous version of the record, which
    scripts/check_revisions_ratchet.py compares it with, so the schema's
    append-only rule is enforced there, not here.
    """
    revisions = record.get("revisions")
    if not isinstance(revisions, list):
        return []
    errors = []
    dates = [entry.get("date", "") for entry in revisions if isinstance(entry, dict)]
    for i in range(1, len(dates)):
        if dates[i] < dates[i - 1]:
            errors.append(
                f"revisions[{i}].date {dates[i]} is earlier than revisions[{i - 1}].date "
                f"{dates[i - 1]}: revisions are appended in date order"
            )
    last_updated = str(record.get("last_updated") or "")[:10]
    if dates and last_updated and max(dates) > last_updated:
        errors.append(
            f"last_updated {last_updated} predates the latest revision {max(dates)}: "
            f"last_updated must name the record's latest change"
        )
    return errors


def check_revision_values(record: dict, known_fields) -> list[str]:
    """Each revision must name a field the schema defines and record a real
    change, and the revisions of one field must chain: every entry's from is
    the previous entry's to, and the latest to is the value the record holds
    now. That refuses a misspelt field, a no-op entry, a duplicated entry and
    a history that contradicts the record. A deleted or rewritten earlier
    entry can only be seen against the previous version of the record, which
    scripts/check_revisions_ratchet.py does.
    """
    revisions = record.get("revisions")
    if not isinstance(revisions, list):
        return []
    errors = []
    latest = {}
    for i, entry in enumerate(revisions):
        if not isinstance(entry, dict):
            continue
        field = entry.get("field")
        if field not in known_fields:
            errors.append(f"revisions[{i}].field {field!r} is not a property the schema defines")
            continue
        if entry.get("from") == entry.get("to"):
            errors.append(f"revisions[{i}] has the same from and to: it records no change")
        if field in latest and entry.get("from") != latest[field]:
            errors.append(
                f"revisions[{i}].from {entry.get('from')!r} is not the previous to "
                f"{latest[field]!r} for {field}"
            )
        latest[field] = entry.get("to")
    for field, value in latest.items():
        if record.get(field) != value:
            errors.append(
                f"the latest revision of {field} sets it to {value!r}, "
                f"but the record holds {record.get(field)!r}"
            )
    return errors


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


# What: merged_into and rejection_reason only on their own status, no self-merge, and a
#       rejection_reason that links the public decision
# Why:  the schema requires each field when its status is set (scaling spec section 3,
#       #104) but cannot refuse it elsewhere, see the record's own id, or tell a link
#       from prose; a stray merged_into on an active record would name a successor for
#       a record that has none
# How:  compare the fields against status and ave_id, and search the reason for a
#       GitHub issue or discussion URL
def check_status_fields(record: dict) -> list[str]:
    status = record.get("status")
    errors = []
    if "merged_into" in record and status != "merged":
        errors.append(f"merged_into belongs only on a merged record; this one is {status!r}")
    if "rejection_reason" in record and status != "rejected":
        errors.append(f"rejection_reason belongs only on a rejected record; this one is {status!r}")
    if status == "merged" and record.get("merged_into") == record.get("ave_id"):
        errors.append("merged_into names the record itself")
    reason = record.get("rejection_reason")
    if status == "rejected" and isinstance(reason, str) and not DECISION_LINK.search(reason):
        errors.append(
            "rejection_reason must link the public decision: a GitHub issue or discussion "
            "URL, https://github.com/<owner>/<repo>/issues/<n> or /discussions/<n>"
        )
    return errors


# What: every merged record's merged_into names an existing record whose status is active
# Why:  a merge points readers and tools at the record that survives it; a target that
#       does not exist, or is itself deprecated, merged, rejected or a draft, sends them
#       nowhere useful, and requiring an active target means merges never chain or loop
# How:  over the whole corpus, keyed by ave_id; a missing or self-naming merged_into is
#       left to the schema and check_status_fields
def check_merge_targets(records: dict) -> list[str]:
    errors = []
    for ave_id, record in sorted(records.items()):
        target = record.get("merged_into")
        if record.get("status") != "merged" or not isinstance(target, str) or target == ave_id:
            continue
        if target not in records:
            errors.append(f"{ave_id}: merged_into {target} is not a record in records/")
        elif records[target].get("status") != "active":
            errors.append(
                f"{ave_id}: merged_into {target} has status {records[target].get('status')!r}; "
                "a merge must point at an active record, so merges never chain or loop"
            )
    return errors


def record_errors(record: dict, raw_text: str, validator) -> list[str]:
    """Every hard error for one record, in the order main() reports them.

    main() and the tests both call this, so a check dropped from the
    pipeline fails a test instead of passing silently.
    """
    return (
        check_schema(record, validator)
        + check_no_old_field_names(record)
        + check_no_nested_owasp_mcp_mapping(record)
        + check_behavioral_vector_or_example_patterns(record)
        + check_mitigation_enums_only(record)
        + check_aivss_arithmetic(record)
        + check_severity_band(record)
        + check_fingerprint_not_cut_off(record)
        + check_no_vendor_boilerplate(raw_text)
        + check_verification_basis(record)
        + check_revision_order(record)
        + check_revision_values(record, validator.schema.get("properties", {}))
        + check_status_fields(record)
    )


def main() -> int:
    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print("No records found under records/", file=sys.stderr)
        return 1

    cache: dict = {}
    versions_seen: dict[str, int] = {}
    corpus: dict = {}
    total_errors = 0
    for path in paths:
        raw_text = path.read_text()
        record = json.loads(raw_text)
        rid = record.get("ave_id", path.name)
        corpus[rid] = record
        validator, version_errors = validator_for_record(record, cache)
        if validator is None:
            errors = version_errors
        else:
            versions_seen[record["schema_version"]] = versions_seen.get(record["schema_version"], 0) + 1
            errors = record_errors(record, raw_text, validator)
        for e in errors:
            print(f"{rid}: {e}")
        total_errors += len(errors)

        warnings = check_researcher_matches_disclosure(record)
        if warnings:
            for w in warnings:
                print(f"WARNING [{record['ave_id']}]: {w}")
            # do not increment the failure counter, do not affect exit code

    corpus_errors = check_merge_targets(corpus)
    for e in corpus_errors:
        print(e)
    total_errors += len(corpus_errors)

    if total_errors:
        print(f"\n{total_errors} error(s) across {len(paths)} records.", file=sys.stderr)
        return 1
    summary = ", ".join(f"{v}: {n}" for v, n in sorted(versions_seen.items()))
    print(f"All {len(paths)} records valid against the schema version each declares ({summary}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
