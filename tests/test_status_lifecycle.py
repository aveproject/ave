"""Schema 1.3.0's lifecycle statuses (#104, scaling spec section 3): a merged record
names the active record that survives it in merged_into, a rejected record says why
in rejection_reason and links the public decision, and both keep the full field set.

The schema requires each field on its own status. validate_records.py checks what one
record's schema cannot: neither field on any other status, no self-merge, a link to
the decision, and, across the corpus, a merge target that exists and is active, so
merges never chain or loop.
"""
import copy
import json
import shutil
from pathlib import Path

import pytest

from scripts import validate_records

REAL_RECORD = Path("records/AVE-2026-00001.json")
DECISION = "https://github.com/aveproject/ave/discussions/234"


def _validator(version="1.3.0"):
    path = Path(f"schema/ave-record-{version}.schema.json")
    return validate_records.build_validator(json.loads(path.read_text(encoding="utf-8")))


def _record(ave_id="AVE-2026-00001", **changes):
    """A real, fully populated record on schema 1.3.0, with changes applied."""
    record = json.loads(REAL_RECORD.read_text(encoding="utf-8"))
    record["schema_version"] = "1.3.0"
    record["ave_id"] = ave_id
    record.update(changes)
    return record


def _merged(target="AVE-2026-00002", ave_id="AVE-2026-00001"):
    return _record(ave_id, status="merged", merged_into=target)


def _rejected(reason=f"Not a distinct behavioral class; decided in {DECISION}."):
    return _record(status="rejected", rejection_reason=reason)


def _all_errors(record, corpus=None):
    """Schema, per-record and corpus errors for one record, as main() would report them."""
    corpus = corpus if corpus is not None else {record["ave_id"]: record}
    return (validate_records.record_errors(record, json.dumps(record), _validator())
            + validate_records.check_merge_targets(corpus))


# --- valid uses -----------------------------------------------------------------------

def test_a_merged_record_pointing_at_an_active_record_is_valid():
    merged, survivor = _merged(), _record("AVE-2026-00002")
    corpus = {merged["ave_id"]: merged, survivor["ave_id"]: survivor}

    assert _all_errors(merged, corpus) == []


@pytest.mark.parametrize("reason", [
    f"Not a distinct behavioral class; decided in {DECISION}.",
    "See https://github.com/aveproject/ave/issues/104 for the decision.",
])
def test_a_rejected_record_linking_its_decision_is_valid(reason):
    assert _all_errors(_rejected(reason)) == []


@pytest.mark.parametrize("status", ["merged", "rejected"])
def test_merged_and_rejected_keep_the_full_field_set(status):
    record = _merged() if status == "merged" else _rejected()
    del record["remediation"]

    errors = validate_records.check_schema(record, _validator())

    assert any("'remediation' is a required property" in e for e in errors)


# --- what the schema requires ---------------------------------------------------------

def test_a_merged_record_without_merged_into_is_refused():
    record = _merged()
    del record["merged_into"]

    errors = validate_records.check_schema(record, _validator())

    assert any("'merged_into' is a required property" in e for e in errors)


def test_a_rejected_record_without_a_reason_is_refused():
    record = _rejected()
    del record["rejection_reason"]

    errors = validate_records.check_schema(record, _validator())

    assert any("'rejection_reason' is a required property" in e for e in errors)


def test_an_empty_rejection_reason_is_refused():
    errors = validate_records.check_schema(_rejected(""), _validator())

    assert any("rejection_reason" in e for e in errors)


def test_merged_into_must_be_an_ave_id():
    errors = validate_records.check_schema(_merged("AVE-2026-2"), _validator())

    assert any("merged_into" in e for e in errors)


@pytest.mark.parametrize("status", ["merged", "rejected"])
def test_the_frozen_1_2_0_schema_still_refuses_the_new_statuses(status):
    record = _merged() if status == "merged" else _rejected()
    record["schema_version"] = "1.2.0"

    errors = validate_records.check_schema(record, _validator("1.2.0"))

    assert any("is not one of" in e for e in errors)


# --- what the validator checks beyond the schema --------------------------------------

@pytest.mark.parametrize("reason", [
    "Out of AVE's scope: no agentic distinction exists.",
    "Decided in discussion 234 on the ave repository.",
    "http://github.com/aveproject/ave/discussions/234",
    "https://example.com/decision",
    "https://github.com/aveproject/ave/pull/300",
    "https://github.com/aveproject/ave/discussions/",
])
def test_a_rejection_reason_without_a_link_to_the_decision_is_refused(reason):
    errors = validate_records.check_status_fields(_rejected(reason))

    assert any("must link the public decision" in e for e in errors)


def test_a_record_cannot_be_merged_into_itself():
    errors = validate_records.check_status_fields(_merged(target="AVE-2026-00001"))

    assert any("names the record itself" in e for e in errors)


@pytest.mark.parametrize("status", ["active", "deprecated", "draft", "rejected"])
def test_merged_into_is_refused_on_any_status_but_merged(status):
    record = _record(status=status, merged_into="AVE-2026-00002")
    if status == "rejected":
        record["rejection_reason"] = DECISION

    errors = validate_records.check_status_fields(record)

    assert any("merged_into belongs only on a merged record" in e for e in errors)


@pytest.mark.parametrize("status", ["active", "deprecated", "draft", "merged"])
def test_rejection_reason_is_refused_on_any_status_but_rejected(status):
    record = _record(status=status, rejection_reason=DECISION)
    if status == "merged":
        record["merged_into"] = "AVE-2026-00002"

    errors = validate_records.check_status_fields(record)

    assert any("rejection_reason belongs only on a rejected record" in e for e in errors)


@pytest.mark.parametrize("target_status", ["deprecated", "merged", "rejected", "draft"])
def test_a_merge_into_a_record_that_is_not_active_is_refused(target_status):
    merged = _merged()
    target = _record("AVE-2026-00002", status=target_status)
    corpus = {merged["ave_id"]: merged, target["ave_id"]: target}

    errors = validate_records.check_merge_targets(corpus)

    assert errors == [
        f"AVE-2026-00001: merged_into AVE-2026-00002 has status '{target_status}'; a merge "
        "must point at an active record, so merges never chain or loop"
    ]


def test_two_records_merged_into_each_other_are_both_refused():
    first, second = _merged("AVE-2026-00002"), _merged("AVE-2026-00001", ave_id="AVE-2026-00002")

    errors = validate_records.check_merge_targets({"AVE-2026-00001": first, "AVE-2026-00002": second})

    assert len(errors) == 2


def test_a_merge_into_an_unknown_id_is_refused():
    merged = _merged("AVE-2026-99999")

    errors = validate_records.check_merge_targets({merged["ave_id"]: merged})

    assert errors == ["AVE-2026-00001: merged_into AVE-2026-99999 is not a record in records/"]


def test_record_errors_includes_the_status_field_checks():
    record = _record(status="active", merged_into="AVE-2026-00002")

    errors = validate_records.record_errors(record, json.dumps(record), _validator())

    assert any("merged_into belongs only on a merged record" in e for e in errors)


# --- the new revision reason codes ----------------------------------------------------

@pytest.mark.parametrize("code", ["score_revised", "status_changed"])
def test_the_new_reason_codes_are_accepted_from_1_3_0_and_not_before(code):
    entry = {"date": "2026-10-29", "field": "status", "from": "active", "to": "rejected", "reason_code": code}
    record = _rejected()
    record["revisions"] = [entry]
    older = copy.deepcopy(record)
    older.update(schema_version="1.2.0", status="deprecated")
    del older["rejection_reason"]
    older["revisions"] = [dict(entry, to="deprecated")]

    assert validate_records.check_schema(record, _validator()) == []
    assert any(code in e for e in validate_records.check_schema(older, _validator("1.2.0")))


# --- main() over a corpus -------------------------------------------------------------

def _stage(tmp_path, monkeypatch, records):
    """A scratch records/ and schema/ holding the given records and the real schemas."""
    (tmp_path / "records").mkdir()
    shutil.copytree("schema", tmp_path / "schema")
    for record in records:
        path = tmp_path / "records" / f"{record['ave_id']}.json"
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    monkeypatch.setattr(validate_records, "RECORDS_DIR", tmp_path / "records")
    monkeypatch.setattr(validate_records, "SCHEMA_DIR", tmp_path / "schema")


def test_main_accepts_a_valid_merge(tmp_path, monkeypatch, capsys):
    _stage(tmp_path, monkeypatch, [_merged(), _record("AVE-2026-00002")])

    assert validate_records.main() == 0


def test_main_refuses_a_merge_into_a_deprecated_record(tmp_path, monkeypatch, capsys):
    _stage(tmp_path, monkeypatch, [_merged(), _record("AVE-2026-00002", status="deprecated")])

    assert validate_records.main() == 1
    assert "merged_into AVE-2026-00002 has status 'deprecated'" in capsys.readouterr().out
