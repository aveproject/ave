import copy
import json

import pytest

from scripts import validate_records


def _validator():
    schema = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_records.build_validator(schema)


BASE = {
    "ave_id": "AVE-2026-99999",
    "schema_version": "1.3.0",
    "status": "draft",
    "title": "Revisions fixture",
    "description": "A minimal draft record carrying a revisions array.",
    "attack_class": "test",
    "behavioral_fingerprint": "test.",
    "references": ["https://example.com"],
    "last_updated": "2026-09-28T23:51:58Z",
    "evidence_vantage": "substrate",
    "revisions": [
        {
            "date": "2026-09-28",
            "field": "evidence_vantage",
            "from": None,
            "to": "substrate",
            "reason_code": "declaration_added",
        }
    ],
}


def _record(**entry_changes):
    record = copy.deepcopy(BASE)
    record["revisions"][0].update(entry_changes)
    return record


def test_an_added_field_entry_with_null_from_is_valid():
    assert validate_records.check_schema(_record(), _validator()) == []
    assert validate_records.check_revision_order(_record()) == []


def test_an_unregistered_reason_code_is_refused():
    errors = validate_records.check_schema(_record(reason_code="value_tweaked"), _validator())
    assert any("value_tweaked" in error for error in errors)


@pytest.mark.parametrize("missing", ["date", "field", "from", "to", "reason_code"])
def test_every_required_entry_member_is_required(missing):
    record = _record()
    del record["revisions"][0][missing]
    assert validate_records.check_schema(record, _validator())


def test_a_null_to_is_refused():
    assert validate_records.check_schema(_record(to=None), _validator())


def test_an_unknown_entry_member_is_refused():
    assert validate_records.check_schema(_record(note="x"), _validator())


def test_revisions_out_of_date_order_are_refused():
    record = _record()
    record["revisions"].insert(0, dict(record["revisions"][0], date="2026-09-29"))
    record["last_updated"] = "2026-09-29T00:00:00Z"
    errors = validate_records.check_revision_order(record)
    assert any("date order" in error for error in errors)


def test_a_revision_after_last_updated_is_refused():
    record = _record()
    record["last_updated"] = "2026-08-07T00:00:00Z"
    errors = validate_records.check_revision_order(record)
    assert any("predates the latest revision" in error for error in errors)


def test_a_record_without_revisions_makes_no_claim():
    record = copy.deepcopy(BASE)
    del record["revisions"]
    assert validate_records.check_revision_order(record) == []


def test_two_revisions_on_the_same_date_are_accepted():
    record = _record(to="artifact")
    record["revisions"].append(
        {
            "date": "2026-09-28",
            "field": "evidence_vantage",
            "from": "artifact",
            "to": "substrate",
            "reason_code": "declaration_added",
        }
    )
    assert validate_records.check_revision_order(record) == []


def test_the_validator_pipeline_refuses_revisions_out_of_date_order():
    record = _record()
    record["revisions"].insert(0, dict(record["revisions"][0], date="2026-09-29"))
    record["last_updated"] = "2026-09-29T00:00:00Z"
    errors = validate_records.record_errors(record, json.dumps(record), _validator())
    assert any("date order" in error for error in errors)


KNOWN_FIELDS = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))["properties"]


def test_a_consistent_history_passes_the_value_check():
    assert validate_records.check_revision_values(_record(), KNOWN_FIELDS) == []


def test_a_field_the_schema_does_not_define_is_refused():
    errors = validate_records.check_revision_values(_record(field="evidence_vantge"), KNOWN_FIELDS)
    assert any("not a property the schema defines" in error for error in errors)


def test_a_revision_with_the_same_from_and_to_is_refused():
    errors = validate_records.check_revision_values(_record(**{"from": "substrate"}), KNOWN_FIELDS)
    assert any("records no change" in error for error in errors)


def test_a_duplicated_revision_breaks_the_chain():
    record = _record()
    record["revisions"].append(copy.deepcopy(record["revisions"][0]))
    errors = validate_records.check_revision_values(record, KNOWN_FIELDS)
    assert any("is not the previous to" in error for error in errors)


def test_a_latest_to_that_contradicts_the_record_is_refused():
    errors = validate_records.check_revision_values(_record(to="artifact"), KNOWN_FIELDS)
    assert any("but the record holds 'substrate'" in error for error in errors)


def test_the_validator_pipeline_refuses_a_contradicting_latest_to():
    record = _record(to="artifact")
    errors = validate_records.record_errors(record, json.dumps(record), _validator())
    assert any("but the record holds" in error for error in errors)
