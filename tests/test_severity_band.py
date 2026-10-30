import json
from pathlib import Path

import pytest

from scripts import validate_records

RECORDS = sorted(Path("records").glob("AVE-*.json"))


def record(severity, score, nested=None):
    aivss = {"aivss_score": score}
    if nested is not None:
        aivss["aivss_severity"] = nested
    return {"ave_id": "AVE-2026-99999", "severity": severity, "aivss": aivss}


@pytest.mark.parametrize("score, band", [
    (10, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
    (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0, "LOW"),
])
def test_a_score_falls_in_the_band_the_readme_gives(score, band):
    assert validate_records.severity_for_score(score) == band
    assert validate_records.check_severity_band(record(band, score)) == []


def test_every_published_record_carries_the_band_its_score_falls_in():
    assert RECORDS, "no records found"
    for path in RECORDS:
        found = validate_records.check_severity_band(json.loads(path.read_text(encoding="utf-8")))
        assert found == [], f"{path.name}: {found}"


def test_a_label_one_band_off_is_reported_on_each_side_of_an_edge():
    assert len(validate_records.check_severity_band(record("CRITICAL", 8.9))) == 1
    assert len(validate_records.check_severity_band(record("HIGH", 9.0))) == 1
    assert len(validate_records.check_severity_band(record("MEDIUM", 7.0))) == 1
    assert len(validate_records.check_severity_band(record("HIGH", 6.9))) == 1
    assert len(validate_records.check_severity_band(record("LOW", 4.0))) == 1
    assert len(validate_records.check_severity_band(record("MEDIUM", 3.9))) == 1


def test_the_message_names_both_values_and_the_band():
    [message] = validate_records.check_severity_band(record("HIGH", 9.2))
    assert message == "severity HIGH does not match aivss.aivss_score 9.2, which is CRITICAL"


def test_the_nested_label_is_checked_when_present_and_ignored_when_absent():
    assert validate_records.check_severity_band(record("HIGH", 7.5, nested="HIGH")) == []
    [message] = validate_records.check_severity_band(record("HIGH", 7.5, nested="MEDIUM"))
    assert message.startswith("aivss.aivss_severity MEDIUM does not match")
    assert len(validate_records.check_severity_band(record("MEDIUM", 7.5, nested="MEDIUM"))) == 2


def test_a_record_with_no_score_has_nothing_to_compare():
    assert validate_records.check_severity_band({"ave_id": "AVE-2026-99999", "status": "draft"}) == []
    assert validate_records.check_severity_band({"severity": "HIGH", "aivss": {}}) == []
    assert validate_records.check_severity_band({"severity": "HIGH", "aivss": "n/a"}) == []
    assert validate_records.check_severity_band(record("HIGH", "7.5")) == []
    assert validate_records.check_severity_band(record("HIGH", True)) == []


def test_a_record_with_no_severity_is_the_schema_s_to_report_not_this_check_s():
    assert validate_records.check_severity_band({"aivss": {"aivss_score": 7.5}}) == []


def test_the_check_is_part_of_the_pipeline_a_record_goes_through():
    schema = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = validate_records.build_validator(schema)
    path = Path("records/AVE-2026-00001.json")
    raw = path.read_text(encoding="utf-8")
    good = json.loads(raw)
    assert validate_records.record_errors(good, raw, validator) == []
    bad = dict(good, severity="CRITICAL")
    found = validate_records.record_errors(bad, raw, validator)
    assert any("does not match aivss.aivss_score" in e for e in found), found
