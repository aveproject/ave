import json

from scripts import validate_records


def test_record_validator_rejects_invalid_date_time_format():
    schema = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = validate_records.build_validator(schema)
    record = {
        "ave_id": "AVE-2026-99999",
        "schema_version": "1.1.0",
        "status": "draft",
        "title": "Invalid date-time fixture",
        "description": "A minimal draft record with malformed published metadata.",
        "attack_class": "test",
        "behavioral_fingerprint": "test",
        "references": [{"title": "Example", "url": "https://example.com"}],
        "published": "not-a-date-time",
    }

    errors = validate_records.check_schema(record, validator)

    assert any("not-a-date-time" in error for error in errors)
