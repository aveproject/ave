"""Each record is validated against the schema version it declares, not the newest one."""

import json
import shutil
from pathlib import Path

import pytest

from scripts import validate_records

# The record as published under schema 1.3.0: the frozen snapshot keeps the 1.x shape
# (aarf with data_access and external_dependencies) that the 1.x schema files describe.
SNAPSHOT = Path("dist/ave-records-v1.3.0.json")


def _real_record(version):
    record = next(r for r in json.loads(SNAPSHOT.read_text(encoding="utf-8")) if r["ave_id"] == "AVE-2026-00001")
    record["schema_version"] = version
    return record


def _write_schemas(directory: Path, versions: dict[str, set[str]]) -> None:
    """Write tiny closed schemas: each version accepts ave_id, schema_version and its own extras."""
    directory.mkdir(parents=True, exist_ok=True)
    for version, extras in versions.items():
        properties = {"ave_id": {"type": "string"}, "schema_version": {"type": "string"}}
        properties.update({name: {"type": "string"} for name in extras})
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
        }
        (directory / f"ave-record-{version}.schema.json").write_text(json.dumps(schema), encoding="utf-8")


def test_a_1_1_0_record_validates_against_the_frozen_1_1_0_file():
    validator, errors = validate_records.validator_for_record(_real_record("1.1.0"), {})

    assert errors == []
    assert validator.schema["$id"].endswith("ave-record-1.1.0.schema.json")
    assert validate_records.check_schema(_real_record("1.1.0"), validator) == []


def test_a_1_2_0_record_validates_against_the_1_2_0_file():
    validator, errors = validate_records.validator_for_record(_real_record("1.2.0"), {})

    assert errors == []
    assert validator.schema["$id"].endswith("ave-record-1.2.0.schema.json")


def test_an_unknown_version_is_refused_with_a_clear_message():
    validator, errors = validate_records.validator_for_record(_real_record("9.9.9"), {})

    assert validator is None
    assert len(errors) == 1
    assert "9.9.9" in errors[0]
    assert "published versions" in errors[0]
    assert "1.2.0" in errors[0]


@pytest.mark.parametrize("bad", [None, "1.1", "v1.1.0", "1.1.0-rc1", 1.1, ""])
def test_a_missing_or_malformed_version_is_refused(bad):
    record = _real_record("1.2.0")
    if bad is None:
        del record["schema_version"]
    else:
        record["schema_version"] = bad

    validator, errors = validate_records.validator_for_record(record, {})

    assert validator is None
    assert errors and "schema_version" in errors[0]


def test_a_1_2_0_record_may_use_a_field_that_1_1_0_lacks(tmp_path):
    _write_schemas(tmp_path, {"1.1.0": set(), "1.2.0": {"new_field"}})
    new_style = {"ave_id": "AVE-2026-99999", "schema_version": "1.2.0", "new_field": "x"}

    validator, errors = validate_records.validator_for_record(new_style, {}, schema_dir=tmp_path)
    assert errors == []
    assert validate_records.check_schema(new_style, validator) == []

    # the very same content declaring 1.1.0 is judged by 1.1.0's closed field set
    old_style = dict(new_style, schema_version="1.1.0")
    old_validator, old_errors = validate_records.validator_for_record(old_style, {}, schema_dir=tmp_path)
    assert old_errors == []
    assert validate_records.check_schema(old_style, old_validator)


def test_the_validator_cache_is_per_version(tmp_path):
    _write_schemas(tmp_path, {"1.1.0": set(), "1.2.0": {"new_field"}})
    cache: dict = {}

    first, _ = validate_records.validator_for_record({"schema_version": "1.1.0"}, cache, schema_dir=tmp_path)
    second, _ = validate_records.validator_for_record({"schema_version": "1.2.0"}, cache, schema_dir=tmp_path)
    again, _ = validate_records.validator_for_record({"schema_version": "1.1.0"}, cache, schema_dir=tmp_path)

    assert first is not second
    assert first is again


def test_published_versions_come_from_the_files_in_numeric_order(tmp_path):
    _write_schemas(tmp_path, {"1.10.0": set(), "1.2.0": set(), "1.1.0": set()})
    (tmp_path / "ave-record.schema.json").write_text("{}", encoding="utf-8")  # the alias is not a version

    assert validate_records.published_schema_versions(tmp_path) == ["1.1.0", "1.2.0", "1.10.0"]


def _stage_corpus(tmp_path, monkeypatch, versions):
    """A scratch corpus: one real record per entry in versions, plus the real schema files."""
    records = tmp_path / "records"
    schemas = tmp_path / "schema"
    records.mkdir()
    schemas.mkdir()
    for path in Path("schema").glob("ave-record-*.schema.json"):
        shutil.copy(path, schemas / path.name)
    for index, version in enumerate(versions, start=1):
        text = json.dumps(_real_record(version), indent=2) + "\n"
        (records / f"AVE-2026-0000{index}.json").write_text(text, encoding="utf-8")
    monkeypatch.setattr(validate_records, "RECORDS_DIR", records)
    monkeypatch.setattr(validate_records, "SCHEMA_DIR", schemas)


def test_main_validates_a_mixed_corpus_and_reports_each_version(tmp_path, monkeypatch, capsys):
    _stage_corpus(tmp_path, monkeypatch, ["1.1.0", "1.2.0"])

    assert validate_records.main() == 0

    out = capsys.readouterr().out
    assert "1.1.0: 1" in out and "1.2.0: 1" in out


def test_main_fails_on_a_record_with_an_unpublished_version(tmp_path, monkeypatch, capsys):
    _stage_corpus(tmp_path, monkeypatch, ["1.2.0", "9.9.9"])

    assert validate_records.main() == 1

    assert "9.9.9" in capsys.readouterr().out
