"""A crosswalk must not name a rejected AVE record as if it were live.

A record with status `rejected` is not a gap in a framework and not a mapping target,
so a crosswalk that points at one in an id field is stale. The check reads the same
structural id fields the id-resolution check reads (ave_id, primary_ave_id, ave_ids),
finds ids inside comma-separated values, exempts a `checked_and_rejected` section
because naming the rejected record is its purpose, and only warns for a crosswalk
that its tool's own author maintains.
"""
import json

import pytest

from scripts import validate_crosswalks

REJECTED = {"AVE-2026-00052", "AVE-2026-00053"}


def crosswalk(**sections) -> dict:
    """A minimal crosswalk document carrying the sections under test."""
    return {
        "$schema": "https://aveproject.org/schema/crosswalk-1.0.0.schema.json",
        "source": {"url": "https://aveproject.org"},
        "target": {"url": "https://aveproject.org"},
        "generated": "2026-11-16",
        "note": "Fixture crosswalk.",
        "mappings": [{"ave_id": "AVE-2026-00001"}],
        "coverage": {"mapped": 1},
        **sections,
    }


def test_rejected_ids_are_the_records_whose_status_is_rejected(tmp_path, monkeypatch):
    records = tmp_path / "records"
    records.mkdir()
    for ave_id, status in (("AVE-2026-00001", "active"), ("AVE-2026-00052", "rejected"),
                           ("AVE-2026-00060", "deprecated"), ("AVE-2026-00061", "rejected")):
        (records / f"{ave_id}.json").write_text(
            json.dumps({"ave_id": ave_id, "status": status}), encoding="utf-8")
    (records / "AVE-2026-00002.json").write_text(
        json.dumps({"ave_id": "AVE-2026-00002"}), encoding="utf-8")
    monkeypatch.setattr(validate_crosswalks, "RECORDS_DIR", records)

    assert validate_crosswalks.rejected_ave_ids() == {"AVE-2026-00052", "AVE-2026-00061"}


def test_a_mapping_to_a_rejected_record_fails():
    document = crosswalk(mappings=[{"ave_id": "AVE-2026-00001"}, {"ave_id": "AVE-2026-00052"}])

    failures, warnings = validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json")

    assert warnings == []
    assert len(failures) == 1
    assert "AVE-2026-00052" in failures[0] and "mappings[1].ave_id" in failures[0]


def test_a_gap_entry_naming_a_rejected_record_fails():
    document = crosswalk(gaps_in_x=[{"topic": "t", "ave_id": "AVE-2026-00053", "reason": "r"}])

    failures, _ = validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json")

    assert len(failures) == 1 and "AVE-2026-00053" in failures[0]


def test_primary_ave_id_and_ave_ids_are_read_too():
    document = crosswalk(mappings=[
        {"primary_ave_id": "AVE-2026-00052", "ave_ids": ["AVE-2026-00001", "AVE-2026-00053"]}])

    failures, _ = validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json")

    assert sorted(f.split()[0] for f in failures) == [
        "mappings[0].ave_ids[1]", "mappings[0].primary_ave_id"]


def test_ids_inside_a_comma_separated_value_are_found():
    document = crosswalk(gaps_in_x=[{"ave_id": "AVE-2026-00052, AVE-2026-00053"}])

    failures, _ = validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json")

    assert len(failures) == 2
    assert any("AVE-2026-00052" in f for f in failures)
    assert any("AVE-2026-00053" in f for f in failures)


def test_a_free_text_value_that_names_no_record_is_left_alone():
    document = crosswalk(gaps_in_x=[{"ave_id": "all 56 records"}])

    assert validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json") == ([], [])


def test_a_checked_and_rejected_section_may_name_the_rejected_record():
    document = crosswalk(checked_and_rejected=[
        {"skillspector_rule": "TT5", "ave_id": "AVE-2026-00052", "reason": "rejected"}])

    assert validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json") == ([], [])


def test_the_exemption_is_only_for_the_checked_and_rejected_section():
    document = crosswalk(
        checked_and_rejected=[{"ave_id": "AVE-2026-00052"}],
        gaps=[{"ave_id": "AVE-2026-00053"}])

    failures, _ = validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json")

    assert len(failures) == 1 and "gaps[0].ave_id" in failures[0]


def test_a_note_may_say_a_record_was_rejected():
    document = crosswalk(
        note="AVE-2026-00052 was rejected in v1.3.0.",
        revision_note="AVE-2026-00053 dropped; see discussion 234.",
        gaps=[{"reason": "Mapped to AVE-2026-00053 until it was rejected."}])

    assert validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "some-tool-to-ave.json") == ([], [])


def test_a_crosswalk_owned_by_its_tool_author_only_warns(monkeypatch):
    monkeypatch.setattr(validate_crosswalks, "EXTERNALLY_OWNED_CROSSWALKS",
                        {"owned-by-someone-else.json": "the-author"})
    document = crosswalk(mappings=[{"ave_id": "AVE-2026-00052"}])

    failures, warnings = validate_crosswalks.check_no_rejected_ids(
        document, REJECTED, "owned-by-someone-else.json")

    assert failures == []
    assert len(warnings) == 1
    assert "the-author" in warnings[0] and "AVE-2026-00052" in warnings[0]


def test_every_externally_owned_crosswalk_exists():
    """A renamed or removed file must not leave a stale exemption behind."""
    for name in validate_crosswalks.EXTERNALLY_OWNED_CROSSWALKS:
        assert (validate_crosswalks.CROSSWALKS_DIR / name).is_file(), name


def test_no_crosswalk_the_project_maintains_names_a_rejected_record():
    rejected = validate_crosswalks.rejected_ave_ids()
    assert rejected, "the repository has rejected records; the check has something to find"
    for path in sorted(validate_crosswalks.CROSSWALKS_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        failures, _ = validate_crosswalks.check_no_rejected_ids(document, rejected, path.name)
        assert failures == [], path.name


def run_tree(tmp_path, monkeypatch, crosswalk_files: dict) -> None:
    """A repository in miniature: the shipped crosswalk schema, three records (one
    rejected), and the given crosswalks, for main() to run against."""
    (tmp_path / "schema").mkdir()
    schema = validate_crosswalks.SCHEMA_PATH.read_text(encoding="utf-8")
    (tmp_path / "schema" / "crosswalk-1.0.0.schema.json").write_text(schema, encoding="utf-8")
    (tmp_path / "records").mkdir()
    for ave_id, status in (("AVE-2026-00001", "active"), ("AVE-2026-00052", "rejected")):
        (tmp_path / "records" / f"{ave_id}.json").write_text(
            json.dumps({"ave_id": ave_id, "status": status}), encoding="utf-8")
    (tmp_path / "crosswalks").mkdir()
    for name, document in crosswalk_files.items():
        (tmp_path / "crosswalks" / name).write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["validate_crosswalks.py"])


def test_the_run_fails_when_a_crosswalk_names_a_rejected_record(tmp_path, monkeypatch, capsys):
    run_tree(tmp_path, monkeypatch, {
        "mine-to-ave.json": crosswalk(mappings=[{"ave_id": "AVE-2026-00052"}])})

    exit_code = validate_crosswalks.main()

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "FAIL" in out and "AVE-2026-00052" in out and "rejected" in out


def test_the_run_passes_with_a_warning_for_an_externally_owned_crosswalk(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validate_crosswalks, "EXTERNALLY_OWNED_CROSSWALKS",
                        {"theirs-to-ave.json": "their-author"})
    run_tree(tmp_path, monkeypatch, {
        "theirs-to-ave.json": crosswalk(mappings=[{"ave_id": "AVE-2026-00052"}])})

    exit_code = validate_crosswalks.main()

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "WARNING [theirs-to-ave.json]" in out and "their-author" in out
    assert "FAIL" not in out
