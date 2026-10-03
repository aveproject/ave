import json
from scripts import check_mutation_thm_trail as check


def record(**overrides):
    base = {"ave_id": "AVE-2026-99999", "mutation_count": 0, "aivss": {"notes": ""}}
    base.update(overrides)
    return base


def test_zero_mutation_count_needs_no_trail():
    assert check.has_thm_trail(record(mutation_count=0, aivss={"notes": ""})) is True


def test_mutation_count_one_with_no_thm_keyword_is_flagged():
    assert check.has_thm_trail(record(
        mutation_count=1,
        aivss={"notes": "AARF scores based on typical agentic deployment context."},
    )) is False


def test_mutation_count_one_with_thm_keyword_passes():
    """Notes field contains 'ThM unchanged, same evidence tier' or
    similar, matches on keyword, passes."""
    assert check.has_thm_trail(record(
        mutation_count=1,
        aivss={"notes": "ThM unchanged, new source is theoretical, same tier as existing citations."},
    )) is True


def test_missing_mutation_count_field_is_treated_as_zero():
    r = {"ave_id": "AVE-2026-99999", "aivss": {"notes": ""}}
    assert check.has_thm_trail(r) is True


def test_missing_notes_field_with_mutation_is_flagged():
    """A record can carry mutation_count without an aivss.notes field at
    all (predates this convention); that reads as no trail, not a crash."""
    r = {"ave_id": "AVE-2026-99999", "mutation_count": 3, "aivss": {}}
    assert check.has_thm_trail(r) is False


def test_keyword_match_is_case_insensitive():
    assert check.has_thm_trail(record(
        mutation_count=1,
        aivss={"notes": "MUTATION recorded, no score change warranted."},
    )) is True


def test_default_mode_warns_and_exits_zero(tmp_path, monkeypatch, capsys):
    flagged = record(mutation_count=1, aivss={"notes": "no reasoning here"})
    (tmp_path / "AVE-2026-99999.json").write_text(json.dumps(flagged), encoding="utf-8")
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main([]) == 0
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "AVE-2026-99999" in out


def test_strict_mode_fails_on_missing_trail(tmp_path, monkeypatch):
    flagged = record(mutation_count=1, aivss={"notes": "no reasoning here"})
    (tmp_path / "AVE-2026-99999.json").write_text(json.dumps(flagged), encoding="utf-8")
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main(["--strict"]) == 1


def test_strict_mode_passes_when_trail_present(tmp_path, monkeypatch):
    clean = record(mutation_count=1, aivss={"notes": "thm raised from 0.75 to 1"})
    (tmp_path / "AVE-2026-99999.json").write_text(json.dumps(clean), encoding="utf-8")
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main(["--strict"]) == 0


def test_only_flag_scopes_the_check(tmp_path, monkeypatch):
    """The property a new-record or edited-record PR gate depends on:
    --only must not re-flag other records in the same directory."""
    flagged = record(ave_id="AVE-2026-00001", mutation_count=5, aivss={"notes": ""})
    (tmp_path / "AVE-2026-00001.json").write_text(json.dumps(flagged), encoding="utf-8")
    clean = record(ave_id="AVE-2026-99999", mutation_count=1, aivss={"notes": "thm unchanged"})
    (tmp_path / "AVE-2026-99999.json").write_text(json.dumps(clean), encoding="utf-8")
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main(["--strict", "--only", "AVE-2026-99999"]) == 0


def test_no_records_found_returns_error(tmp_path, monkeypatch):
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main([]) == 2
