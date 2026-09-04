import json
import pytest
from scripts import check_framework_sources as check


def record(**overrides):
    base = {"ave_id": "AVE-2026-99999"}
    base.update(overrides)
    return base


def test_record_with_no_framework_fields_has_nothing_missing():
    assert check.missing_sources(record()) == []


def test_mapped_field_with_no_framework_sources_entry_is_missing():
    assert check.missing_sources(record(owasp_mcp=["MCP03"])) == ["owasp_mcp"]


def test_mapped_field_with_real_source_entry_is_not_missing():
    r = record(
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"commit": "a" * 40, "read_date": "2026-08-20"}},
    )
    assert check.missing_sources(r) == []


def test_source_entry_missing_read_date_does_not_count():
    """Mutation check: if the read_date requirement were dropped, this
    must go red. A version/commit alone with no date isn't a real pin."""
    r = record(
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"commit": "a" * 40}},
    )
    assert check.missing_sources(r) == ["owasp_mcp"]


def test_unpinnable_with_read_date_counts_as_a_real_source():
    r = record(
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"pin_status": "unpinnable", "read_date": "2026-08-20"}},
    )
    assert check.missing_sources(r) == []


def test_unpinnable_without_read_date_does_not_count():
    """Mutation check: if the unpinnable branch stopped checking read_date,
    this must go red -- unpinnable alone is a bare declaration, not a pin."""
    r = record(
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"pin_status": "unpinnable"}},
    )
    assert check.missing_sources(r) == ["owasp_mcp"]


def test_unknown_with_read_date_counts_as_a_real_source():
    r = record(
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"pin_status": "unknown", "read_date": "2026-08-20"}},
    )
    assert check.missing_sources(r) == []


def test_unknown_without_read_date_does_not_count():
    """Mutation check: if the unknown branch stopped checking read_date,
    this must go red -- unknown alone is a bare declaration, not a pin."""
    r = record(
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"pin_status": "unknown"}},
    )
    assert check.missing_sources(r) == ["owasp_mcp"]


def test_multiple_mapped_fields_each_checked_independently():
    r = record(
        owasp_mcp=["MCP03"],
        mitre_atlas=["AML.T0051.001"],
        framework_sources={"owasp_mcp": {"commit": "a" * 40, "read_date": "2026-08-20"}},
    )
    assert check.missing_sources(r) == ["mitre_atlas"]


def test_empty_list_field_is_not_treated_as_a_carried_mapping():
    """An empty owasp_asi: [] should not demand a framework_sources entry --
    there's no mapping to have provenance for."""
    assert check.missing_sources(record(owasp_asi=[])) == []


def test_default_mode_warns_and_exits_zero(tmp_path, monkeypatch, capsys):
    (tmp_path / "AVE-2026-99999.json").write_text(
        json.dumps(record(owasp_mcp=["MCP03"])), encoding="utf-8"
    )
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["check_framework_sources.py"])
    assert check.main([]) == 0
    assert "WARNING" in capsys.readouterr().out


def test_strict_mode_fails_on_missing_sources(tmp_path, monkeypatch):
    (tmp_path / "AVE-2026-99999.json").write_text(
        json.dumps(record(owasp_mcp=["MCP03"])), encoding="utf-8"
    )
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main(["--strict"]) == 1


def test_only_flag_scopes_the_check_to_named_records(tmp_path, monkeypatch):
    """The property a new-record PR gate depends on: --only must not
    re-flag the records that predate this field."""
    (tmp_path / "AVE-2026-00001.json").write_text(
        json.dumps(record(ave_id="AVE-2026-00001", owasp_mcp=["MCP03"])), encoding="utf-8"
    )
    complete = record(
        ave_id="AVE-2026-99999",
        owasp_mcp=["MCP03"],
        framework_sources={"owasp_mcp": {"commit": "a" * 40, "read_date": "2026-08-20"}},
    )
    (tmp_path / "AVE-2026-99999.json").write_text(json.dumps(complete), encoding="utf-8")
    monkeypatch.setattr(check, "RECORDS_DIR", tmp_path)
    assert check.main(["--strict", "--only", "AVE-2026-99999"]) == 0
