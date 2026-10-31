import json
from pathlib import Path

import pytest

from scripts import validate_records

RECORDS = sorted(Path("records").glob("AVE-*.json"))
CUT_AT_200 = (
    "Component grants the agent unlimited authority to use any available tool, spawn sub-agents without limits, "
    "or recursively expand its own capabilities without scope boundaries or human oversight checkp"
)


def record(fingerprint):
    return {"ave_id": "AVE-2026-99999", "behavioral_fingerprint": fingerprint}


@pytest.mark.parametrize("text", [
    "Component instructs the agent to pipe remote content into a shell interpreter.",
    "Component instructs the agent to run a command (curl | bash)",
    'Component tells the agent to print "the secret"',
    "Component sets the flag `verify=False`",
    "Component sets the flag 'verify'",
    "Does the component ask the agent to run it?",
    "Component acts without asking!",
    "Component lists the allowed values [a, b]",
    "Component acts.   ",
    "x.",
])
def test_a_sentence_that_ends_where_a_sentence_ends_passes(text):
    assert validate_records.check_fingerprint_not_cut_off(record(text)) == []


@pytest.mark.parametrize("text", [
    "Component floods the agent's context window to push safety instructions out of the acti",
    "Component sets the flag and then enab",
    "Component acts",
    "Component acts,",
    "Component acts and",
    "Component acts:",
    "Component acts;",
])
def test_a_fingerprint_that_stops_mid_sentence_fails(text):
    found = validate_records.check_fingerprint_not_cut_off(record(text))
    assert len(found) == 1 and "does not end" in found[0], found


def test_the_message_shows_where_it_stops():
    found = validate_records.check_fingerprint_not_cut_off(record(CUT_AT_200))
    assert "oversight checkp" in found[0]


def test_exactly_200_characters_fails_even_when_it_ends_like_a_sentence():
    ends_well = "a" * 199 + "."
    assert len(ends_well) == 200
    found = validate_records.check_fingerprint_not_cut_off(record(ends_well))
    assert len(found) == 1 and "exactly 200 characters" in found[0], found


def test_the_200_character_message_says_how_to_fix_it():
    found = validate_records.check_fingerprint_not_cut_off(record("a" * 199 + "."))
    assert "finish it or restore the earlier text from git history" in found[0], found
    assert "if it is whole, reword it" in found[0] and "no longer exactly 200" in found[0], found


def test_a_cut_at_exactly_200_reports_both_problems():
    assert len(CUT_AT_200) == 200
    found = validate_records.check_fingerprint_not_cut_off(record(CUT_AT_200))
    assert len(found) == 2
    assert any("does not end" in e for e in found) and any("exactly 200 characters" in e for e in found)


def test_199_and_201_characters_are_fine():
    for n in (199, 201):
        assert validate_records.check_fingerprint_not_cut_off(record("a" * (n - 1) + ".")) == []


def test_trailing_whitespace_is_ignored_for_the_ending_but_not_counted_in_the_length():
    assert validate_records.check_fingerprint_not_cut_off(record("Component acts.\n")) == []
    assert validate_records.check_fingerprint_not_cut_off(record("a" * 199 + ".\n")) != []
    assert validate_records.check_fingerprint_not_cut_off(record("a" * 198 + ".   ")) == []


@pytest.mark.parametrize("bad", [None, 7, ["x"], {"a": 1}, ""])
def test_a_missing_or_odd_fingerprint_is_the_schema_s_to_report_not_this_check_s(bad):
    assert validate_records.check_fingerprint_not_cut_off({"ave_id": "AVE-2026-99999", "behavioral_fingerprint": bad}) == []
    assert validate_records.check_fingerprint_not_cut_off({"ave_id": "AVE-2026-99999"}) == []


@pytest.mark.parametrize("path", RECORDS, ids=lambda p: p.stem)
def test_no_published_record_has_a_fingerprint_that_is_cut_off(path):
    record_ = json.loads(path.read_text(encoding="utf-8"))
    assert validate_records.check_fingerprint_not_cut_off(record_) == []


def test_the_frozen_snapshot_still_has_the_eight_cut_fingerprints_so_the_guard_is_not_applied_to_it():
    """The guard checks records/, never the frozen dist snapshots, which are never edited."""
    frozen = json.loads(Path("dist/ave-records-v1.3.0.json").read_text(encoding="utf-8"))
    cut = sorted(r["ave_id"][-5:] for r in frozen if validate_records.check_fingerprint_not_cut_off(r))
    assert cut == ["00023", "00026", "00029", "00030", "00033", "00038", "00039", "00040"]


def test_the_check_is_part_of_the_pipeline_a_record_goes_through():
    schema = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = validate_records.build_validator(schema)
    raw = Path("records/AVE-2026-00001.json").read_text(encoding="utf-8")
    good = json.loads(raw)
    assert validate_records.record_errors(good, raw, validator) == []
    bad = dict(good, behavioral_fingerprint=CUT_AT_200)
    found = validate_records.record_errors(bad, raw, validator)
    assert any("does not end" in e for e in found) and any("exactly 200 characters" in e for e in found), found
