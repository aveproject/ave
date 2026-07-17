import json
import pytest
from pathlib import Path

RECORDS  = Path("records")
FIXTURES = Path("tests/fixtures")


def ave_ids():
    return sorted(f.stem for f in RECORDS.glob("AVE-*.json"))


def fixture_pairs():
    for pos in sorted(FIXTURES.glob("*_positive.*")):
        ave_id = pos.stem.replace("_positive", "")
        neg = FIXTURES / pos.name.replace("_positive", "_negative")
        if neg.exists():
            yield ave_id, pos, neg


@pytest.mark.parametrize("ave_id", ave_ids())
def test_record_has_fixture_pair(ave_id):
    pos = any(FIXTURES.glob(f"{ave_id}_positive.*"))
    neg = any(FIXTURES.glob(f"{ave_id}_negative.*"))
    assert pos, f"{ave_id}: missing positive fixture"
    assert neg, f"{ave_id}: missing negative fixture"


@pytest.mark.parametrize("ave_id,pos,neg", list(fixture_pairs()))
def test_positive_fixture_nonempty(ave_id, pos, neg):
    assert pos.read_text().strip(), f"{ave_id}: positive fixture is empty"


@pytest.mark.parametrize("ave_id,pos,neg", list(fixture_pairs()))
def test_negative_fixture_nonempty(ave_id, pos, neg):
    assert neg.read_text().strip(), f"{ave_id}: negative fixture is empty"


@pytest.mark.parametrize("ave_id,pos,neg", list(fixture_pairs()))
def test_fixture_pair_has_matching_record(ave_id, pos, neg):
    record_path = RECORDS / f"{ave_id}.json"
    assert record_path.exists(), f"{ave_id}: fixture pair has no matching record"
    record = json.loads(record_path.read_text())
    assert record["ave_id"] == ave_id
