import pytest
from pathlib import Path
import importlib.util

FIXTURES = Path("tests/fixtures")
RULES    = Path("rules/pattern")

def load_rule(ave_id):
    for f in RULES.glob("*.py"):
        spec = importlib.util.spec_from_file_location(f.stem, f)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if mod.RULE.get("ave_id") == ave_id:
            return mod
    return None

def fixture_pairs():
    for pos in sorted(FIXTURES.glob("*_positive.*")):
        ave_id = pos.stem.replace("_positive", "")
        neg = FIXTURES / pos.name.replace("_positive", "_negative")
        if neg.exists():
            yield ave_id, pos, neg

@pytest.mark.parametrize("ave_id,pos,neg", list(fixture_pairs()))
def test_positive(ave_id, pos, neg):
    mod = load_rule(ave_id)
    if mod is None:
        pytest.skip(f"no rule for {ave_id}")
    assert mod.matches(pos.read_text()), \
        f"{ave_id}: positive fixture did not trigger"

@pytest.mark.parametrize("ave_id,pos,neg", list(fixture_pairs()))
def test_negative(ave_id, pos, neg):
    mod = load_rule(ave_id)
    if mod is None:
        pytest.skip(f"no rule for {ave_id}")
    assert not mod.matches(neg.read_text()), \
        f"{ave_id}: negative fixture triggered (false positive)"
