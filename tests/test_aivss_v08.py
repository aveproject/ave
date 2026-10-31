"""AVE scores with the OWASP AIVSS v0.8 equation from schema 2.0.0 (sections 3.3 to 3.5 of the
v0.8 document, https://aivss.owasp.org):

    AARS  = (10 - CVSS_Base) x (Factor_Sum / 10) x ThM
    AIVSS = (CVSS_Base + AARS) x Mitigation_Factor, rounded half up to one decimal

Schema 1.x declared a different equation and its records are still checked against it.
"""
import copy
import json
from decimal import Decimal
from pathlib import Path

import jsonschema
import pytest

from scripts import validate_records

SCHEMA = json.loads(Path("schema/ave-record-2.0.0.schema.json").read_text(encoding="utf-8"))
RECORDS = sorted(Path("records").glob("AVE-*.json"))

# OWASP's own worked examples (v0.8, section 3.6, Table 5): CVSS base, Factor_Sum, expected
# AARS, expected score. All use ThM 0.97 and a Mitigation_Factor of 1.0.
OWASP_EXAMPLES = [
    ("3.6.1 Agentic AI Tool Misuse", 9.4, 9.0, "0.5238", "9.9"),
    ("3.6.2 Agent Access Control Violation", 8.7, 8.0, "1.0088", "9.7"),
    ("3.6.3 Agent Cascading Failures", 7.1, 8.0, "2.2504", "9.4"),
    ("3.6.4 Agent Orchestration Exploitation", 9.4, 9.5, "0.5529", "10.0"),
    ("3.6.5 Agent Identity Impersonation", 7.4, 7.5, "1.8915", "9.3"),
    ("3.6.6 Agent Memory Manipulation", 5.8, 7.5, "3.0555", "8.9"),
    ("3.6.7 Critical Systems Interaction", 6.9, 7.5, "2.25525", "9.2"),
    ("3.6.8 Agent Supply Chain Risk", 9.3, 6.5, "0.44135", "9.7"),
    ("3.6.9 Agent Untraceability", 5.3, 6.5, "2.96335", "8.3"),
    ("3.6.10 Goal and Instruction Manipulation", 2.1, 6.5, "4.98095", "7.1"),
]

FULL = {name: 1 for name in validate_records.AARF_FACTORS}


def record(cvss=8.0, factors=None, thm=1, mf=1, aars=None, score=None, top=None, version="2.0.0"):
    """A record carrying only what the arithmetic check reads, consistent unless overridden."""
    factors = dict(FULL if factors is None else factors)
    exact_aars, exact_score = validate_records.aivss_v08(cvss, sum(Decimal(str(v)) for v in factors.values()), thm, mf)
    score = float(exact_score) if score is None else score
    aivss = {"cvss_base": cvss, "aarf": factors,
             "aars": float(exact_aars.quantize(validate_records.AARS_STORED_PLACES)) if aars is None else aars,
             "thm": thm, "mitigation_factor": mf, "aivss_score": score}
    return {"schema_version": version, "aivss": aivss, "aivss_score": score if top is None else top}


@pytest.mark.parametrize("name, cvss, factor_sum, aars, score", OWASP_EXAMPLES, ids=[e[0] for e in OWASP_EXAMPLES])
def test_the_equation_reproduces_owasps_own_worked_examples(name, cvss, factor_sum, aars, score):
    got_aars, got_score = validate_records.aivss_v08(cvss, factor_sum, 0.97, 1.0)
    assert got_aars == Decimal(aars)
    assert got_score == Decimal(score)


def test_rounding_is_half_up_not_python_s_round():
    # round(9.35, 1) is 9.3 and round(8.25, 1) is 8.2 in Python; the document says half up
    assert validate_records.aivss_v08(9.35, 0, 1, 1)[1] == Decimal("9.4")
    assert validate_records.aivss_v08(8.25, 0, 1, 1)[1] == Decimal("8.3")
    assert validate_records.aivss_v08(7.35, 0, 1, 1)[1] == Decimal("7.4")


def test_the_score_comes_from_the_exact_uplift_not_the_four_decimal_aars_a_record_stores():
    # AARS is 2.74995 exactly. Stored to four decimals it is 2.7500, which would make 4.65 and round to 4.7.
    aars, score = validate_records.aivss_v08(1.9, 3.5, 0.97, 1)
    assert aars == Decimal("2.74995")
    assert score == Decimal("4.6")
    factors = {name: 0 for name in validate_records.AARF_FACTORS} | {"autonomy": 1, "tool_use": 1, "multi_agent": 1, "context": 0.5}
    assert validate_records.check_aivss_arithmetic(record(1.9, factors, thm=0.97, aars=2.75, score=4.6)) == []
    assert validate_records.check_aivss_arithmetic(record(1.9, factors, thm=0.97, aars=2.75, score=4.7))[0].startswith("aivss.aivss_score mismatch: computed 4.6")


def test_a_consistent_record_passes():
    assert validate_records.check_aivss_arithmetic(record()) == []
    assert validate_records.check_aivss_arithmetic(record(cvss=5.0, thm=0.5, mf=0.83)) == []


def test_each_way_a_record_can_disagree_is_reported_separately():
    [aars] = validate_records.check_aivss_arithmetic(record(aars=5))
    assert aars.startswith("aivss.aars mismatch: computed 2.0000, record states 5")
    [score] = validate_records.check_aivss_arithmetic(record(score=9.9, top=9.9))
    assert score == "aivss.aivss_score mismatch: computed 10.0, record states 9.9"
    [top] = validate_records.check_aivss_arithmetic(record(top=7.0))
    assert top == "top-level aivss_score (7.0) does not match aivss.aivss_score (10.0)"


def test_aars_is_allowed_the_rounding_that_storing_it_implies_and_no_more():
    factors = {name: 0 for name in validate_records.AARF_FACTORS} | {"autonomy": 1, "tool_use": 1, "multi_agent": 1, "context": 0.5}
    exact = Decimal("2.74995")
    assert validate_records.check_aivss_arithmetic(record(1.9, factors, 0.97, aars=2.75, score=4.6)) == []
    assert validate_records.check_aivss_arithmetic(record(1.9, factors, 0.97, aars=2.7499, score=4.6)) == []
    assert len(validate_records.check_aivss_arithmetic(record(1.9, factors, 0.97, aars=2.7498, score=4.6))) == 1
    assert exact - Decimal("2.7499") == Decimal("0.00005")


def test_a_missing_scoring_field_or_a_non_numeric_factor_is_named():
    r = record()
    del r["aivss"]["thm"]
    assert validate_records.check_aivss_arithmetic(r) == ["aivss missing scoring field(s): thm"]
    r = record()
    r["aivss"]["aarf"]["autonomy"] = "1"
    assert validate_records.check_aivss_arithmetic(r) == ["aivss.aarf holds a value that is not a number"]
    r = record()
    r["aivss"]["aarf"]["autonomy"] = True
    assert validate_records.check_aivss_arithmetic(r) == ["aivss.aarf holds a value that is not a number"]


def test_a_record_without_aivss_or_aarf_has_nothing_to_compute():
    assert validate_records.check_aivss_arithmetic({"schema_version": "2.0.0", "status": "draft"}) == []
    assert validate_records.check_aivss_arithmetic({"schema_version": "2.0.0", "aivss": {"cvss_base": 5}}) == []
    assert validate_records.check_aivss_arithmetic({"schema_version": "2.0.0", "aivss": "n/a"}) == []


def test_the_schema_version_a_record_declares_picks_the_equation():
    # Schema 1.x: ((cvss_base + aars) / 2) x thm x mitigation_factor with aars the sum of the factors.
    # Here ((8.0 + 2) / 2) x 1 x 1 = 5.0.
    v1 = {"schema_version": "1.3.0", "aivss_score": 5.0,
          "aivss": {"cvss_base": 8.0, "thm": 1, "mitigation_factor": 1, "aarf": {"autonomy": 1, "tool_use": 1}, "aars": 2, "aivss_score": 5.0}}
    assert validate_records.check_aivss_arithmetic(v1) == []

    # The same numbers declared as 2.0.0 are not a v0.8 score: the uplift is (10 - 8) x (2 / 10) x 1 = 0.4 and the score 8.4.
    v08 = copy.deepcopy(v1)
    v08["schema_version"] = "2.0.0"
    errors = validate_records.check_aivss_arithmetic(v08)
    assert any(e.startswith("aivss.aars mismatch: computed 0.4000") for e in errors)
    assert any(e.startswith("aivss.aivss_score mismatch: computed 8.4") for e in errors)

    # and a 1.x record is not held to the v0.8 equation
    v1["aivss"]["aivss_score"] = v1["aivss_score"] = 8.4
    assert validate_records.check_aivss_arithmetic(v1) != []


# --- the schema ---------------------------------------------------------------------------------

def aivss_errors(aivss):
    sub = {"$schema": SCHEMA["$schema"], **SCHEMA["properties"]["aivss"]}
    return [e.message for e in jsonschema.Draft202012Validator(sub).iter_errors(aivss)]


def good_aivss():
    return record(cvss=8.0, factors=FULL)["aivss"] | {"spec_version": "0.8"}


def test_the_schema_accepts_a_v08_object():
    assert aivss_errors(good_aivss()) == []


def test_the_schema_requires_all_ten_factors_and_the_aarf_object():
    a = good_aivss()
    del a["aarf"]["opacity"]
    assert any("opacity" in e for e in aivss_errors(a))
    a = good_aivss()
    del a["aarf"]
    assert any("aarf" in e for e in aivss_errors(a))


@pytest.mark.parametrize("removed", ["data_access", "external_dependencies"])
def test_the_two_factors_schema_1_x_scored_are_no_longer_accepted(removed):
    a = good_aivss()
    a["aarf"][removed] = 1
    assert any(removed in e for e in aivss_errors(a))


@pytest.mark.parametrize("bad", [0.3, 0.75, 1.5, -1])
def test_a_factor_is_0_half_or_1(bad):
    a = good_aivss()
    a["aarf"]["autonomy"] = bad
    assert aivss_errors(a)


@pytest.mark.parametrize("good", [0, 0.5, 1, 1.0])
def test_a_factor_accepts_the_three_points(good):
    a = good_aivss()
    a["aarf"]["autonomy"] = good
    assert aivss_errors(a) == []


@pytest.mark.parametrize("thm, accepted", [(0.5, True), (0.97, True), (1, True), (1.0, True), (0.75, False), (0.9, False), (1.5, False)])
def test_thm_is_one_of_the_three_exploit_maturity_values(thm, accepted):
    a = good_aivss()
    a["thm"] = thm
    assert (aivss_errors(a) == []) is accepted


@pytest.mark.parametrize("mf, accepted", [(0.67, True), (0.83, True), (1, True), (0.5, False), (0, False), (0.9, False)])
def test_mitigation_factor_is_one_of_the_three_strengths(mf, accepted):
    a = good_aivss()
    a["mitigation_factor"] = mf
    assert (aivss_errors(a) == []) is accepted


def test_schema_2_0_0_differs_from_1_3_0_only_in_the_aivss_object_and_its_version_strings():
    old = json.loads(Path("schema/ave-record-1.3.0.schema.json").read_text(encoding="utf-8"))
    new = SCHEMA

    def rest(s):
        s = copy.deepcopy(s)
        s["properties"].pop("aivss")
        for key in ("$id", "description"):
            s.pop(key)
        s["properties"]["schema_version"].pop("description")
        s["properties"]["schema_version"].pop("examples")
        return s

    assert rest(old) == rest(new)
    assert new["$id"].endswith("ave-record-2.0.0.schema.json")
    assert new["properties"]["schema_version"]["examples"] == ["2.0.0"]


def test_the_alias_is_the_2_0_0_file_byte_for_byte():
    assert Path("schema/ave-record.schema.json").read_bytes() == Path("schema/ave-record-2.0.0.schema.json").read_bytes()


# --- the corpus -------------------------------------------------------------------------------

def test_every_record_declares_2_0_0_and_scores_as_v08():
    assert RECORDS
    for path in RECORDS:
        rec = json.loads(path.read_text(encoding="utf-8"))
        assert rec["schema_version"] == "2.0.0", path.name
        assert validate_records.check_aivss_arithmetic(rec) == [], path.name
        assert list(rec["aivss"]["aarf"]) == list(validate_records.AARF_FACTORS), path.name
        assert rec["aivss"]["spec_version"] == "0.8", path.name


def test_a_changed_severity_is_recorded_in_revisions_with_the_old_and_new_value():
    old = {r["ave_id"]: r for r in json.loads(Path("dist/ave-records-v1.3.0.json").read_text(encoding="utf-8"))}
    for path in RECORDS:
        rec = json.loads(path.read_text(encoding="utf-8"))
        before = old[rec["ave_id"]]
        entries = {e["field"]: e for e in rec.get("revisions", []) if e["reason_code"] == "score_revised"}
        assert entries["aivss_score"]["from"] == before["aivss_score"], path.name
        assert entries["aivss_score"]["to"] == rec["aivss_score"], path.name
        if rec["severity"] != before["severity"]:
            assert entries["severity"]["from"] == before["severity"] and entries["severity"]["to"] == rec["severity"], path.name
        else:
            assert "severity" not in entries, path.name
