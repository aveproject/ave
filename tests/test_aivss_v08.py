"""scripts/aivss_v08.py: the OWASP AIVSS v0.8 arithmetic, in exact decimal.

Sources are sections of "AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8" (Part 2): 3.3.1 (AARS),
3.3.2 Table 4a (ThM), 3.4 and 3.4.0 (primary equation), 3.4.1 Table 4b (Mitigation_Factor), 3.5.1 (rounding),
3.5.2 (bands), and the ten worked examples of 3.6, which all use ThM 0.97 and Mitigation_Factor 1.0.
"""

from decimal import Decimal

import pytest

from scripts import aivss_v08 as av

FACTORS = av.FACTORS

# OWASP section 3.6: (section, CVSS base, the ten factors in the specification's order, Factor_Sum, AARS, final score, band).
OWASP_EXAMPLES = [
    ("3.6.1", 9.4, (1, 1, 1, 1, 1, 1, .5, 1, 1, .5), 9.0, "0.5238", 9.9, "CRITICAL"),
    ("3.6.2", 8.7, (1, 1, 1, 1, .5, 1, 1, 1, .5, 0), 8.0, "1.0088", 9.7, "CRITICAL"),
    ("3.6.3", 7.1, (1, .5, 1, 1, 1, 1, .5, .5, 1, .5), 8.0, "2.2504", 9.4, "CRITICAL"),
    ("3.6.4", 9.4, (1, 1, 1, 1, 1, 1, 1, 1, 1, .5), 9.5, "0.5529", 10.0, "CRITICAL"),
    ("3.6.5", 7.4, (1, 1, 1, 1, 1, 1, 0, 1, .5, 0), 7.5, "1.8915", 9.3, "CRITICAL"),
    ("3.6.6", 5.8, (1, .5, 1, 1, .5, 1, 1, 0, .5, 1), 7.5, "3.0555", 8.9, "HIGH"),
    ("3.6.7", 6.9, (1, 1, .5, 1, .5, 1, .5, 0, 1, 1), 7.5, "2.25525", 9.2, "CRITICAL"),
    ("3.6.8", 9.3, (1, 1, 0, 0, 1, 1, .5, 1, 1, 0), 6.5, "0.44135", 9.7, "CRITICAL"),
    ("3.6.9", 5.3, (1, 1, 0, 0, 1, 1, .5, .5, 1, .5), 6.5, "2.96335", 8.3, "HIGH"),
    ("3.6.10", 2.1, (.5, 0, 1, 1, 1, 1, 1, 0, 0, 1), 6.5, "4.98095", 7.1, "HIGH"),
]


def f(**kw):
    d = {k: 0.0 for k in FACTORS}
    d.update(kw)
    return d


def spread(factor_sum):
    """Ten factors, each 0, 0.5 or 1, whose sum is `factor_sum`."""
    vals = [1.0] * int(factor_sum // 1) + ([0.5] if factor_sum % 1 else [])
    return dict(zip(FACTORS, vals + [0.0] * (10 - len(vals))))


@pytest.mark.parametrize("row", OWASP_EXAMPLES, ids=[r[0] for r in OWASP_EXAMPLES])
def test_the_equation_reproduces_each_of_owasps_ten_worked_examples(row):
    _, base, vals, fsum, aars, final, band = row
    a = dict(zip(FACTORS, vals))
    assert av.factor_sum(a) == fsum
    assert av.aars_exact(base, a, "poc") == Decimal(aars)
    assert av.score(base, a, "poc", "none") == final
    assert av.band(final) == band


def test_the_factor_names_are_appendix_a_s():
    assert FACTORS == ("autonomy", "tools", "language", "context", "non_determinism", "opacity", "persistence", "identity", "multi_agent", "self_mod")


def test_an_example_that_is_not_from_the_specification():
    # AVE's own hand check, not one of OWASP's: CVSS 6.0, factor sum 7.0, PoC, partial mitigation: AARS 2.716, AIVSS 7.2 (High).
    a = f(autonomy=1, tools=1, language=1, context=1, non_determinism=1, opacity=1, persistence=1)
    assert av.factor_sum(a) == 7.0
    assert av.aars_exact(6.0, a, "poc") == Decimal("2.716")
    assert av.score(6.0, a, "poc", "partial") == 7.2 and av.band(7.2) == "HIGH"


def test_uplift_is_bounded_by_the_gap_to_ten():
    all1 = {k: 1.0 for k in FACTORS}
    assert av.aars(10.0, all1, "attacked") == 0.0
    assert av.score(9.0, all1, "attacked", "none") == 10.0
    assert av.score(8.5, f(), "attacked", "none") == 8.5          # no agentic factors: the score is the CVSS base


def test_without_mitigation_credit_the_score_is_never_below_the_cvss_base():
    for c in (0.0, 3.3, 5.5, 7.7, 9.9):
        assert av.score(c, f(autonomy=0.5), "poc", "none") >= c


def test_each_threat_multiplier_level_scales_the_uplift():
    all1 = {k: 1.0 for k in FACTORS}                              # gap 5.0, factor sum 10: AARS is gap x ThM
    assert av.aars(5.0, all1, "attacked") == 5.0
    assert av.aars(5.0, all1, "poc") == pytest.approx(4.85)
    assert av.aars(5.0, all1, "unreported") == 2.5


def test_each_mitigation_level_scales_the_score():
    all1 = {k: 1.0 for k in FACTORS}                              # CVSS 6.0, PoC: raw 9.88 before mitigation
    assert [av.score(6.0, all1, "poc", m) for m in ("none", "partial", "strong")] == [9.9, 8.2, 6.6]


def test_the_constants_are_the_specifications():
    assert av.THM == {"attacked": Decimal("1.00"), "poc": Decimal("0.97"), "unreported": Decimal("0.50")}
    assert av.MITIGATION == {"none": Decimal("1.00"), "partial": Decimal("0.83"), "strong": Decimal("0.67")}
    assert av.FACTOR_LEVELS == (Decimal("0.0"), Decimal("0.5"), Decimal("1.0"))


def test_inputs_outside_the_specification_are_refused():
    with pytest.raises(ValueError):
        av.factor_sum(f(autonomy=0.3))
    with pytest.raises(ValueError):
        av.factor_sum({"autonomy": 1.0})
    with pytest.raises(ValueError):
        av.factor_sum({**f(), "data_access": 1.0})                 # an eleventh key
    with pytest.raises(KeyError):
        av.aars(5.0, f(), "theoretical")
    with pytest.raises(KeyError):
        av.score(5.0, f(), "poc", "weak")
    for bad in (-0.1, 10.1):
        with pytest.raises(ValueError):
            av.aars(bad, f(), "poc")


@pytest.mark.parametrize("raw,expected", [(8.64, 8.6), (8.65, 8.7)])
def test_the_specifications_own_rounding_examples(raw, expected):
    assert av.r1(raw) == expected                                  # 3.5.1


def test_rounding_is_half_up_and_not_ties_to_even():
    assert av.r1(7.25) == 7.3 and av.r1(7.35) == 7.4 and av.r1(0.05) == 0.1 and av.r1(8.25) == 8.3


@pytest.mark.parametrize("cvss,fsum,thm,mit,expected", [
    (1.0, 8.5, "attacked", "none", 8.7),         # raw 8.65 exactly; a float product gives 8.6
    (0.0, 5.0, "attacked", "partial", 4.2),      # raw 4.15
    (1.0, 1.5, "attacked", "none", 2.4),         # raw 2.35
    (3.9, 5.0, "attacked", "none", 7.0),         # raw 6.95: a float product gives 6.9 MEDIUM, the exact result is 7.0 HIGH
])
def test_exact_ties_round_up_the_way_the_specification_says(cvss, fsum, thm, mit, expected):
    assert av.factor_sum(spread(fsum)) == fsum
    assert av.score(cvss, spread(fsum), thm, mit) == expected
    if expected == 7.0:
        assert av.band(expected) == "HIGH"


def test_the_score_comes_from_the_unrounded_uplift_not_the_stored_four_decimals():
    # AARS is exactly 2.74995 (five places). Rounded to four places it is 2.7500, which would give 4.65 and round up to 4.7.
    a = f(autonomy=1, tools=1, multi_agent=1, context=0.5)
    assert av.aars_exact(1.9, a, "poc") == Decimal("2.74995") and av.factor_sum(a) == 3.5
    assert av.score(1.9, a, "poc", "none") == 4.6


def test_an_exact_uplift_never_needs_more_than_five_decimal_places():
    most = 0
    for c10 in range(0, 101):
        for k in range(0, 21):
            for thm in av.THM:
                exp = -av.aars_exact(c10 / 10, spread(k / 2), thm).normalize().as_tuple().exponent
                most = max(most, exp)
    assert most == 5


def test_bands():
    assert [av.band(x) for x in (10.0, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1)] == ["CRITICAL", "CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "LOW"]


def test_a_score_below_0_1_has_no_band_in_the_specification():
    with pytest.raises(ValueError):
        av.band(0.0)
