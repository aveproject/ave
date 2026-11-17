"""scripts/vector_sensitivity.py: the CVSS vector counts and the sensitivity of the bands.

The script needs the `cvss` package, which is not a declared dependency of this repository, so these tests are skipped
where it is not installed (pip install cvss).
"""

import json

import pytest

pytest.importorskip("cvss")

from scripts import aivss_v08 as av  # noqa: E402
from scripts import vector_sensitivity as vs  # noqa: E402

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"        # computes to 9.3
ALL_H = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"      # computes to 10.0
INVALID = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"    # UI:R is a CVSS 3.1 value, not v4.0


def write_records(directory, rows):
    """rows: (number, component_type, vector); writes records/AVE-2026-NNNNN.json files holding only what the script reads."""
    for number, component_type, vector in rows:
        record = {"ave_id": f"AVE-2026-{number:05d}", "cvss_base_vector": vector}
        if component_type is not None:
            record["component_type"] = component_type
        (directory / f"AVE-2026-{number:05d}.json").write_text(json.dumps(record), encoding="utf-8")
    return directory


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    write_records(tmp_path, [(1, "skill", BASE), (2, "mcp_server", ALL_H), (3, "skill", INVALID)])
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    return tmp_path


def spread(factor_sum):
    """Ten factors, each 0, 0.5 or 1, that add to `factor_sum`."""
    vals = [1.0] * int(factor_sum // 1) + ([0.5] if factor_sum % 1 else [])
    return dict(zip(av.FACTORS, vals + [0.0] * (10 - len(vals))))


@pytest.mark.parametrize("score,band", [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"), (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW")])
def test_the_base_band_follows_first_s_rating_scale(score, band):
    assert vs.base_band(score) == band


def test_with_metrics_replaces_only_the_named_metrics_and_keeps_the_order():
    changed = vs.with_metrics(BASE, UI="P", SC="H")
    assert changed == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N"
    assert vs.with_metrics(BASE) == BASE


@pytest.mark.parametrize("base,fs,thm,mit", [(3.9, 5.0, "attacked", "none"), (1.0, 8.5, "attacked", "none"), (6.0, 7.0, "poc", "partial"),
                                              (9.3, 7.0, "unreported", "strong"), (0.0, 0.0, "poc", "none"), (10.0, 10.0, "attacked", "partial")])
def test_the_score_agrees_with_the_aivss_arithmetic_module(base, fs, thm, mit):
    assert vs.score(base, fs, thm, mit) == av.score(base, spread(fs), thm, mit)


def test_the_score_rounds_an_exact_tie_up():
    assert vs.score(3.9, 5.0, "attacked", "none") == 7.0            # raw 6.95; a float product gives 6.9


def test_load_keeps_the_valid_vectors_with_their_computed_base_and_skips_the_invalid_one(corpus):
    assert vs.load() == [("AVE-2026-00001", "skill", BASE, 9.3), ("AVE-2026-00002", "mcp_server", ALL_H, 10.0)]


def test_part_1_reports_the_counts_the_conformance_statement_quotes(corpus, capsys):
    vs.main()
    first = capsys.readouterr().out.splitlines()[0]
    assert first == "1. Reproduction: 2 valid vectors; base >= 9.0: 2; >= 7.0: 2; median 9.65; any of SC/SI/SA High: 1"


def test_part_3_measures_what_removing_the_subsequent_system_impact_does(corpus, capsys):
    vs.main()
    out = capsys.readouterr().out
    line = next(x for x in out.splitlines() if x.startswith("3. Subsequent System"))
    assert "changes 1 records, median drop 0.7, max 0.7, base band changes 0" in line     # 10.0 becomes 9.3, both CRITICAL
    assert "SC=H 1, SI=H 1, SA=H 1" in line and "2 distinct (SC,SI,SA) combinations" in line


def test_part_2_counts_the_records_that_have_the_assumption_and_how_far_the_base_falls(corpus, capsys):
    from cvss import CVSS4

    vs.main()
    out = capsys.readouterr().out
    row = next(x for x in out.splitlines() if x.strip().startswith("UI:N -> P"))
    # expected, computed here with the library directly: both valid records have UI:N
    drops = [float(CVSS4(v).base_score) - float(CVSS4(vs.with_metrics(v, UI="P")).base_score) for v in (BASE, ALL_H)]
    flips = sum(vs.base_band(float(CVSS4(v).base_score)) != vs.base_band(float(CVSS4(vs.with_metrics(v, UI="P")).base_score)) for v in (BASE, ALL_H))
    assert row.split()[3:] == ["2", f"{sorted(drops)[0] / 2 + sorted(drops)[1] / 2:.1f}", f"{max(drops):.1f}", str(flips)]
    assert flips == 1                                                  # 9.3 falls to HIGH, 10.0 stays CRITICAL


def test_part_4_reports_each_component_type_that_has_records(corpus, capsys):
    vs.main()
    out = capsys.readouterr().out
    assert any(x.strip().startswith("mcp_server") and " 1 records" in x for x in out.splitlines())
    assert any(x.strip().startswith("skill") and " 1 records" in x for x in out.splitlines())
    assert not any(x.strip().startswith("agent") for x in out.splitlines())


def test_a_corpus_with_no_valid_vector_does_not_crash(tmp_path, monkeypatch, capsys):
    write_records(tmp_path, [(1, "skill", INVALID)])
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    vs.main()
    assert "no record has a valid CVSS v4.0 vector" in capsys.readouterr().out


def test_a_corpus_without_the_tested_metric_values_does_not_crash(tmp_path, monkeypatch, capsys):
    write_records(tmp_path, [(1, "skill", BASE)])           # no record has SC:H, so the SC and SI tests have nothing to measure
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    vs.main()
    out = capsys.readouterr().out
    row = next(x for x in out.splitlines() if x.strip().startswith("SC:H -> L"))
    assert row.split()[3:6] == ["0", "-", "-"]
    assert "changes 0 records, median drop 0.0, max 0.0" in out


# A richer corpus whose expected figures are computed here, with the `cvss` package and the aivss_v08 module, and not copied
# from the script's own output. The vectors are the pilot's and OWASP's 3.6.10 example, so the bases are real: 5.9, 5.1, 7.0,
# 2.1, 9.4, 7.2, and a vector whose only High subsequent metric is SA.
RICH = [
    (1, "skill", "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    (2, "mcp_server", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"),
    (3, "agent", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"),
    (4, "skill", "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"),
    (5, "skill", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    (6, "skill", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N"),
    (7, "mcp_server", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H"),
]
FACTOR_RANGE = {"skill": (4.0, 10.0), "agent": (4.0, 10.0), "mcp_server": (3.0, 9.0)}


@pytest.fixture
def rich(tmp_path, monkeypatch):
    write_records(tmp_path, RICH)
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    return [(f"AVE-2026-{n:05d}", ct, v, float(__import__("cvss").CVSS4(v).base_score)) for n, ct, v in RICH]


def test_part_1_thresholds_and_the_subsequent_system_test_use_all_three_metrics(rich, capsys):
    vs.main()
    first = capsys.readouterr().out.splitlines()[0]
    bases = sorted(r[3] for r in rich)
    expected_median = bases[len(bases) // 2]
    assert f"{len(rich)} valid vectors; base >= 9.0: {sum(b >= 9 for b in bases)}; >= 7.0: {sum(b >= 7 for b in bases)}; median {expected_median}; any of SC/SI/SA High: 2" in first
    assert sum(7 <= b < 8 for b in bases) == 3 and sum(b >= 9 for b in bases) == 1     # the corpus separates 7 from 8 and 9 from 10


def test_part_3_counts_a_band_change_when_the_subsequent_impact_is_removed(rich, capsys):
    from cvss import CVSS4

    vs.main()
    line = next(x for x in capsys.readouterr().out.splitlines() if x.startswith("3. Subsequent System"))
    drops, flips = [], 0
    for _, _, v, base in rich:
        nb = float(CVSS4(vs.with_metrics(v, SC="N", SI="N", SA="N")).base_score)
        if nb != base:
            drops.append(base - nb)
            flips += vs.base_band(nb) != vs.base_band(base)
    assert flips == 2                      # 9.4 (CRITICAL) falls to 8.7 (HIGH), and the SA-only vector's 7.7 (HIGH) falls to 0.0 (LOW)
    assert f"changes {len(drops)} records" in line and f"base band changes {flips};" in line
    assert "SC=H 1, SI=H 1, SA=H 2" in line


def independent_part_4(rows, ctype):
    """Part 4 recomputed here with aivss_v08 and the documented ranges: (largest score move, number of records whose band can change)."""
    lo_fs, hi_fs = FACTOR_RANGE[ctype]
    flipped, biggest = set(), 0.0
    for ave_id, _, _, base in (r for r in rows if r[1] == ctype):
        for thm in av.THM:
            for mit in av.MITIGATION:
                fs = lo_fs
                while fs + 1.0 <= 10.0 and fs <= hi_fs:
                    low, high = av.score(base, spread(fs), thm, mit), av.score(base, spread(fs + 1.0), thm, mit)
                    biggest = max(biggest, high - low)
                    if av.band(low) != av.band(high):
                        flipped.add(ave_id)
                    fs += 0.5
    return biggest, len(flipped)


def part_4_lines(out):
    return {x.split()[0]: x for x in out.splitlines() if x.strip().startswith(("skill", "mcp_server", "agent"))}


def test_part_4_matches_an_independent_calculation_for_every_component_type(rich, capsys):
    vs.main()
    lines = part_4_lines(capsys.readouterr().out)
    for ctype in FACTOR_RANGE:
        biggest, flips = independent_part_4(rich, ctype)
        assert f"{sum(1 for r in rich if r[1] == ctype)} records" in lines[ctype]
        assert f"largest score move {biggest:.2f}; records whose band can change: {flips}" in lines[ctype]


def test_part_4_matches_an_independent_calculation_on_the_repository_s_own_records(monkeypatch, capsys):
    # the real records contain the cases the small corpus does not (a band that moves only under Partial or Strong mitigation,
    # the mcp_server range), so this compares against a recomputation, never against fixed counts
    monkeypatch.setattr(vs, "RECORDS", "records")
    rows = vs.load()
    assert len(rows) > 50
    vs.main()
    lines = part_4_lines(capsys.readouterr().out)
    results = {}
    for ctype in FACTOR_RANGE:
        biggest, flips = independent_part_4(rows, ctype)
        results[ctype] = flips
        assert f"{sum(1 for r in rows if r[1] == ctype)} records" in lines[ctype]
        assert f"largest score move {biggest:.2f}; records whose band can change: {flips}" in lines[ctype]
    assert any(results.values())                      # the real corpus has records whose band a one-point Factor_Sum step can move


# D21 (docs/specs/aivss-v0.8-conformance.md): a record is band-sensitive when its band differs between the floor (base x stored
# Mitigation_Factor, Factor_Sum 0) and the ceiling (Factor_Sum 10, threat maturity Attacked 1.00, the same Mitigation_Factor).
LEVEL_OF_FACTOR = {1: "none", 0.83: "partial", 0.67: "strong"}
ZERO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"        # computes to 0.0


def write_with_mitigation(directory, rows):
    """rows: (number, vector, mitigation_factor or None); writes records holding only what the D21 count reads."""
    for number, vector, factor in rows:
        record = {"ave_id": f"AVE-2026-{number:05d}", "cvss_base_vector": vector}
        if factor is not None:
            record["aivss"] = {"mitigation_factor": factor}
        (directory / f"AVE-2026-{number:05d}.json").write_text(json.dumps(record), encoding="utf-8")


def expected_d21(base, factor):
    """D21 recomputed with the aivss_v08 module: True when the band differs between floor and ceiling."""
    level = LEVEL_OF_FACTOR[factor]
    floor, ceiling = av.score(base, spread(0.0), "attacked", level), av.score(base, spread(10.0), "attacked", level)
    return av.band(floor) != av.band(ceiling) if floor >= 0.1 else True


D21_CASES = [                       # (vector, stored mitigation factor, base)
    (RICH[0][2], 1, 5.9), (RICH[0][2], 0.83, 5.9),                   # MEDIUM floor, ceiling 10.0 or 8.3: sensitive
    (RICH[6][2], 1, 7.7), (RICH[6][2], 0.83, 7.7),                   # HIGH floor 7.7 reaches 10.0; floor 6.4 reaches 8.3
    (BASE, 1, 9.3), (BASE, 0.83, 9.3),                               # CRITICAL stays CRITICAL; HIGH 7.7 stays below 8.3 HIGH
    (ALL_H, 1, 10.0), (ALL_H, 0.83, 10.0),                           # 10.0 to 10.0; 8.3 to 8.3
]


@pytest.mark.parametrize("vector,factor,base", D21_CASES)
def test_the_floor_and_ceiling_bands_agree_with_the_aivss_arithmetic_module(vector, factor, base):
    from cvss import CVSS4

    assert float(CVSS4(vector).base_score) == base
    floor, ceiling = vs.d21_floor_ceiling(base, factor)
    level = LEVEL_OF_FACTOR[factor]
    assert floor == av.score(base, spread(0.0), "attacked", level)
    assert ceiling == av.score(base, spread(10.0), "attacked", level)


def test_d21_counts_the_records_whose_band_differs_between_floor_and_ceiling(tmp_path, monkeypatch):
    write_with_mitigation(tmp_path, [(n, vector, factor) for n, (vector, factor, _) in enumerate(D21_CASES, start=1)])
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))

    ids = vs.d21_band_sensitive(vs.load(), vs.load_mitigation())

    expected = [f"AVE-2026-{n:05d}" for n, (_, factor, base) in enumerate(D21_CASES, start=1) if expected_d21(base, factor)]
    assert ids == expected
    assert expected == ["AVE-2026-00001", "AVE-2026-00002", "AVE-2026-00003", "AVE-2026-00004"]      # fixed by hand, not by the script


def test_a_mitigation_level_can_make_a_record_band_insensitive_or_sensitive(tmp_path, monkeypatch):
    # 9.3 is CRITICAL at both ends with no credit, and HIGH at both ends with Partial credit (7.7 and 8.3); 7.7 with Partial credit spans MEDIUM to HIGH.
    write_with_mitigation(tmp_path, [(1, BASE, 1), (2, BASE, 0.83), (3, RICH[6][2], 0.83)])
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    assert vs.d21_band_sensitive(vs.load(), vs.load_mitigation()) == ["AVE-2026-00003"]


def test_a_record_that_stores_no_mitigation_factor_gets_no_credit(tmp_path, monkeypatch):
    write_with_mitigation(tmp_path, [(1, RICH[0][2], None), (2, BASE, None)])
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    assert vs.load_mitigation() == {"AVE-2026-00001": 1, "AVE-2026-00002": 1}
    assert vs.d21_band_sensitive(vs.load(), vs.load_mitigation()) == ["AVE-2026-00001"]


def test_a_floor_below_the_lowest_band_counts_as_band_sensitive_and_does_not_crash(tmp_path, monkeypatch):
    write_with_mitigation(tmp_path, [(1, ZERO, 1)])           # base 0.0 has no band (3.5.2); its ceiling is CRITICAL
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))
    assert vs.d21_band_sensitive(vs.load(), vs.load_mitigation()) == ["AVE-2026-00001"]


def test_the_report_prints_the_d21_count_as_its_own_line_with_the_definition(tmp_path, monkeypatch, capsys):
    write_with_mitigation(tmp_path, [(n, vector, factor) for n, (vector, factor, _) in enumerate(D21_CASES, start=1)])
    monkeypatch.setattr(vs, "RECORDS", str(tmp_path))

    vs.main()

    lines = capsys.readouterr().out.splitlines()
    line = next(x for x in lines if "D21" in x)
    assert line.startswith("   D21 band-sensitive records: 4 of 8 valid vectors")
    for words in ("band differs between", "base x stored Mitigation_Factor at Factor_Sum 0",
                  "Factor_Sum 10 at threat maturity Attacked 1.00"):
        assert words in line
    assert lines.index(line) == 1                              # directly under the reproduction line, which stays first
    assert sum("D21" in x for x in lines) == 1


def test_the_d21_count_on_the_repository_s_own_records_is_recomputed_not_copied(monkeypatch, capsys):
    monkeypatch.setattr(vs, "RECORDS", "records")
    rows, mitigation = vs.load(), vs.load_mitigation()
    expected = [r[0] for r in rows if expected_d21(r[3], float(mitigation[r[0]]))]
    assert vs.d21_band_sensitive(rows, mitigation) == expected
    vs.main()
    assert f"D21 band-sensitive records: {len(expected)} of {len(rows)} valid vectors" in capsys.readouterr().out
