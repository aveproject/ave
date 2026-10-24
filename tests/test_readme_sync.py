"""The README restates values that live in records/: each record's AIVSS score
and severity in the record index, how many records there are, and how many sit
in each severity band. They are edited by hand and nothing checked them
against the records, so when #294 moved AVE-2026-00044 from 6.1 MEDIUM to 8.1
HIGH, its index row and the Stats HIGH and MEDIUM counts kept the old values.
These tests read both sides and fail on drift.

Draft records are left out of the index, the band counts and the totals: the
README asks a draft for a reduced eight-field core only, so it need not carry
a score yet, and a draft listed in the index is reported.
"""
import json
import re
from pathlib import Path

README = Path("README.md")
RECORDS_DIR = Path("records")
BANDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# An index row read strictly: the id in the link text is also the file it links to.
INDEX_ROW = re.compile(
    r"^\| \[(AVE-\d{4}-\d{5})\]\(records/\1\.json\) \| .*? \| (\d+\.\d) \| "
    r"\**(CRITICAL|HIGH|MEDIUM|LOW)\** \|[ \t]*$",
    re.M,
)
# Any line whose first cell holds a record id, linked or not, so a row that is
# there but not in the expected form is reported as unreadable, not as missing.
ANY_INDEX_ROW = re.compile(r"^[ \t]*\|[ \t]*\**\[?(AVE-\d{4}-\d{5})\b", re.M)
STATS_ROW = re.compile(r"^\| (CRITICAL|HIGH|MEDIUM|LOW) \([^)]*\) \| (\d+) \|[ \t]*$", re.M)
TOTAL_ROW = re.compile(r"^\| Total records \| (\d+) \|[ \t]*$", re.M)
BADGE = re.compile(r"img\.shields\.io/badge/records-(\d+)-")
SUMMARY = re.compile(r"<strong>(\d+) records, click to expand</strong>")
ROW_FORM = "| [ID](records/ID.json) | title | N.N | SEVERITY |"


def load_records(directory: Path = RECORDS_DIR) -> tuple[dict, list[str]]:
    records, problems = {}, []
    for path in sorted(directory.glob("AVE-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        ave_id = record.get("ave_id")
        if ave_id in records:
            problems.append(f"{path.name} repeats {ave_id}, already read from another file")
            continue
        records[ave_id] = record
    return records, problems


def scored(records: dict) -> dict:
    return {ave_id: r for ave_id, r in records.items() if r.get("status") != "draft"}


def section(readme: str, heading: str) -> str | None:
    """The text under `## heading`, up to the next level-two heading."""
    match = re.search(rf"^## {re.escape(heading)}[ \t]*$(.*?)(?=^## |\Z)", readme, re.M | re.S)
    return match.group(1) if match else None


def index_drift(readme: str, records: dict) -> list[str]:
    """Every non-draft record has exactly one index row, and the row states the
    record's own aivss.aivss_score and severity."""
    index = section(readme, "Record index")
    if index is None:
        return ["README has no '## Record index' section"]
    rows = [(m.group(1), float(m.group(2)), m.group(3)) for m in INDEX_ROW.finditer(index)]
    read = {ave_id for ave_id, _, _ in rows}
    listed = [m.group(1) for m in ANY_INDEX_ROW.finditer(index)]
    expected = scored(records)

    problems = [f"the index row for {ave_id} could not be read; expected {ROW_FORM}"
                for ave_id in sorted(set(listed) - read)]
    problems += [f"{ave_id} has no row in the README record index"
                 for ave_id in sorted(set(expected) - set(listed))]
    problems += [f"{ave_id} has more than one row in the README record index"
                 for ave_id in sorted({i for i in listed if listed.count(i) > 1})]
    for ave_id, score, severity in rows:
        if ave_id not in records:
            problems.append(f"{ave_id} is in the README record index but not in {RECORDS_DIR}/")
            continue
        if ave_id not in expected:
            problems.append(f"{ave_id} is in the README record index but is a draft; drafts are left out of the index")
            continue
        record = expected[ave_id]
        record_score = record.get("aivss", {}).get("aivss_score")
        record_severity = record.get("severity")
        if record_score is None or record_severity is None:
            problems.append(f"{ave_id} has no aivss.aivss_score or severity to compare its row with")
            continue
        if score != record_score:
            problems.append(f"{ave_id}: README says score {score}, the record says {record_score}")
        if severity != record_severity:
            problems.append(f"{ave_id}: README says {severity}, the record says {record_severity}")
    return problems


def stats_drift(readme: str, records: dict) -> list[str]:
    """The Stats total and per-band counts are the counts of non-draft records."""
    stats = section(readme, "Stats")
    if stats is None:
        return ["README has no '## Stats' section"]
    expected = scored(records)
    counts = {band: 0 for band in BANDS}
    for record in expected.values():
        counts[record.get("severity")] = counts.get(record.get("severity"), 0) + 1

    problems, stated = [], {}
    for m in STATS_ROW.finditer(stats):
        if m.group(1) in stated:
            problems.append(f"Stats states {m.group(1)} more than once")
        stated[m.group(1)] = int(m.group(2))
    for band in BANDS:
        if band not in stated:
            problems.append(f"Stats has no {band} row in the form | {band} (range) | N |")
        elif stated[band] != counts[band]:
            problems.append(f"Stats says {stated[band]} {band}, {RECORDS_DIR}/ holds {counts[band]}")
    totals = TOTAL_ROW.findall(stats)
    if len(totals) != 1:
        problems.append(f"Stats has {len(totals)} 'Total records' rows, expected 1")
    elif int(totals[0]) != len(expected):
        problems.append(f"Stats says {totals[0]} total records, {RECORDS_DIR}/ holds {len(expected)}")
    return problems


def restated_total_drift(readme: str, records: dict) -> list[str]:
    """The records badge and the index summary repeat the total; each must be
    there exactly once and state it."""
    total = len(scored(records))
    problems = []
    for name, found in (("records badge", BADGE.findall(readme)),
                        ("index summary", SUMMARY.findall(section(readme, "Record index") or ""))):
        if len(found) != 1:
            problems.append(f"the README should have one {name}, it has {len(found)}")
        elif int(found[0]) != total:
            problems.append(f"the {name} says {found[0]}, {RECORDS_DIR}/ holds {total}")
    return problems


def every_check(readme: str, records: dict) -> list[str]:
    """Every check the README is held to."""
    return index_drift(readme, records) + stats_drift(readme, records) + restated_total_drift(readme, records)


def readme_drift(readme_path: Path = README, records_dir: Path = RECORDS_DIR) -> list[str]:
    """The whole real-data path: read the records, then run every check on the
    README. The real-data test runs this, and so does a fixture below that
    drifts against each check, so a step left out of it fails that fixture."""
    records, problems = load_records(records_dir)
    return problems + every_check(readme_path.read_text(encoding="utf-8"), records)


def test_readme_matches_records():
    assert readme_drift() == []


# --- each refusal the checks can make is shown, with its own message --------------
#
# A comparison that always finds the two sides equal would pass forever. These run
# each check against a one-record README written here, with the value under test
# made to disagree, so a refusal can only come from it; the cases that must pass
# show the same checks accepting what they should.

RECORD = {"ave_id": "AVE-2026-00001", "status": "active", "severity": "HIGH",
          "aivss": {"aivss_score": 8.0}}
ONE = {"AVE-2026-00001": RECORD}
ROW = "| [AVE-2026-00001](records/AVE-2026-00001.json) | Example | 8.0 | HIGH |"


def readme_with(rows=(ROW,), total=1, high=1, medium=0, badge=1, summary=1, drop_band=None):
    bands = [("CRITICAL", ">= 9.0", 0), ("HIGH", "7.0-8.9", high),
             ("MEDIUM", "4.0-6.9", medium), ("LOW", "< 4.0", 0)]
    return "\n".join([
        f"[![Records](https://img.shields.io/badge/records-{badge}-0f6e56?style=flat-square)](records/)",
        "",
        "## Stats",
        "",
        "| | |",
        "|---|---|",
        f"| Total records | {total} |",
        *[f"| {band} ({span}) | {count} |" for band, span, count in bands if band != drop_band],
        "",
        "## Record index",
        "",
        f"<summary><strong>{summary} records, click to expand</strong></summary>",
        "",
        "| AVE ID | Title | AIVSS | Severity |",
        "|---|---|---|---|",
        *rows,
        "",
        "## Detect with Bawbel Scanner",
        "",
    ])


# cases that must pass

def test_a_readme_that_states_the_records_passes_every_check():
    assert every_check(readme_with(), ONE) == []


def test_a_bold_severity_and_a_trailing_space_are_still_read():
    record = {"AVE-2026-00001": dict(RECORD, severity="CRITICAL", aivss={"aivss_score": 9.2})}
    row = "| [AVE-2026-00001](records/AVE-2026-00001.json) | Example | 9.2 | **CRITICAL** | "

    assert index_drift(readme_with(rows=(row,)), record) == []


def test_a_draft_record_needs_no_row_and_is_not_counted():
    records = dict(ONE, **{"AVE-2026-00002": {"ave_id": "AVE-2026-00002", "status": "draft"}})

    assert every_check(readme_with(), records) == []


def test_rows_outside_their_section_are_not_read():
    stray = "\n".join(["## Recently updated", "",
                       ROW.replace("| 8.0 | HIGH |", "| 6.1 | MEDIUM |"),
                       "| HIGH (7.0-8.9) | 0 |", "| Total records | 5 |",
                       "<strong>9 records, click to expand</strong>", ""])

    assert every_check(readme_with() + stray, ONE) == []


# drift against each check, through the path the real README goes through

def test_a_readme_that_drifts_against_each_check_is_reported_through_the_real_data_path(tmp_path):
    (tmp_path / "records").mkdir()
    for name in ("AVE-2026-00001.json", "AVE-2026-00002.json"):
        (tmp_path / "records" / name).write_text(json.dumps(RECORD), encoding="utf-8")
    row = ROW.replace("| 8.0 |", "| 7.5 |")
    readme = readme_with(rows=(row,), total=2, high=0, medium=1, badge=2, summary=3)
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")

    assert readme_drift(tmp_path / "README.md", tmp_path / "records") == [
        "AVE-2026-00002.json repeats AVE-2026-00001, already read from another file",
        "AVE-2026-00001: README says score 7.5, the record says 8.0",
        "Stats says 0 HIGH, records/ holds 1",
        "Stats says 1 MEDIUM, records/ holds 0",
        "Stats says 2 total records, records/ holds 1",
        "the records badge says 2, records/ holds 1",
        "the index summary says 3, records/ holds 1",
    ]


# the index

def test_a_row_whose_score_lags_its_record_is_reported():
    row = ROW.replace("| 8.0 |", "| 7.5 |")

    assert index_drift(readme_with(rows=(row,)), ONE) == [
        "AVE-2026-00001: README says score 7.5, the record says 8.0"]


def test_a_row_whose_severity_lags_its_record_is_reported():
    row = ROW.replace("| HIGH |", "| MEDIUM |")

    assert index_drift(readme_with(rows=(row,)), ONE) == [
        "AVE-2026-00001: README says MEDIUM, the record says HIGH"]


def test_a_record_with_no_row_is_reported():
    assert index_drift(readme_with(rows=()), ONE) == [
        "AVE-2026-00001 has no row in the README record index"]


def test_a_record_with_two_rows_is_reported():
    assert index_drift(readme_with(rows=(ROW, ROW)), ONE) == [
        "AVE-2026-00001 has more than one row in the README record index"]


def test_a_row_for_an_id_that_is_not_in_records_is_reported():
    assert index_drift(readme_with(), {}) == [
        "AVE-2026-00001 is in the README record index but not in records/"]


def test_a_row_for_a_draft_is_reported():
    draft = {"AVE-2026-00002": {"ave_id": "AVE-2026-00002", "status": "draft"}}
    row = "| [AVE-2026-00002](records/AVE-2026-00002.json) | Draft | 7.0 | HIGH |"

    assert index_drift(readme_with(rows=(ROW, row)), dict(ONE, **draft)) == [
        "AVE-2026-00002 is in the README record index but is a draft; drafts are left out of the index"]


def test_a_record_with_no_score_is_reported():
    record = {"AVE-2026-00001": {"ave_id": "AVE-2026-00001", "status": "active", "severity": "HIGH"}}

    assert index_drift(readme_with(), record) == [
        "AVE-2026-00001 has no aivss.aivss_score or severity to compare its row with"]


def test_a_row_that_is_there_but_unreadable_is_not_reported_as_missing():
    for row in (ROW.replace("| HIGH |", "| High |"),
                ROW.replace("(records/AVE-2026-00001.json)", "(records/AVE-2026-00002.json)"),
                ROW.replace("[AVE-2026-00001](records/AVE-2026-00001.json)", "AVE-2026-00001")):
        assert index_drift(readme_with(rows=(row,)), ONE) == [
            f"the index row for AVE-2026-00001 could not be read; expected {ROW_FORM}"], row


def test_a_missing_index_section_is_reported():
    readme = readme_with().replace("## Record index", "## Records")

    assert index_drift(readme, ONE) == ["README has no '## Record index' section"]


# the Stats block

def test_a_band_count_that_lags_is_reported():
    assert stats_drift(readme_with(high=0, medium=1), ONE) == [
        "Stats says 0 HIGH, records/ holds 1", "Stats says 1 MEDIUM, records/ holds 0"]


def test_a_missing_band_row_is_reported():
    assert stats_drift(readme_with(drop_band="LOW"), ONE) == [
        "Stats has no LOW row in the form | LOW (range) | N |"]


def test_a_band_stated_twice_is_reported():
    readme = readme_with().replace("| LOW (< 4.0) | 0 |", "| LOW (< 4.0) | 0 |\n| LOW (< 4.0) | 0 |")

    assert stats_drift(readme, ONE) == ["Stats states LOW more than once"]


def test_a_wrong_total_is_reported():
    assert stats_drift(readme_with(total=2), ONE) == ["Stats says 2 total records, records/ holds 1"]


def test_a_missing_or_repeated_total_row_is_reported():
    for rows, n in (("", 0), ("| Total records | 1 |\n| Total records | 1 |\n", 2)):
        readme = readme_with().replace("| Total records | 1 |\n", rows)

        assert stats_drift(readme, ONE) == [f"Stats has {n} 'Total records' rows, expected 1"], rows


def test_a_missing_stats_section_is_reported():
    readme = readme_with().replace("## Stats", "## Figures")

    assert stats_drift(readme, ONE) == ["README has no '## Stats' section"]


# the restated totals

def test_a_badge_or_index_summary_that_lags_is_reported():
    assert restated_total_drift(readme_with(badge=2, summary=3), ONE) == [
        "the records badge says 2, records/ holds 1",
        "the index summary says 3, records/ holds 1"]


def test_a_missing_badge_or_index_summary_is_reported():
    readme = readme_with().replace("badge/records-1-", "badge/count-1-").replace("<strong>1 records", "<strong>1 entries")

    assert restated_total_drift(readme, ONE) == [
        "the README should have one records badge, it has 0",
        "the README should have one index summary, it has 0"]


# the records themselves

def test_two_record_files_with_the_same_id_are_reported(tmp_path):
    for name in ("AVE-2026-00001.json", "AVE-2026-00002.json"):
        (tmp_path / name).write_text(json.dumps(RECORD), encoding="utf-8")

    records, problems = load_records(tmp_path)

    assert list(records) == ["AVE-2026-00001"]
    assert problems == ["AVE-2026-00002.json repeats AVE-2026-00001, already read from another file"]
