"""The revisions ratchet (issue #382): a record's revisions are append-only, and a change
to severity, status or the derived verification_basis since the merge base carries a
revisions entry that says so. validate_records.py sees one record at a time; these checks
need the base version of each record, so every test builds a real git repository with a
base commit and a head commit.
"""
import json
import subprocess

import pytest

from scripts import check_revisions_ratchet as ratchet

ID = "AVE-2026-00001"


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def entry(field, old, new, code="declaration_corrected", date="2026-10-29"):
    return {"date": date, "field": field, "from": old, "to": new, "reason_code": code}


def record(ave_id=ID, **overrides):
    """A published record: severity, status and the three inputs of verification_basis."""
    base = {
        "ave_id": ave_id, "schema_version": "1.3.0", "status": "active", "severity": "MEDIUM",
        "title": "t", "description": "d",
        "evidence_basis_engines": ["pattern"],
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not _ABSENT}


_ABSENT = object()


def write(repo, rec):
    (repo / "records").mkdir(exist_ok=True)
    (repo / "records" / f"{rec['ave_id']}.json").write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")


def commit(repo, message="change"):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A repository on branch main with no records yet, and the working directory set to it."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.org")
    _git(tmp_path, "config", "user.name", "T")
    (tmp_path / "README.md").write_text("fixture\n", encoding="utf-8")
    commit(tmp_path, "init")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def base_then_head(repo, before, after):
    """Commit BEFORE on main, tag it `base`, then commit AFTER on top; return the problems found."""
    write(repo, before)
    commit(repo, "base")
    _git(repo, "tag", "base")
    write(repo, after)
    commit(repo, "head")
    return ratchet.check("base")


# --- rule 1: revisions are append-only --------------------------------------------------

def test_an_appended_entry_passes(repo):
    first = entry("severity", "LOW", "MEDIUM", date="2026-10-01")
    problems = base_then_head(
        repo, record(revisions=[first]),
        record(revisions=[first, entry("severity", "MEDIUM", "HIGH")], severity="HIGH"),
    )
    assert problems == []


def test_a_first_revisions_array_passes(repo):
    problems = base_then_head(
        repo, record(), record(severity="HIGH", revisions=[entry("severity", "MEDIUM", "HIGH")]))
    assert problems == []


def test_an_edited_entry_is_refused(repo):
    first = entry("severity", "LOW", "MEDIUM", date="2026-10-01")
    edited = dict(first, reason_code="score_revised")
    problems = base_then_head(repo, record(revisions=[first]), record(revisions=[edited]))
    assert problems == [f"{ID}: revisions[0] was edited; revisions are append-only"]


def test_a_removed_entry_is_refused(repo):
    a = entry("severity", "LOW", "MEDIUM", date="2026-10-01")
    b = entry("severity", "MEDIUM", "HIGH", date="2026-10-15")
    problems = base_then_head(repo, record(severity="HIGH", revisions=[a, b]), record(severity="HIGH", revisions=[a]))
    assert problems == [f"{ID}: 1 earlier revisions entry was removed; revisions are append-only"]


def test_a_dropped_array_is_refused(repo):
    a = entry("severity", "LOW", "MEDIUM", date="2026-10-01")
    problems = base_then_head(repo, record(revisions=[a]), record())
    assert problems == [f"{ID}: the revisions array was removed; revisions are append-only"]


def test_reordered_entries_are_refused(repo):
    a = entry("severity", "LOW", "MEDIUM", date="2026-10-01")
    b = entry("severity", "MEDIUM", "HIGH", date="2026-10-15")
    problems = base_then_head(
        repo, record(severity="HIGH", revisions=[a, b]), record(severity="HIGH", revisions=[b, a]))
    assert problems == [
        f"{ID}: revisions[0] was edited; revisions are append-only",
        f"{ID}: revisions[1] was edited; revisions are append-only",
    ]


def test_whitespace_changes_to_an_entry_are_not_an_edit(repo):
    a = entry("severity", "LOW", "MEDIUM", date="2026-10-01")
    write(repo, record(revisions=[a]))
    commit(repo, "base")
    _git(repo, "tag", "base")
    (repo / "records" / f"{ID}.json").write_text(json.dumps(record(revisions=[a]), separators=(",", ":")), encoding="utf-8")
    commit(repo, "head")
    assert ratchet.check("base") == []


# --- rule 2: severity and status -------------------------------------------------------

def test_a_severity_change_without_an_entry_is_refused(repo):
    problems = base_then_head(repo, record(), record(severity="HIGH"))
    assert problems == [
        f"{ID}: severity changed from 'MEDIUM' to 'HIGH' with no revisions entry for it: "
        "append {field: severity, from: 'MEDIUM', to: 'HIGH', reason_code, date}"
    ]


def test_a_severity_change_with_a_matching_entry_passes(repo):
    problems = base_then_head(
        repo, record(), record(severity="HIGH", revisions=[entry("severity", "MEDIUM", "HIGH", "score_revised")]))
    assert problems == []


@pytest.mark.parametrize("wrong", [
    entry("severity", "LOW", "HIGH"),        # from is not the base value
    entry("severity", "MEDIUM", "CRITICAL"),  # to is not the head value
    entry("status", "MEDIUM", "HIGH"),        # an entry for a different field
])
def test_an_entry_that_does_not_match_the_change_is_refused(repo, wrong):
    problems = base_then_head(repo, record(), record(severity="HIGH", revisions=[wrong]))
    assert len(problems) == 1 and "severity changed from 'MEDIUM' to 'HIGH'" in problems[0]


def test_two_changes_in_one_push_pass_with_a_chain_of_entries(repo):
    chain = [entry("severity", "MEDIUM", "HIGH", date="2026-10-20"), entry("severity", "HIGH", "CRITICAL", date="2026-10-25")]
    assert base_then_head(repo, record(), record(severity="CRITICAL", revisions=chain)) == []


def test_a_chain_that_does_not_reach_the_head_value_is_refused(repo):
    chain = [entry("severity", "MEDIUM", "HIGH", date="2026-10-20"), entry("severity", "HIGH", "LOW", date="2026-10-25")]
    problems = base_then_head(repo, record(), record(severity="CRITICAL", revisions=chain))
    assert len(problems) == 1


def test_an_entry_from_before_the_base_does_not_explain_a_new_change(repo):
    stale = entry("severity", "MEDIUM", "HIGH", date="2026-09-01")  # already there; the value was edited back by hand
    problems = base_then_head(repo, record(revisions=[stale]), record(severity="HIGH", revisions=[stale]))
    assert len(problems) == 1 and "severity changed from 'MEDIUM' to 'HIGH'" in problems[0]


def test_a_chain_with_a_gap_is_refused(repo):
    chain = [entry("severity", "MEDIUM", "HIGH", date="2026-10-20"), entry("severity", "LOW", "CRITICAL", date="2026-10-25")]
    assert len(base_then_head(repo, record(), record(severity="CRITICAL", revisions=chain))) == 1


def test_a_change_and_its_reversal_need_no_entry(repo):
    assert base_then_head(repo, record(), record(severity="MEDIUM", title="renamed")) == []


def test_a_status_change_without_an_entry_is_refused(repo):
    problems = base_then_head(repo, record(), record(status="deprecated"))
    assert problems == [
        f"{ID}: status changed from 'active' to 'deprecated' with no revisions entry for it: "
        "append {field: status, from: 'active', to: 'deprecated', reason_code, date}"
    ]


def test_a_status_change_with_a_matching_entry_passes(repo):
    after = record(status="merged", merged_into="AVE-2026-00002", revisions=[entry("status", "active", "merged", "status_changed")])
    assert base_then_head(repo, record(), after) == []


def test_an_unrelated_field_change_passes(repo):
    assert base_then_head(repo, record(), record(description="rewritten", title="renamed")) == []


# --- rule 2: the derived verification_basis -------------------------------------------

SUBSTRATE = {"evidence_vantage": "substrate", "evidence_basis_engines": ["pattern", "external_authority"]}


def test_a_derived_basis_change_without_an_entry_is_refused(repo):
    problems = base_then_head(
        repo, record(evidence_basis_engines=["pattern", "external_authority"]), record(**SUBSTRATE))
    assert len(problems) == 1
    assert problems[0].startswith(
        f"{ID}: the derived verification_basis changed from 'artifact_reconstructed' to 'substrate_reconstructed'")


def test_a_derived_basis_change_is_explained_by_an_entry_for_the_declaration_that_changed(repo):
    """AVE-2026-00074's own shape: the entry names evidence_vantage, the cause."""
    after = record(**SUBSTRATE, revisions=[entry("evidence_vantage", None, "substrate", "declaration_added")])
    assert base_then_head(repo, record(evidence_basis_engines=["pattern", "external_authority"]), after) == []


def test_a_derived_basis_change_is_explained_by_an_entry_for_verification_basis_itself(repo):
    """The shape vocabulary_member_added and derivation_rule_changed need: no declaration changed."""
    after = record(**SUBSTRATE, verification_basis="substrate_reconstructed",
                   revisions=[entry("verification_basis", "artifact_reconstructed", "substrate_reconstructed", "derivation_rule_changed")])
    assert base_then_head(repo, record(evidence_basis_engines=["pattern", "external_authority"]), after) == []


def test_a_verification_basis_entry_may_start_from_an_absent_stored_value(repo):
    after = record(**SUBSTRATE, verification_basis="substrate_reconstructed",
                   revisions=[entry("verification_basis", None, "substrate_reconstructed", "declaration_added")])
    assert base_then_head(repo, record(evidence_basis_engines=["pattern", "external_authority"]), after) == []


def test_a_declaration_entry_with_the_wrong_values_does_not_explain_the_change(repo):
    after = record(**SUBSTRATE, revisions=[entry("evidence_vantage", "artifact", "substrate", "declaration_corrected")])
    problems = base_then_head(repo, record(evidence_basis_engines=["pattern", "external_authority"]), after)
    assert len(problems) == 1 and "derived verification_basis changed" in problems[0]


def test_every_declaration_that_changed_needs_its_own_entry_without_a_verification_basis_entry(repo):
    before = record(evidence_basis_engines=["pattern", "external_authority"], evidence_vantage="artifact", evidence_method="reconstructed")
    after = record(evidence_basis_engines=["pattern", "external_authority"], evidence_vantage="substrate", evidence_method="intercepted",
                   revisions=[entry("evidence_vantage", "artifact", "substrate")])
    problems = base_then_head(repo, before, after)
    assert len(problems) == 1 and "evidence_method" in problems[0]


def test_a_declaration_change_that_leaves_the_derived_basis_alone_needs_no_entry(repo):
    # no substrate-capable engine, so a declared substrate vantage cannot raise the derived basis
    assert base_then_head(repo, record(), record(evidence_vantage="substrate")) == []


def test_adding_an_artifact_engine_needs_no_entry(repo):
    assert base_then_head(repo, record(), record(evidence_basis_engines=["pattern", "yara"])) == []


def test_the_derived_value_is_compared_not_the_stored_one(repo):
    # a stored verification_basis that does not change, while the axes that derive it do
    before = record(evidence_basis_engines=["pattern", "external_authority"], verification_basis="artifact_reconstructed")
    after = record(**SUBSTRATE, verification_basis="artifact_reconstructed")
    problems = base_then_head(repo, before, after)
    assert len(problems) == 1 and "derived verification_basis changed" in problems[0]


# --- exemptions and scope --------------------------------------------------------------

def test_a_new_record_is_exempt(repo):
    write(repo, record("AVE-2026-00002"))
    commit(repo, "base")
    _git(repo, "tag", "base")
    write(repo, record("AVE-2026-00003", severity="CRITICAL", status="active", **SUBSTRATE))
    commit(repo, "head")
    assert ratchet.check("base") == []


def test_a_record_that_was_a_draft_at_the_base_is_exempt(repo):
    before = record(status="draft", severity=_ABSENT)
    assert base_then_head(repo, before, record(status="active", severity="HIGH")) == []


def test_only_records_changed_since_the_base_are_checked(repo):
    write(repo, record("AVE-2026-00002"))
    write(repo, record("AVE-2026-00003"))
    commit(repo, "base")
    _git(repo, "tag", "base")
    write(repo, record("AVE-2026-00003", severity="HIGH"))
    commit(repo, "head")
    problems = ratchet.check("base")
    assert [p.split(":")[0] for p in problems] == ["AVE-2026-00003"]


def test_files_outside_records_are_ignored(repo):
    (repo / "notes").mkdir()
    (repo / "notes" / "AVE-2026-00001.json").write_text(json.dumps(record()), encoding="utf-8")
    commit(repo, "base")
    _git(repo, "tag", "base")
    (repo / "notes" / "AVE-2026-00001.json").write_text(json.dumps(record(severity="HIGH")), encoding="utf-8")
    commit(repo, "head")
    assert ratchet.check("base") == []


def test_a_change_with_no_records_passes(repo):
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    commit(repo, "base")
    _git(repo, "tag", "base")
    (repo / "README.md").write_text("changed again\n", encoding="utf-8")
    commit(repo, "head")
    assert ratchet.check("base") == []


def test_every_record_is_checked_and_reported(repo):
    write(repo, record("AVE-2026-00002"))
    write(repo, record("AVE-2026-00003"))
    commit(repo, "base")
    _git(repo, "tag", "base")
    write(repo, record("AVE-2026-00002", severity="HIGH"))
    write(repo, record("AVE-2026-00003", status="deprecated"))
    commit(repo, "head")
    assert [p.split(":")[0] for p in ratchet.check("base")] == ["AVE-2026-00002", "AVE-2026-00003"]


def test_a_head_ref_other_than_HEAD_is_read(repo):
    write(repo, record())
    commit(repo, "base")
    _git(repo, "tag", "base")
    write(repo, record(severity="HIGH"))
    commit(repo, "one")
    _git(repo, "tag", "one")
    write(repo, record(severity="LOW"))
    commit(repo, "two")
    found = ratchet.check("base", "one")
    assert len(found) == 1 and "'MEDIUM' to 'HIGH'" in found[0]
    assert len(ratchet.check("base", "HEAD")) == 1 and "'MEDIUM' to 'LOW'" in ratchet.check("base", "HEAD")[0]


# --- the three-dot form: a base that moved ---------------------------------------------

def _moved_base(repo):
    """main holds record 1 with severity MEDIUM. A branch starts there and does not touch it.
    Then main moves on: record 1 goes to HIGH, with its entry. Returns nothing; HEAD is the branch."""
    write(repo, record())
    commit(repo, "fork point")
    _git(repo, "branch", "topic")
    write(repo, record(severity="HIGH", revisions=[entry("severity", "MEDIUM", "HIGH", "score_revised")]))
    commit(repo, "main moves on")
    _git(repo, "checkout", "-q", "topic")
    (repo / "README.md").write_text("topic work\n", encoding="utf-8")
    write(repo, record("AVE-2026-00009"))
    commit(repo, "topic")


def test_a_base_that_moved_is_not_the_changes_own(repo):
    _moved_base(repo)
    assert ratchet.check("main") == []


def test_a_record_both_sides_edited_is_compared_with_its_merge_base_version(repo):
    """main rescored record 1 (with its entry) after the fork; the branch only fixed its title.
    The branch's change is the title, so there is nothing to explain: against main's tip it would
    look as though the branch had undone the rescore and dropped its entry."""
    write(repo, record())
    commit(repo, "fork point")
    _git(repo, "branch", "topic")
    write(repo, record(severity="HIGH", revisions=[entry("severity", "MEDIUM", "HIGH", "score_revised")]))
    commit(repo, "main moves on")
    _git(repo, "checkout", "-q", "topic")
    write(repo, record(title="a better title"))
    commit(repo, "topic")
    assert ratchet.inspect("main") == (1, [])


def test_only_the_branchs_own_records_are_listed_when_the_base_moved(repo):
    _moved_base(repo)
    assert ratchet.inspect("main")[0] == 1  # AVE-2026-00009; record 1 changed on main, not here


def test_a_two_dot_comparison_would_blame_the_branch_for_the_base(repo):
    """Why the merge base matters: against the moved tip of main, the branch looks as if it
    had reverted record 1's severity and deleted its revisions entry."""
    _moved_base(repo)
    tip = _git(repo, "rev-parse", "main")
    before = ratchet.read_record(tip, f"records/{ID}.json")
    after = ratchet.read_record("HEAD", f"records/{ID}.json")
    two_dot = ratchet.record_problems(before, after)
    assert any("revisions" in p for p in two_dot) and any("severity changed" in p for p in two_dot)
    assert ratchet.check("main") == []


# --- failing safe ----------------------------------------------------------------------

def test_an_unknown_base_cannot_be_read(repo):
    write(repo, record())
    commit(repo, "x")
    with pytest.raises(RuntimeError):
        ratchet.check("no-such-ref")


def test_main_exits_2_when_the_change_cannot_be_listed(repo, capsys):
    assert ratchet.main(["--ratchet-since", "no-such-ref"]) == 2
    assert "none was checked" in capsys.readouterr().err


def test_main_exits_1_with_every_problem_and_0_when_clean(repo, capsys):
    write(repo, record())
    commit(repo, "base")
    _git(repo, "tag", "base")
    write(repo, record(severity="HIGH", status="deprecated"))
    commit(repo, "head")
    assert ratchet.main(["--ratchet-since", "base"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL: 2 problem(s) in 1 of 1 record(s)")
    assert "severity changed" in out and "status changed" in out
    _git(repo, "tag", "head")
    assert ratchet.main(["--ratchet-since", "head"]) == 0
    assert "Ratchet: 0 record(s) changed since head" in capsys.readouterr().out


def test_main_requires_a_base():
    with pytest.raises(SystemExit):
        ratchet.main([])
