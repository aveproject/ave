import json

import pytest

from scripts import check_confidence_signal


def base_record(**overrides):
    record = {
        "ave_id": "AVE-2026-99999",
        "schema_version": "1.1.0",
        "status": "active",
        "title": "Confidence signal fixture",
        "description": "Fixture record for the confidence signal check.",
        "attack_class": "test",
        "behavioral_fingerprint": "test",
        "references": [{"tag": "Source", "text": "Source", "url": "https://example.com"}],
        "confidence_baseline": 0.85,
        "evidence_basis_engines": ["pattern"],
        "evidence_kind_default": "behavioral_pattern",
    }
    record.update(overrides)
    return record


def names(record):
    """The finding names a record carries, which is the half a consumer routes
    on. The prose is asserted separately and only where it is the subject."""
    return [f["finding"] for f in check_confidence_signal.confidence_signals(record)]


def signal_for(record, finding):
    """The prose of one named finding, or None if the record does not carry it."""
    for f in check_confidence_signal.confidence_signals(record):
        if f["finding"] == finding:
            return f["signal"]
    return None


# --- the high band gates both findings ---------------------------------------

def test_low_confidence_is_not_a_finding_whatever_the_basis():
    """Low declared confidence is consistent with weak evidence. Neither arm is
    a finding on its own; both are findings about a high number."""
    assert names(base_record(confidence_baseline=0.45)) == []


def test_missing_confidence_is_not_a_finding():
    """Absent confidence is a separate concern; the signal check stays silent."""
    assert names(base_record(confidence_baseline=None)) == []


def test_evidence_that_supports_the_number_carries_no_findings():
    record = base_record(
        confidence_baseline=0.95,
        evidence_vantage="substrate",
        evidence_basis_engines=["pattern", "sandbox"],
    )
    assert names(record) == []


# --- the four combinations the split was measured against --------------------
#
# Each row below is one cell of the table that showed the two predicates
# disagreeing on main: cardinality and the verification_basis derivation, over
# the same evidence_basis_engines field, with evidence_vantage=substrate,
# evidence_method=intercepted and confidence_baseline=0.9.

def four_cell_record(engines):
    return base_record(
        confidence_baseline=0.9,
        evidence_vantage="substrate",
        evidence_method="intercepted",
        evidence_basis_engines=engines,
    )


def test_two_engines_neither_reaching_substrate_is_a_vantage_floor():
    """The miss. Cardinality saw two members and stayed silent while the
    record's own derived basis was artifact_intercepted -- a floor-level basis
    carrying a 0.9, which is the exact shape issue #98 exists to surface."""
    record = four_cell_record(["pattern", "yara"])
    assert names(record) == [check_confidence_signal.VANTAGE_FLOOR]
    assert "artifact_intercepted" in signal_for(record, check_confidence_signal.VANTAGE_FLOOR)


def test_one_substrate_capable_engine_is_an_independence_floor_only():
    """The false positive. Cardinality fired on a record whose derived basis
    was substrate_intercepted, the strongest available, and called it a floor
    basis. There is a real finding here -- one source -- but it is the
    corroboration one, and the record's vantage is not at issue."""
    record = four_cell_record(["sandbox"])
    assert names(record) == [check_confidence_signal.INDEPENDENCE_FLOOR]
    assert "single source" in signal_for(record, check_confidence_signal.INDEPENDENCE_FLOOR)


def test_one_engine_that_cannot_reach_substrate_carries_both_findings():
    """Both predicates agreed here, and they agreed because both faults are
    present, not because they measure the same thing. The record needs two
    different repairs and now says so."""
    assert names(four_cell_record(["pattern"])) == [
        check_confidence_signal.VANTAGE_FLOOR,
        check_confidence_signal.INDEPENDENCE_FLOOR,
    ]


def test_two_engines_one_reaching_substrate_carries_neither():
    assert names(four_cell_record(["pattern", "sandbox"])) == []


# --- the vantage arm ---------------------------------------------------------

def test_the_vantage_arm_reads_the_derivation_not_the_declaration():
    """A declared substrate vantage its engines cannot reach derives the floor,
    and the finding follows the derivation. A producer cannot clear this arm by
    asserting a vantage its evidence has no way to occupy."""
    record = base_record(
        confidence_baseline=0.9,
        evidence_vantage="substrate",
        evidence_basis_engines=["pattern", "yara", "semgrep", "llm", "magika"],
    )
    assert names(record) == [check_confidence_signal.VANTAGE_FLOOR]


def test_a_stamped_verification_basis_does_not_override_the_derivation():
    """verification_basis is derived, never authored, and validate_records.py
    hard-fails a declaration the axes refute. A consumer-side check that read
    the stamp would be reading the author's own copy -- a self-report, which is
    the complaint in issue #98 wearing a better field name."""
    record = base_record(
        confidence_baseline=0.9,
        verification_basis="substrate_intercepted",
        evidence_basis_engines=["pattern", "yara"],
    )
    assert check_confidence_signal.VANTAGE_FLOOR in names(record)


def test_semantic_inference_is_a_vantage_finding_not_an_independence_one():
    """An inference over meaning is a reading of content the artifact produced,
    however good the reading, so it sits at the same rung and takes the same
    remedy. It says nothing about how many sources agreed, so it must not reach
    the independence arm."""
    record = base_record(
        confidence_baseline=0.9,
        evidence_vantage="substrate",
        evidence_basis_engines=["sandbox", "pattern"],
        evidence_kind_default="semantic_inference",
    )
    assert names(record) == [check_confidence_signal.VANTAGE_FLOOR]
    assert "semantic_inference" in signal_for(record, check_confidence_signal.VANTAGE_FLOOR)


def test_the_vantage_finding_names_every_cause_holding_it_down():
    """An author who fixes one cause and re-runs should not discover the second
    only then. Both are reported in the one finding, because both take the
    vantage remedy."""
    signal = signal_for(
        base_record(confidence_baseline=0.9, evidence_kind_default="semantic_inference"),
        check_confidence_signal.VANTAGE_FLOOR,
    )
    assert "artifact_reconstructed" in signal
    assert "semantic_inference" in signal


# --- the independence arm ----------------------------------------------------

def test_a_duplicated_member_is_one_source():
    """astrogilda's attack test (2026-08-26): a duplicated member is a single
    source wearing a list of length two and must not dodge the floor."""
    record = base_record(confidence_baseline=0.95, evidence_basis_engines=["pattern", "pattern"])
    assert check_confidence_signal.INDEPENDENCE_FLOOR in names(record)


def test_engine_list_ordering_is_normalized():
    """The corpus writes the same basis sets in multiple orders (18 ways for
    13 distinct bases); the check must see them as the same basis."""
    a = base_record(evidence_basis_engines=["pattern", "semgrep"])
    b = base_record(evidence_basis_engines=["semgrep", "pattern"])
    assert check_confidence_signal.confidence_signals(a) == check_confidence_signal.confidence_signals(b)


@pytest.mark.parametrize("engines", [[None, 3], [{"engine": "sandbox"}, ["sandbox"]], []])
def test_a_member_that_is_not_a_string_is_not_a_source(engines):
    """Two malformed members are not two independent sources, the same reading
    write_verification_basis.py gives a malformed engine field: a typo must not
    raise what a record is credited with."""
    record = base_record(confidence_baseline=0.9, evidence_basis_engines=engines)
    assert check_confidence_signal.INDEPENDENCE_FLOOR in names(record)


def test_no_legible_source_says_so_rather_than_naming_one():
    signal = signal_for(
        base_record(confidence_baseline=0.9, evidence_basis_engines=[]),
        check_confidence_signal.INDEPENDENCE_FLOOR,
    )
    assert "no legible source" in signal


# --- the external-authority note --------------------------------------------

AUTHORITY_METHODOLOGY = (
    "Queries GitHub's users API for owners, the package registry for names, RDAP for "
    "domains, provider fingerprints for cloud subdomains; a failed probe degrades to "
    "silence."
)


def test_the_note_reads_as_an_enum_gap_while_the_engine_set_cannot_reach_substrate():
    """AVE-2026-00074's pre-#218 shape: its methodology probed outside parties
    while its engine set had no member for that rung, so the floor there was a
    gap in the vocabulary rather than an overclaim, and the signal said so."""
    signal = signal_for(
        base_record(detection_methodology=AUTHORITY_METHODOLOGY),
        check_confidence_signal.VANTAGE_FLOOR,
    )
    assert "external-authority probe" in signal
    assert "enum gap" in signal


def test_the_note_stops_blaming_the_vocabulary_once_the_member_is_adopted():
    """Post-#218 shape. The record now carries external_authority, so its
    ceiling reaches substrate and the enum gap is closed: what holds it at the
    floor is that it has never declared evidence_vantage. Telling this author
    to add a member the record already carries would send them hunting a bug
    that is not there."""
    record = base_record(
        evidence_basis_engines=["pattern", "external_authority"],
        detection_methodology=AUTHORITY_METHODOLOGY,
    )
    assert names(record) == [check_confidence_signal.VANTAGE_FLOOR]
    signal = signal_for(record, check_confidence_signal.VANTAGE_FLOOR)
    assert "has not declared evidence_vantage" in signal
    assert "enum gap" not in signal


def test_declaring_the_vantage_clears_the_record_the_note_points_at():
    """The other half of the sentence above: doing what the note asks leaves
    the record with no findings at all."""
    assert names(base_record(
        evidence_vantage="substrate",
        evidence_basis_engines=["pattern", "external_authority"],
        detection_methodology=AUTHORITY_METHODOLOGY,
    )) == []


def test_the_note_attaches_to_the_vantage_finding_only():
    """The note explains a vantage-vocabulary gap. The same record's
    independence finding is true on its own terms, and an exculpatory sentence
    pasted onto it would excuse a fault it does not describe."""
    signal = signal_for(
        base_record(detection_methodology=AUTHORITY_METHODOLOGY),
        check_confidence_signal.INDEPENDENCE_FLOOR,
    )
    assert signal is not None
    assert "external-authority probe" not in signal


def test_authority_probe_note_negative_control():
    """astrogilda's attack test (2026-08-26): prose that merely mentions a
    registry or domain is not an authority probe. The note is the only
    exculpatory sentence in the output, so a false attach is worse than a
    false flag; the negative case must stay quiet."""
    for methodology in (
        "Static pattern scan for hardcoded credentials in packages published to the npm registry.",
        "Domain-specific heuristics over the tool description string.",
        "Matches the Windows registry key path written by the installer.",
    ):
        signal = signal_for(
            base_record(detection_methodology=methodology),
            check_confidence_signal.VANTAGE_FLOOR,
        )
        assert signal is not None
        assert "external-authority probe" not in signal, methodology


# --- the command line --------------------------------------------------------

def test_main_is_soft_warning_exit_zero():
    """The agreed design: warn-not-fail, exit code untouched (same shape as
    check_researcher_matches_disclosure)."""
    assert check_confidence_signal.main([]) == 0


def test_json_output_names_the_finding_and_counts_both_axes(tmp_path, monkeypatch, capsys):
    """A record carrying both findings contributes two findings on one record,
    and downstream tooling has to be able to read either number without
    inferring the other."""
    record = base_record(confidence_baseline=0.9)
    (tmp_path / "AVE-2026-99999.json").write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(check_confidence_signal, "RECORDS_DIR", tmp_path)

    assert check_confidence_signal.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert payload["records"] == 1
    assert [f["finding"] for f in payload["findings"]] == [
        check_confidence_signal.VANTAGE_FLOOR,
        check_confidence_signal.INDEPENDENCE_FLOOR,
    ]
    assert {f["ave_id"] for f in payload["findings"]} == {"AVE-2026-99999"}


def test_an_empty_records_directory_is_reported_not_passed(tmp_path, monkeypatch):
    """An absent corpus must never read as a clean run."""
    monkeypatch.setattr(check_confidence_signal, "RECORDS_DIR", tmp_path)
    assert check_confidence_signal.main([]) == 2


# --- the ratchet (issue #286) -------------------------------------------------

import subprocess


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _write(repo, rid, **overrides):
    records = repo / "records"
    records.mkdir(exist_ok=True)
    (records / f"{rid}.json").write_text(json.dumps(base_record(ave_id=rid, **overrides)), encoding="utf-8")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A git repository holding one old, unstamped, high-confidence record on
    its base commit, on a branch named "base", with the working directory set to it the
    way CI runs the script."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.org")
    _git(tmp_path, "config", "user.name", "T")
    _write(tmp_path, "AVE-2026-00001", confidence_baseline=0.9)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")
    _git(tmp_path, "branch", "base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _commit(repo):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "change")


def test_lacks_vantage_stamp_asks_for_the_statement_not_a_value():
    assert check_confidence_signal.lacks_vantage_stamp(base_record(confidence_baseline=0.9))
    assert check_confidence_signal.lacks_vantage_stamp(
        base_record(confidence_baseline=0.9, evidence_vantage=""))
    assert not check_confidence_signal.lacks_vantage_stamp(
        base_record(confidence_baseline=0.9, evidence_vantage="artifact"))
    assert not check_confidence_signal.lacks_vantage_stamp(base_record(confidence_baseline=0.5))
    assert not check_confidence_signal.lacks_vantage_stamp(base_record(confidence_baseline=None))


def test_ratchet_fails_a_new_unstamped_high_confidence_record(repo, capsys):
    _write(repo, "AVE-2026-00002", confidence_baseline=0.9)
    _commit(repo)
    assert check_confidence_signal.ratchet("base") == 1
    out = capsys.readouterr().out
    assert "AVE-2026-00002" in out
    assert "AVE-2026-00001" not in out


def test_ratchet_fails_an_edited_record_that_is_still_unstamped(repo):
    _write(repo, "AVE-2026-00001", confidence_baseline=0.95)
    _commit(repo)
    assert check_confidence_signal.ratchet("base") == 1


def test_ratchet_passes_when_the_change_states_the_vantage(repo):
    _write(repo, "AVE-2026-00002", confidence_baseline=0.9, evidence_vantage="artifact")
    _write(repo, "AVE-2026-00001", confidence_baseline=0.9, evidence_vantage="substrate")
    _commit(repo)
    assert check_confidence_signal.ratchet("base") == 0


def test_ratchet_leaves_older_records_to_the_soft_warning(repo):
    (repo / "README.md").write_text("unrelated", encoding="utf-8")
    _commit(repo)
    assert check_confidence_signal.ratchet("base") == 0


def test_ratchet_ignores_base_changes_after_the_branch_point(repo):
    _git(repo, "switch", "-q", "-c", "feature")
    (repo / "README.md").write_text("feature branch", encoding="utf-8")
    _commit(repo)

    _git(repo, "switch", "-q", "base")
    record_path = repo / "records" / "AVE-2026-00001.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    _commit(repo)

    _git(repo, "switch", "-q", "feature")
    two_dot = subprocess.run(
        ["git", "diff", "--name-only", "base..HEAD", "--", "records"],
        capture_output=True, text=True, check=True,
    )
    assert two_dot.stdout.strip() == "records/AVE-2026-00001.json"
    assert check_confidence_signal.changed_record_paths("base") == []
    assert check_confidence_signal.ratchet("base") == 0


def test_ratchet_ignores_deleted_records(repo):
    (repo / "records" / "AVE-2026-00001.json").unlink()
    _commit(repo)
    assert check_confidence_signal.changed_record_paths("base") == []
    assert check_confidence_signal.ratchet("base") == 0


def test_ratchet_passes_a_low_confidence_record_without_the_stamp(repo):
    _write(repo, "AVE-2026-00002", confidence_baseline=0.45)
    _commit(repo)
    assert check_confidence_signal.ratchet("base") == 0


def test_ratchet_cannot_read_the_change_and_says_nothing_was_checked(repo, capsys):
    assert check_confidence_signal.ratchet("no-such-ref") == 2
    assert "none was checked" in capsys.readouterr().err


def test_main_returns_the_ratchet_verdict(repo):
    _write(repo, "AVE-2026-00002", confidence_baseline=0.9)
    _commit(repo)
    assert check_confidence_signal.main(["--ratchet-since", "base"]) == 1
    assert check_confidence_signal.main([]) == 0
