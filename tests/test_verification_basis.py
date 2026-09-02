import json

import pytest

from scripts import write_verification_basis as writer


def record(**overrides):
    base = {
        "ave_id": "AVE-2026-99999",
        "schema_version": "1.1.0",
        "status": "active",
        "title": "Verification basis fixture",
        "description": "Fixture record for the verification_basis derivation.",
        "attack_class": "test",
        "behavioral_fingerprint": "test",
        "references": [{"tag": "Source", "text": "Source", "url": "https://example.com"}],
    }
    base.update(overrides)
    return base


# --- the floor -------------------------------------------------------------

def test_a_record_saying_nothing_derives_the_floor():
    """Silence is never credited as a claim. A record with no axes at all sits
    at the weaker value of both, which is the value a producer may always
    truthfully state."""
    assert writer.derive(record()) == "artifact_reconstructed"


def test_the_floor_is_reachable_without_admitting_anything():
    """Both floor values are stateable outright, not only by omission."""
    assert writer.derive(record(
        evidence_vantage="artifact", evidence_method="reconstructed",
    )) == "artifact_reconstructed"


# --- the ceiling the engine set imposes ------------------------------------

def test_content_engines_cannot_reach_substrate_however_many_there_are():
    """pattern, yara, semgrep, llm and magika all read what the artifact wrote,
    so no combination of them lets a declared substrate vantage stand."""
    assert writer.derive(record(
        evidence_vantage="substrate",
        evidence_basis_engines=["pattern", "yara", "semgrep", "llm", "magika"],
    )) == "artifact_reconstructed"


def test_external_authority_makes_the_substrate_claim_reachable():
    """The member added for issue #98. Before it existed the ceiling was pinned
    at artifact for a record whose finding came from an outside answer."""
    assert writer.derive(record(
        evidence_vantage="substrate",
        evidence_method="intercepted",
        evidence_basis_engines=["pattern", "external_authority"],
    )) == "substrate_intercepted"


def test_sandbox_also_reaches_substrate():
    assert writer.derive(record(
        evidence_vantage="substrate", evidence_basis_engines=["sandbox"],
    )) == "substrate_reconstructed"


def test_the_derived_vantage_is_readable_without_parsing_the_composed_value():
    """The vantage half of the composition, pinned as a name of its own.

    scripts/check_confidence_signal.py floors its vantage arm on this. A
    consumer that had to recover the vantage by splitting
    'substrate_intercepted' on an underscore, or by re-testing
    SUBSTRATE_ENGINES itself, would be a second definition of the same
    predicate -- which is the defect the confidence check was split to fix.
    """
    assert writer.derived_vantage(record(
        evidence_vantage="substrate", evidence_basis_engines=["sandbox"],
    )) == "substrate"
    assert writer.derived_vantage(record(
        evidence_vantage="substrate", evidence_basis_engines=["pattern"],
    )) == "artifact"
    assert writer.derived_vantage(record()) == "artifact"


def test_the_ceiling_does_not_raise_a_record_that_claims_nothing():
    """A strong engine set is permission to make a claim, not the claim. A
    record that declares no vantage stays at the floor even with the strongest
    engine present."""
    assert writer.derive(record(
        evidence_basis_engines=["external_authority", "sandbox"],
    )) == "artifact_reconstructed"


# --- composition by weakest input ------------------------------------------

@pytest.mark.parametrize("vantage,method,expected", [
    ("substrate", "intercepted", "substrate_intercepted"),
    ("substrate", "reconstructed", "substrate_reconstructed"),
    ("artifact", "intercepted", "artifact_intercepted"),
    ("artifact", "reconstructed", "artifact_reconstructed"),
])
def test_all_four_cells_are_reachable(vantage, method, expected):
    assert writer.derive(record(
        evidence_vantage=vantage, evidence_method=method,
        evidence_basis_engines=["sandbox"],
    )) == expected


def test_method_absent_reads_as_reconstructed_not_intercepted():
    assert writer.derive(record(
        evidence_vantage="substrate", evidence_basis_engines=["sandbox"],
    )) == "substrate_reconstructed"


# --- values outside the closed vocabularies --------------------------------

@pytest.mark.parametrize("bad", ["SUBSTRATE", "substrate ", "trusted", "", None, 1, True, ["substrate"]])
def test_an_unreadable_vantage_reads_as_the_floor_at_its_own_level(bad):
    """Pinned on the axis reader directly, not only through derive(). Checked
    through derive() alone this guard is unobservable: a stray value fails the
    equality against 'substrate' either way, so the closed-vocabulary check
    could be deleted and every end-to-end assertion would still pass."""
    assert writer.declared_vantage(record(evidence_vantage=bad)) == "artifact"


@pytest.mark.parametrize("bad", ["INTERCEPTED", "live", "", None, 0, []])
def test_an_unreadable_method_reads_as_the_floor_at_its_own_level(bad):
    assert writer.declared_method(record(evidence_method=bad)) == "reconstructed"


@pytest.mark.parametrize("bad", ["SUBSTRATE", "substrate ", "trusted", "", None, 1, True, ["substrate"]])
def test_an_unreadable_vantage_is_the_floor_not_a_new_rung(bad):
    """A value outside the closed vocabulary is a producer saying something the
    derivation cannot read, and the honest reading of that is the floor, never a
    stronger rung and never a crash."""
    assert writer.derive(record(
        evidence_vantage=bad, evidence_basis_engines=["sandbox"],
    )) == "artifact_reconstructed"


@pytest.mark.parametrize("bad", ["INTERCEPTED", "live", "", None, 0, []])
def test_an_unreadable_method_is_the_floor(bad):
    assert writer.derive(record(
        evidence_vantage="substrate", evidence_method=bad,
        evidence_basis_engines=["sandbox"],
    )) == "substrate_reconstructed"


@pytest.mark.parametrize("bad", ["sandbox", {"sandbox": 1}, None, 7, [None, 3], []])
def test_a_malformed_engine_field_reaches_nothing(bad):
    """A string is not a one-element list and a typo is not a strong vantage.
    'sandbox' as a bare string must not be read as the sandbox engine."""
    assert writer.derive(record(
        evidence_vantage="substrate", evidence_basis_engines=bad,
    )) == "artifact_reconstructed"


def test_a_valid_engine_beside_junk_still_counts():
    assert writer.derive(record(
        evidence_vantage="substrate", evidence_basis_engines=[None, 3, "sandbox"],
    )) == "substrate_reconstructed"


# --- the declaration is falsifiable ----------------------------------------

def test_no_declaration_is_not_a_finding():
    assert writer.check_record(record(evidence_basis_engines=["pattern"])) == []


def test_a_matching_declaration_passes():
    assert writer.check_record(record(
        verification_basis="artifact_reconstructed", evidence_basis_engines=["pattern"],
    )) == []


def test_a_declaration_stronger_than_the_axes_is_refuted():
    """The pin_status shape: a side declaring something its own content
    contradicts fails, which is what makes the declaration worth carrying."""
    problems = writer.check_record(record(
        verification_basis="substrate_intercepted",
        evidence_vantage="artifact",
        evidence_basis_engines=["pattern"],
    ))
    assert len(problems) == 1
    assert "substrate_intercepted" in problems[0]
    assert "artifact_reconstructed" in problems[0]


def test_a_declaration_weaker_than_the_axes_is_also_refuted():
    """Understating is a mismatch too. The field states what the derivation
    computes, so a record cannot quietly opt out of its own stronger basis."""
    assert writer.check_record(record(
        verification_basis="artifact_reconstructed",
        evidence_vantage="substrate",
        evidence_method="intercepted",
        evidence_basis_engines=["external_authority"],
    )) != []


# --- the writer refuses to reformat ----------------------------------------

def test_a_non_canonical_file_is_not_canonical():
    """73 of the 80 records on main differ from this script's serialisation in
    escaping or whitespace alone; writing into one would reformat it."""
    rec = record()
    raw = json.dumps(rec, indent=4) + "\n"
    assert writer.is_canonical(raw, rec) is False


def test_a_canonical_file_is_recognised():
    rec = record()
    assert writer.is_canonical(writer.serialize(rec), rec) is True


def test_write_refuses_non_canonical_records_and_exits_nonzero(tmp_path, monkeypatch):
    rec = record()
    path = tmp_path / "AVE-2026-99999.json"
    path.write_text(json.dumps(rec, indent=4) + "\n", encoding="utf-8")
    monkeypatch.setattr(writer, "RECORDS_DIR", tmp_path)

    assert writer.main(["--write"]) == 1
    assert path.read_text(encoding="utf-8") == json.dumps(rec, indent=4) + "\n"


def test_write_stamps_a_canonical_record(tmp_path, monkeypatch):
    rec = record(evidence_vantage="substrate", evidence_method="intercepted",
                 evidence_basis_engines=["external_authority"])
    path = tmp_path / "AVE-2026-99999.json"
    path.write_text(writer.serialize(rec), encoding="utf-8")
    monkeypatch.setattr(writer, "RECORDS_DIR", tmp_path)

    assert writer.main(["--write"]) == 0
    assert json.loads(path.read_text(encoding="utf-8"))["verification_basis"] == \
        "substrate_intercepted"


def test_check_mode_fails_on_a_contradicted_declaration(tmp_path, monkeypatch):
    rec = record(verification_basis="substrate_intercepted",
                 evidence_basis_engines=["pattern"])
    (tmp_path / "AVE-2026-99999.json").write_text(writer.serialize(rec), encoding="utf-8")
    monkeypatch.setattr(writer, "RECORDS_DIR", tmp_path)

    assert writer.main([]) == 1


def test_an_empty_records_directory_is_reported_not_passed(tmp_path, monkeypatch):
    """An absent corpus must never read as a clean run."""
    monkeypatch.setattr(writer, "RECORDS_DIR", tmp_path)
    assert writer.main([]) == 1


# --- the shipped corpus -----------------------------------------------------

def test_every_published_record_agrees_with_its_derivation():
    """Run against records/ as it stands, the same way the check half runs."""
    assert writer.main([]) == 0
