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


def test_high_confidence_on_floor_basis_is_flagged():
    """The issue #98 shape: a high float with no structural verification.

    Mirrors AVE-2026-00074's pre-#218 shape: pattern-only engine set, high
    confidence. The record has since gained external_authority (issue #218);
    this fixture pins the floor behavior the check is designed to catch.
    """
    record = base_record()
    result = check_confidence_signal.confidence_signal(record)
    assert result is not None
    assert "confidence_baseline 0.85" in result
    assert "high band" in result
    assert "floor" in result


def test_high_confidence_with_multi_engine_basis_is_not_flagged():
    """Two or more engines is not a floor basis, regardless of which engines."""
    record = base_record(
        evidence_basis_engines=["pattern", "semgrep"],
        evidence_kind_default="behavioral_pattern",
    )
    assert check_confidence_signal.confidence_signal(record) is None


def test_semantic_inference_kind_is_floor_even_with_multiple_engines():
    """semantic_inference is a floor kind on its own."""
    record = base_record(
        confidence_baseline=0.9,
        evidence_basis_engines=["yara", "semgrep"],
        evidence_kind_default="semantic_inference",
    )
    assert check_confidence_signal.confidence_signal(record) is not None


def test_low_confidence_on_floor_basis_is_not_flagged():
    """Low declared confidence is consistent with a weak basis: no signal."""
    record = base_record(confidence_baseline=0.45)
    assert check_confidence_signal.confidence_signal(record) is None


def test_missing_confidence_is_not_flagged():
    """Absent confidence is a separate concern; the signal check stays silent."""
    record = base_record(confidence_baseline=None)
    assert check_confidence_signal.confidence_signal(record) is None


def test_engine_list_ordering_is_normalized():
    """The corpus writes the same basis sets in multiple orders (18 ways for
    13 distinct bases); the check must see them as the same basis."""
    a = base_record(evidence_basis_engines=["pattern", "semgrep"])
    b = base_record(evidence_basis_engines=["semgrep", "pattern"])
    assert check_confidence_signal.confidence_signal(a) == check_confidence_signal.confidence_signal(b)


def test_duplicate_engine_members_are_still_a_floor_basis():
    """astrogilda's attack test (2026-08-26): a duplicated member is a
    single-engine basis wearing a list of length two and must not dodge
    the floor. len(set(engines)) <= 1 pins the fixed behaviour."""
    record = base_record(
        confidence_baseline=0.95,
        evidence_basis_engines=["pattern", "pattern"],
    )
    result = check_confidence_signal.confidence_signal(record)
    assert result is not None
    assert "floor" in result


def test_authority_probe_note_is_appended_to_00074_shape():
    """AVE-2026-00074's pre-#218 detection methodology named authority probes
    while its engine set still sat at the floor; the floor there was an enum
    gap, not an overclaim, and the signal said so. Pins the note logic that
    any pre-vocabulary record still gets."""
    record = base_record(
        detection_methodology="Queries GitHub's users API for owners, the package "
        "registry for names, RDAP for domains, provider fingerprints for cloud "
        "subdomains; a failed probe degrades to silence.",
    )
    result = check_confidence_signal.confidence_signal(record)
    assert result is not None
    assert "external-authority probe" in result
    assert "enum gap" in result


def test_external_authority_member_clears_the_00074_enum_gap():
    """Post-#218 shape: AVE-2026-00074's engines now carry external_authority,
    so the floor clears and the check stays quiet -- the escalation condition
    named in #213/#214 is satisfied by the record's own vocabulary."""
    record = base_record(
        evidence_basis_engines=["pattern", "external_authority"],
        detection_methodology="Queries GitHub's users API for owners, the package "
        "registry for names, RDAP for domains, provider fingerprints for cloud "
        "subdomains; a failed probe degrades to silence.",
    )
    assert check_confidence_signal.confidence_signal(record) is None


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
        record = base_record(detection_methodology=methodology)
        result = check_confidence_signal.confidence_signal(record)
        assert result is not None
        assert "external-authority probe" not in result, methodology


def test_main_is_soft_warning_exit_zero():
    """The agreed design: warn-not-fail, exit code untouched (same shape as
    check_researcher_matches_disclosure)."""
    assert check_confidence_signal.main([]) == 0
