import json

import pytest

from scripts import validate_crosswalks, validate_records


def test_record_validator_rejects_invalid_date_time_format():
    schema = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = validate_records.build_validator(schema)
    record = {
        "ave_id": "AVE-2026-99999",
        "schema_version": "1.1.0",
        "status": "draft",
        "title": "Invalid date-time fixture",
        "description": "A minimal draft record with malformed published metadata.",
        "attack_class": "test",
        "behavioral_fingerprint": "test",
        "references": [{"title": "Example", "url": "https://example.com"}],
        "published": "not-a-date-time",
    }

    errors = validate_records.check_schema(record, validator)

    assert any("not-a-date-time" in error for error in errors)


# --- crosswalk pin declarations -------------------------------------------------
#
# The three states an endpoint can be in, and the checks that keep them apart:
# pinned (carries commit), declared unpinnable (says so, with a reason and a date,
# and is refutable), or neither, which is the blank the warning is about.


def crosswalk_validator():
    schema = json.loads(validate_crosswalks.SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_crosswalks.build_validator(schema)


def crosswalk_document(source: dict, target: dict | None = None) -> dict:
    """A crosswalk carrying only what the schema requires, plus the endpoints
    under test, so that a refusal can only have come from the endpoint."""
    return {
        "$schema": "https://aveproject.org/schema/crosswalk-1.0.0.schema.json",
        "source": source,
        "target": target or {"url": "https://aveproject.org"},
        "generated": "2026-08-09",
        "note": "Fixture crosswalk, endpoints only.",
        "mappings": [{"ave_id": "AVE-2026-00001"}],
        "coverage": {"mapped": 1},
    }


UNPINNABLE_SITE = {
    "url": "https://owasp.org/www-project-agentic-skills-top-10/",
    "pin_status": "unpinnable",
    "unpinnable_reason": "published as a site with no repository behind it",
    "checked_against_live_site": "2026-08-09",
    "content_digest": "sha256:" + "0" * 64,
}


def test_every_crosswalk_in_the_repository_still_validates():
    validator = crosswalk_validator()
    paths = sorted(validate_crosswalks.CROSSWALKS_DIR.glob("*.json"))

    assert paths, "no crosswalks found to validate"
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        assert validate_crosswalks.check_schema(document, validator) == [], path


def test_schema_accepts_a_declared_unpinnable_endpoint():
    document = crosswalk_document({"url": "https://aveproject.org"}, dict(UNPINNABLE_SITE))

    assert validate_crosswalks.check_schema(document, crosswalk_validator()) == []


@pytest.mark.parametrize("dropped", ["unpinnable_reason", "checked_against_live_site", "content_digest"])
def test_schema_rejects_an_unpinnable_declaration_missing_its_evidence(dropped):
    endpoint = dict(UNPINNABLE_SITE)
    del endpoint[dropped]
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    errors = validate_crosswalks.check_schema(document, crosswalk_validator())

    assert any(dropped in error for error in errors)


def test_schema_rejects_an_endpoint_that_is_both_pinned_and_unpinnable():
    endpoint = dict(UNPINNABLE_SITE, commit="a" * 40)
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    assert validate_crosswalks.check_schema(document, crosswalk_validator()) != []


def test_schema_rejects_a_pin_status_other_than_unpinnable():
    endpoint = dict(UNPINNABLE_SITE, pin_status="pinned")
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    assert validate_crosswalks.check_schema(document, crosswalk_validator()) != []


def test_declaring_a_repository_unpinnable_fails():
    endpoint = dict(UNPINNABLE_SITE, url="https://github.com/aveproject/ave")
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    problems = validate_crosswalks.check_declared_unpinnable_has_no_repository(document)

    assert len(problems) == 1
    assert "which can be pinned" in problems[0]


def test_declaring_a_repository_unpinnable_fails_when_the_repository_is_not_under_url():
    """The shape the check used to miss, taken from a real endpoint.

    The AST10 side of ave-to-ast10.json carries its OWASP project page under url
    and its repository under github. Reading only url leaves that endpoint free
    to declare itself unpinnable and pass, and the network probe reaches the
    same verdict for the same reason, because it probes the project page and
    correctly finds no history behind it. Both halves would report clean on a
    declaration that is false.
    """
    endpoint = dict(UNPINNABLE_SITE,
                    github="https://github.com/OWASP/www-project-agentic-skills-top-10")
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    problems = validate_crosswalks.check_declared_unpinnable_has_no_repository(document)

    assert len(problems) == 1
    assert "its github" in problems[0]
    assert "which can be pinned" in problems[0]


def test_a_site_with_no_repository_under_any_field_is_still_declarable():
    """The widening must not swallow the case the declaration exists for."""
    endpoint = dict(UNPINNABLE_SITE, site="https://owasp.org/projects/")

    assert validate_crosswalks.repository_fields(endpoint) == []


def test_declaring_a_site_with_no_repository_unpinnable_passes():
    document = crosswalk_document({"url": "https://aveproject.org"}, dict(UNPINNABLE_SITE))

    assert validate_crosswalks.check_declared_unpinnable_has_no_repository(document) == []


def test_a_forge_url_with_no_repository_path_is_not_a_repository():
    assert validate_crosswalks.is_repository_url("https://github.com/aveproject/ave")
    assert not validate_crosswalks.is_repository_url("https://github.com/aveproject")
    assert not validate_crosswalks.is_repository_url("https://aveproject.org/schema")


def test_a_stated_record_count_with_no_commit_warns():
    document = crosswalk_document({"url": "https://aveproject.org", "record_count": 76})

    warnings = validate_crosswalks.warn_stated_count_without_pin(document)

    assert len(warnings) == 1
    assert "cannot be re-derived" in warnings[0]


def test_a_stated_record_count_is_not_warned_about_when_pinned():
    document = crosswalk_document(
        {"url": "https://aveproject.org", "record_count": 76, "commit": "b" * 40}
    )

    assert validate_crosswalks.warn_stated_count_without_pin(document) == []


def test_a_stated_record_count_is_not_warned_about_when_declared_unpinnable():
    document = crosswalk_document(dict(UNPINNABLE_SITE, record_count=76))

    assert validate_crosswalks.warn_stated_count_without_pin(document) == []


def crosswalk_schema() -> dict:
    return json.loads(validate_crosswalks.SCHEMA_PATH.read_text(encoding="utf-8"))


def test_the_shipped_schema_has_promoted_commit_for_count_stating_endpoints():
    """The escalation agreed in #94, now landed: warn while commit is optional,
    hard-fail once it is promoted. This asserts which side of the promotion the
    shipped schema is on, not a preference -- the promotion is in, so the check
    fails rather than warns. The promotion is SCOPED to endpoints stating a
    record_count, which is what #126 settled, so `commit_is_required` reads True
    without every endpoint in the repository being obliged to carry a commit."""
    assert validate_crosswalks.commit_is_required(crosswalk_schema()) is True


def test_promoting_commit_to_required_escalates_the_check_with_no_code_change():
    """The other side of the same switch. Requiring commit in the endpoint
    definition is the whole of the escalation: no constant is flipped, no date is
    read, and the validator cannot start failing before the field is promoted or
    keep warning after it."""
    schema = crosswalk_schema()
    schema["$defs"]["endpoint"]["required"] = ["url", "commit"]

    assert validate_crosswalks.commit_is_required(schema) is True


def unpinned_count_tree(tmp_path, schema: dict) -> None:
    """A whole repository in miniature: the given schema, one record, and one
    crosswalk stating a count that nothing pins. Enough for main() to run against,
    since it reads schema/, records/ and crosswalks/ relative to the directory it
    is invoked from."""
    (tmp_path / "schema").mkdir()
    (tmp_path / "schema" / "crosswalk-1.0.0.schema.json").write_text(
        json.dumps(schema), encoding="utf-8")
    (tmp_path / "records").mkdir()
    (tmp_path / "records" / "AVE-2026-00001.json").write_text(
        json.dumps({"ave_id": "AVE-2026-00001"}), encoding="utf-8")
    (tmp_path / "crosswalks").mkdir()
    (tmp_path / "crosswalks" / "unpinned.json").write_text(
        json.dumps(crosswalk_document({"url": "https://aveproject.org",
                                       "record_count": 77})), encoding="utf-8")


def test_an_unpinned_count_now_fails_against_the_shipped_schema(
        tmp_path, monkeypatch, capsys):
    """The same tree that warned before the promotion, run against the schema as
    it now ships. This is the half that would have gone unnoticed: the sibling
    test below builds its own promoted schema, so it passed both before and after
    and could never have told anyone whether the promotion had actually landed."""
    unpinned_count_tree(tmp_path, crosswalk_schema())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["validate_crosswalks.py"])

    exit_code = validate_crosswalks.main()

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "cannot be re-derived" in out
    assert "WARNING" not in out


def test_an_unpinned_count_fails_once_the_schema_promotes_commit(
        tmp_path, monkeypatch, capsys):
    """The escalation, end to end and through main() rather than through the
    predicate alone: the only thing that changed is the schema, and the same
    finding that was printed as a warning above is now reported as a failure.

    The exit code alone cannot show this, because a schema that requires commit
    refuses the file on its own account too, so what is asserted is that the
    unpinned-count finding has stopped being a warning."""
    schema = crosswalk_schema()
    schema["$defs"]["endpoint"]["required"] = ["url", "commit"]
    unpinned_count_tree(tmp_path, schema)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["validate_crosswalks.py"])

    exit_code = validate_crosswalks.main()

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "cannot be re-derived" in out
    assert "WARNING" not in out


def test_forbidding_commit_on_an_unpinnable_side_does_not_read_as_promoting_it():
    """The schema contains a required list naming commit underneath a `not`, to
    keep a declared-unpinnable endpoint from also carrying a pin. Reading that as
    the promotion would hard-fail the whole repository the day it landed.

    This asserts against a schema with the promotion REMOVED rather than against
    the shipped one. It used to read the shipped schema, which worked only while
    nothing else promoted commit; now that something does, that form would pass
    for the wrong reason and would keep passing if the `not` skip were deleted.
    A test that cannot fail when the thing it describes breaks is not a test."""
    schema = crosswalk_schema()
    schema["$defs"]["endpoint"].pop("allOf", None)

    assert "commit" in json.dumps(schema["$defs"]["endpoint"]["then"]["not"])
    assert validate_crosswalks.commit_is_required(schema) is False


def test_an_unpinnable_side_may_still_state_a_count(tmp_path):
    """The interaction the scoping exists for, and the reason the promotion is not
    a bare entry in the endpoint's required list.

    The endpoint description defines three pinning states, and one of them is a
    side that declares itself unpinnable and carries a content digest instead. Such
    a side may still state a record count. Requiring commit of every count-stating
    endpoint without excluding that case would demand a field the unpinnable rule
    directly above forbids, leaving no document that satisfies both and silently
    deleting one of the three states."""
    validator = validate_crosswalks.build_validator(crosswalk_schema())
    endpoint = {
        "url": "https://example.org/standard",
        "record_count": 12,
        "pin_status": "unpinnable",
        "unpinnable_reason": "the endpoint publishes no repository to pin",
        "checked_against_live_site": "2026-08-23",
        "content_digest": "sha256:" + "a" * 64,
    }

    errors = list(validator.iter_errors(crosswalk_document(endpoint)))

    assert errors == [], [error.message for error in errors]
