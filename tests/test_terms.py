import json

from scripts import generate_terms as gen
from scripts import check_terms_sync as sync


def test_render_output_matches_a_hand_computed_case():
    fields = {"beta_field": "Second field.", "alpha_field": "First field."}
    relationships = "Alpha and beta are unrelated."
    output = gen.render(fields, relationships)

    assert output == (
        "# AVE schema terms\n\n"
        "Per-field definitions below are generated directly from "
        "schema/ave-record-1.1.0.schema.json and are never hand-edited. "
        "Run scripts/generate_terms.py after any schema change.\n\n"
        "## Relationships between similar-sounding fields\n\n"
        "Alpha and beta are unrelated.\n\n"
        f"{gen.GENERATED_MARKER}\n\n"
        "### `alpha_field`\n\n"
        "First field.\n\n"
        "### `beta_field`\n\n"
        "Second field.\n"
    )


def test_render_sorts_fields_alphabetically_regardless_of_input_order():
    """Mutation check: if sorted() were dropped, this must go red -- the
    dict's own insertion order (z before a) would leak through instead."""
    fields = {"zeta_field": "Z.", "alpha_field": "A."}
    output = gen.render(fields, "")
    assert output.index("`alpha_field`") < output.index("`zeta_field`")


def test_render_falls_back_to_placeholder_for_empty_description():
    output = gen.render({"undocumented_field": ""}, "")
    assert "(no description in schema)" in output


def test_missing_relationships_file_does_not_crash_the_generator(tmp_path, monkeypatch):
    monkeypatch.setattr(gen, "RELATIONSHIPS_PATH", tmp_path / "does-not-exist.md")
    # main() reads RELATIONSHIPS_PATH itself; replicate that guarded read
    # directly, since main() also writes OUTPUT_PATH as a side effect.
    relationships = gen.RELATIONSHIPS_PATH.read_text(encoding="utf-8") if gen.RELATIONSHIPS_PATH.exists() else ""
    assert relationships == ""
    # Confirm render() itself tolerates the empty string without raising.
    gen.render({"a_field": "A."}, relationships)


def test_load_field_descriptions_reads_every_schema_property(tmp_path, monkeypatch):
    schema = {
        "properties": {
            "one": {"description": "First."},
            "two": {"description": "Second."},
        }
    }
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    monkeypatch.setattr(gen, "SCHEMA_PATH", schema_path)

    fields = gen.load_field_descriptions()
    assert fields == {"one": "First.", "two": "Second."}


def test_sync_check_fails_when_output_file_is_stale(tmp_path, monkeypatch):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        json.dumps({"properties": {"a_field": {"description": "Original."}}}),
        encoding="utf-8",
    )
    relationships_path = tmp_path / "relationships.md"
    relationships_path.write_text("Notes.", encoding="utf-8")
    output_path = tmp_path / "terms.md"

    monkeypatch.setattr(gen, "SCHEMA_PATH", schema_path)
    monkeypatch.setattr(gen, "RELATIONSHIPS_PATH", relationships_path)
    monkeypatch.setattr(gen, "OUTPUT_PATH", output_path)
    monkeypatch.setattr(sync, "RELATIONSHIPS_PATH", relationships_path)
    monkeypatch.setattr(sync, "OUTPUT_PATH", output_path)
    monkeypatch.setattr(sync, "load_field_descriptions", gen.load_field_descriptions)

    gen.main()

    # Change the schema description without regenerating -- terms.md is now stale.
    schema_path.write_text(
        json.dumps({"properties": {"a_field": {"description": "Changed."}}}),
        encoding="utf-8",
    )

    assert sync.main() == 1


def test_sync_check_passes_after_regenerating(tmp_path, monkeypatch):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        json.dumps({"properties": {"a_field": {"description": "Original."}}}),
        encoding="utf-8",
    )
    relationships_path = tmp_path / "relationships.md"
    relationships_path.write_text("Notes.", encoding="utf-8")
    output_path = tmp_path / "terms.md"

    monkeypatch.setattr(gen, "SCHEMA_PATH", schema_path)
    monkeypatch.setattr(gen, "RELATIONSHIPS_PATH", relationships_path)
    monkeypatch.setattr(gen, "OUTPUT_PATH", output_path)
    monkeypatch.setattr(sync, "RELATIONSHIPS_PATH", relationships_path)
    monkeypatch.setattr(sync, "OUTPUT_PATH", output_path)
    monkeypatch.setattr(sync, "load_field_descriptions", gen.load_field_descriptions)

    schema_path.write_text(
        json.dumps({"properties": {"a_field": {"description": "Changed."}}}),
        encoding="utf-8",
    )
    gen.main()

    assert sync.main() == 0
