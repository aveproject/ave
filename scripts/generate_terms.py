# What: generates docs/terms.md from the record schema's own field
#       descriptions. The per-field definitions in that file are never
#       hand-edited; this script is the only thing that writes them.
# Why:  a hand-maintained glossary next to a schema that keeps changing
#       drifts, and a wrong definition is worse than no definition. The
#       relationship notes between confusable field pairs are real,
#       hand-written content this script does not touch; they live in
#       a separate, checked-in section this script reads and re-emits
#       verbatim rather than regenerates.
import json
from pathlib import Path

SCHEMA_PATH = Path("schema/ave-record-1.1.0.schema.json")
RELATIONSHIPS_PATH = Path("docs/terms-relationships.md")
OUTPUT_PATH = Path("docs/terms.md")

GENERATED_MARKER = "<!-- GENERATED FROM schema/ave-record-1.1.0.schema.json, DO NOT HAND-EDIT BELOW THIS LINE -->"


def load_field_descriptions() -> dict[str, str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    props = schema.get("properties", {})
    return {name: spec.get("description", "") for name, spec in props.items()}


def render(fields: dict[str, str], relationships: str) -> str:
    lines = [
        "# AVE schema terms",
        "",
        "Per-field definitions below are generated directly from "
        "schema/ave-record-1.1.0.schema.json and are never hand-edited. "
        "Run scripts/generate_terms.py after any schema change.",
        "",
        "## Relationships between similar-sounding fields",
        "",
        relationships.strip(),
        "",
        GENERATED_MARKER,
        "",
    ]
    for name in sorted(fields):
        desc = fields[name] or "(no description in schema)"
        lines.append(f"### `{name}`")
        lines.append("")
        lines.append(desc)
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    fields = load_field_descriptions()
    relationships = RELATIONSHIPS_PATH.read_text(encoding="utf-8") if RELATIONSHIPS_PATH.exists() else ""
    OUTPUT_PATH.write_text(render(fields, relationships), encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH} from {len(fields)} schema fields.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
