# What: fails if docs/terms.md's generated section does not match what
#       scripts/generate_terms.py would produce right now from the live
#       schema. This is what stops the glossary from silently drifting
#       the way a hand-maintained copy would.
# Why:  a glossary that can disagree with the schema it describes is
#       worse than no glossary, since it looks authoritative while
#       being wrong. This check is a hard failure, not a soft warning,
#       because a stale definition is never the safer default.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.generate_terms import load_field_descriptions, render, RELATIONSHIPS_PATH, OUTPUT_PATH


def main() -> int:
    fields = load_field_descriptions()
    relationships = RELATIONSHIPS_PATH.read_text(encoding="utf-8") if RELATIONSHIPS_PATH.exists() else ""
    expected = render(fields, relationships)
    actual = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""
    if expected != actual:
        print("FAIL: docs/terms.md is out of sync with the schema. "
              "Run: python scripts/generate_terms.py", file=sys.stderr)
        return 1
    print("docs/terms.md matches the live schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
