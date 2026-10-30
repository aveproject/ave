"""README.md, CLAUDE.md and CONTRIBUTING.md each restate which fields a record has: the
required set, the reduced core a draft needs, and (README and CLAUDE.md) every optional
field. They are edited by hand and nothing checked them against the schema, so when the
schema already had ten optional fields the two lists did not name (#386), a reader could
not tell the fields existed. These tests read the schema and the three documents and fail
on drift in either direction: a field the schema has and a document lacks, a field a
document names that the schema does not have, a field in the wrong list or listed twice,
and a count ("15 required fields") that no longer matches.

The schema read is the alias, schema/ave-record.schema.json, so the tests follow every
future version without an edit. The README also lists the optional sub-fields of `aivss`
(`aivss.notes`); CLAUDE.md may. No other nested object's fields are listed anywhere, so
no others are read.
"""
import json
import re
from pathlib import Path

SCHEMA = Path("schema/ave-record.schema.json")

NUMBER_WORDS = {w: n for n, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen "
    "fourteen fifteen sixteen seventeen eighteen nineteen twenty".split())}
FIELD = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$")
SEPARATORS = re.compile(r"[·,\s]+")

# How the schema classes a field. A field is in exactly one of these.
KINDS = (
    ("draft", "part of the draft core"),
    ("published_only", "required once a record is not a draft"),
    ("optional", "optional"),
    ("aivss", "an optional sub-field of aivss"),
)
LABELS = dict(KINDS)

# The forms the documents state a count in, and which set the count is the size of.
COUNTS = (
    (re.compile(r"\b(\w+) required fields\b"), "required", "required fields"),
    (re.compile(r"\b(\w+)-field required set\b"), "required", "required fields"),
    (re.compile(r"\b(\w+)-field core\b"), "draft", "fields in the draft core"),
    (re.compile(r"\bonly needs these (\w+)\b"), "draft", "fields in the draft core"),
)


def schema_sets(schema: dict) -> dict[str, set[str]]:
    """What the schema says each list must hold: the draft core (`required`), the fields a
    record needs once it is not a draft (the `else` branch), every other property, and the
    optional sub-fields of `aivss`, written `aivss.name`."""
    draft = set(schema["required"])
    published_only = set(schema["else"]["required"]) - draft
    aivss = schema["properties"]["aivss"]
    return {
        "draft": draft,
        "published_only": published_only,
        "optional": set(schema["properties"]) - draft - published_only,
        "aivss": {f"aivss.{name}" for name in aivss["properties"] if name not in aivss["required"]},
    }


def kind_of(name: str, sets: dict) -> str | None:
    return next((kind for kind, _ in KINDS if name in sets[kind]), None)


def names_in(text: str) -> tuple[list[str], list[str]]:
    """The field names in a list written `a · b · c`, with or without backticks, across
    lines, and the words that are not field names."""
    words = [w for w in SEPARATORS.split(text.replace("`", "")) if w]
    return [w for w in words if FIELD.match(w)], [w for w in words if not FIELD.match(w)]


def compare(doc: str, where: str, text: str, expected: set, sets: dict, allowed: set = frozenset()) -> list[str]:
    """Every difference between the names `text` lists and the `expected` set. A name in
    `allowed` may be listed or left out."""
    found, unreadable = names_in(text)
    problems = [f"{doc}: could not read {word!r} in the {where}; expected field names separated by ·"
                for word in unreadable]
    for name in sorted(expected - set(found)):
        problems.append(f"{doc}: {name} is {LABELS[kind_of(name, sets)]} in the schema but is not in the {where}")
    for name in sorted(set(found) - expected - allowed):
        kind = kind_of(name, sets)
        problems.append(f"{doc}: {name} is in the {where} but the schema "
                        + (f"has it as {LABELS[kind]}" if kind else "has no such field"))
    problems += [f"{doc}: {name} is in the {where} more than once"
                 for name in sorted({n for n in found if found.count(n) > 1})]
    return problems


def without_notes(block: str) -> str:
    """A CLAUDE.md block's field names alone: its bold heading, its parenthetical notes
    (they can wrap over lines) and the colon after them removed."""
    block = re.sub(r"^\*\*[^*]+\*\*", "", block)
    return re.sub(r"\([^)]*\)", "", block).lstrip(": \n")


def paragraphs(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n[ \t]*\n", text)]


def claude_drift(doc: str, text: str, sets: dict) -> list[str]:
    """CLAUDE.md states each list as a bold-headed paragraph: `**N required fields**`,
    `**Draft submit-required core**`, and any number of `**Optional ...**`."""
    required = draft = None
    optional = []
    for paragraph in paragraphs(text):
        if re.match(r"\*\*\d+ required fields\*\*", paragraph):
            required = without_notes(paragraph)
        elif re.match(r"\*\*Draft submit-required core\*\*", paragraph):
            draft = without_notes(paragraph)
        elif re.match(r"\*\*Optional [^*]*\*\*", paragraph):
            optional.append(without_notes(paragraph))
    problems = []
    if required is None:
        problems.append(f"{doc} has no '**N required fields**' paragraph")
    else:
        problems += compare(doc, "required fields list", required, sets["draft"] | sets["published_only"], sets)
    if draft is None:
        problems.append(f"{doc} has no '**Draft submit-required core**' paragraph")
    else:
        problems += compare(doc, "draft core", draft, sets["draft"], sets)
    if not optional:
        problems.append(f"{doc} has no '**Optional ...**' paragraph")
    else:
        problems += compare(doc, "optional field paragraphs", " ".join(optional), sets["optional"], sets,
                            allowed=sets["aivss"])
    return problems


def readme_drift(doc: str, text: str, sets: dict) -> list[str]:
    """README.md states the required set in a fence after `**N required fields:**`, the
    draft core in a sentence (`reduced eight-field core (...)`) and the optional fields
    in the paragraph after `**All optional fields:**`, the aivss sub-fields included."""
    required = re.search(r"\*\*\d+ required fields:\*\*\s*```[a-z]*\n(.*?)```", text, re.S)
    draft = re.search(r"reduced \w+-field core \((.*?)\)", text, re.S)
    optional = re.search(r"\*\*All optional fields:\*\*[ \t]*\n(.*?)(?=\n[ \t]*\n|\Z)", text, re.S)
    problems = []
    for found, form, where, expected in (
        (required, "'**N required fields:**' and a fenced list", "required fields list",
         sets["draft"] | sets["published_only"]),
        (draft, "'reduced N-field core (...)'", "draft core sentence", sets["draft"]),
        (optional, "'**All optional fields:**' and a list", "optional fields list",
         sets["optional"] | sets["aivss"]),
    ):
        if found is None:
            problems.append(f"{doc} has no {form}")
        else:
            problems += compare(doc, where, found.group(1), expected, sets)
    return problems


def contributing_drift(doc: str, text: str, sets: dict) -> list[str]:
    """CONTRIBUTING.md states the required set in a fence after `The N required fields are:`."""
    required = re.search(r"The \d+ required fields are:\s*```[a-z]*\n(.*?)```", text, re.S)
    if required is None:
        return [f"{doc} has no 'The N required fields are:' and a fenced list"]
    return compare(doc, "required fields list", required.group(1), sets["draft"] | sets["published_only"], sets)


def count_drift(doc: str, text: str, sets: dict) -> list[str]:
    """Every count the document states, in digits or as a word, equals the size of the
    set it counts."""
    sizes = {"required": len(sets["draft"]) + len(sets["published_only"]), "draft": len(sets["draft"])}
    problems = []
    for pattern, kind, what in COUNTS:
        for match in pattern.finditer(text):
            word = match.group(1).lower()
            said = int(word) if word.isdigit() else NUMBER_WORDS.get(word)
            if said is not None and said != sizes[kind]:
                problems.append(f"{doc}: says {said} {what}, the schema has {sizes[kind]}")
    return problems


CHECKS = (
    ("README.md", readme_drift),
    ("CLAUDE.md", claude_drift),
    ("CONTRIBUTING.md", contributing_drift),
)


def documented_fields_drift(root: Path = Path(".")) -> list[str]:
    schema = json.loads((root / SCHEMA).read_text(encoding="utf-8"))
    sets = schema_sets(schema)
    problems = []
    for doc, check in CHECKS:
        text = (root / doc).read_text(encoding="utf-8")
        problems += check(doc, text, sets) + count_drift(doc, text, sets)
    return problems


# --- the real schema against the real documents ----------------------------------

def test_the_schema_still_has_the_shape_the_lists_are_read_from():
    """If the schema were restructured so a set came out empty, every comparison below
    would pass against nothing."""
    sets = schema_sets(json.loads(SCHEMA.read_text(encoding="utf-8")))

    assert all(sets.values()), {kind: len(names) for kind, names in sets.items()}
    names = [n for kind, _ in KINDS for n in sets[kind]]
    assert len(names) == len(set(names)), "a field is in two of the schema's sets"


def test_the_documented_field_lists_match_the_schema():
    assert documented_fields_drift() == []


def test_a_field_the_schema_requires_in_both_places_is_in_one_set():
    schema = dict(SCHEMA_SMALL, **{"else": {"required": ["id", "sev", "aivss"]}})
    sets = schema_sets(schema)

    assert sets["draft"] == {"id", "title"}
    assert sets["published_only"] == {"sev", "aivss"}
    assert sets["optional"] == {"alpha", "beta"}


# --- each refusal the checks can make is shown, with its own message --------------
#
# A comparison that always finds the two sides equal would pass forever. These run each
# check against a small schema and small documents written here, with the one thing under
# test made to disagree, so a refusal can only come from it; the cases that must pass show
# the same checks accepting what they should.

SCHEMA_SMALL = {
    "required": ["id", "title"],
    "else": {"required": ["sev", "aivss"]},
    "properties": {
        "id": {}, "title": {}, "sev": {},
        "aivss": {"required": ["score"], "properties": {"score": {}, "notes": {}}},
        "alpha": {}, "beta": {},
    },
}
SETS = schema_sets(SCHEMA_SMALL)
REQUIRED = "id · title\nsev · aivss"
DRAFT = "id · title"
OPTIONAL = "alpha · beta"


def claude(required=REQUIRED, draft=DRAFT, optional=("alpha · beta",), required_head="**4 required fields**",
           draft_head='**Draft submit-required core** (`status: "draft"` only needs these 2):'):
    blocks = [f"{required_head} (for every `status` except `draft`):\n{required}" if required is not None else "",
              f"{draft_head}\n{draft}" if draft is not None else ""]
    blocks += [f"**Optional group {i}:**\n{names}" for i, names in enumerate(optional)]
    return "# CLAUDE\n\n" + "\n\n".join(b for b in blocks if b) + "\n"


def readme(required=REQUIRED, draft="`id`,\n`title`", optional="`alpha` · `beta` · `aivss.notes`",
           count="4", draft_word="two"):
    parts = ["# README", ""]
    if required is not None:
        parts += [f"**{count} required fields:**", "", "```", required, "```", ""]
    if draft is not None:
        parts += [f"`status: \"draft\"` records need only a reduced {draft_word}-field core ({draft}); the full "
                  f"{count}-field required set above applies.", ""]
    if optional is not None:
        parts += ["**All optional fields:**", optional, "", "`sev` is explained here, after the list.", ""]
    return "\n".join(parts)


def contributing(required=REQUIRED, count="4"):
    body = f"Fill every required field. The {count} required fields are:\n\n```\n{required}\n```\n" if required else ""
    return "# CONTRIBUTING\n\n" + body


def every_check(**overrides):
    docs = {"README.md": readme(), "CLAUDE.md": claude(), "CONTRIBUTING.md": contributing()}
    docs.update(overrides)
    return [p for doc, check in CHECKS for p in check(doc, docs[doc], SETS) + count_drift(doc, docs[doc], SETS)]


# cases that must pass

def test_documents_that_state_the_schema_pass_every_check():
    assert every_check() == []


def test_the_forms_the_real_claude_md_uses_are_read():
    """A heading that wraps over two lines, notes in parentheses that wrap too, a note
    holding a path, and an optional field group on two lines."""
    text = claude(optional=(
        "alpha (derived by\nscripts/write_alpha.py, never authored) ·\nbeta",
    )).replace("**Optional group 0:**", "**Optional group zero** (vendor-neutral only \u2014\nno config ever belongs here):")

    assert claude_drift("CLAUDE.md", text, SETS) == []


def test_several_optional_paragraphs_are_read_together():
    assert claude_drift("CLAUDE.md", claude(optional=("alpha", "beta")), SETS) == []


def test_claude_md_may_list_the_aivss_sub_fields_or_leave_them_out():
    assert claude_drift("CLAUDE.md", claude(optional=("alpha · beta · aivss.notes",)), SETS) == []


def test_a_list_in_any_order_passes():
    assert every_check(**{"CONTRIBUTING.md": contributing(required="aivss · sev\ntitle · id")}) == []


def test_text_after_a_list_is_not_read_as_part_of_it():
    assert readme_drift("README.md", readme(optional="`alpha` · `beta` · `aivss.notes`"), SETS) == []


# a field the schema has and a document lacks

def test_a_field_the_schema_has_and_a_document_lacks_is_reported():
    assert every_check(**{"CLAUDE.md": claude(required="id · title\nsev")}) == [
        "CLAUDE.md: aivss is required once a record is not a draft in the schema but is not in the required fields list"]
    assert every_check(**{"CLAUDE.md": claude(draft="id")}) == [
        "CLAUDE.md: title is part of the draft core in the schema but is not in the draft core"]
    assert every_check(**{"CLAUDE.md": claude(optional=("alpha",))}) == [
        "CLAUDE.md: beta is optional in the schema but is not in the optional field paragraphs"]
    assert every_check(**{"README.md": readme(optional="`alpha` · `beta`")}) == [
        "README.md: aivss.notes is an optional sub-field of aivss in the schema but is not in the optional fields list"]
    assert every_check(**{"README.md": readme(required="id · title\nsev")}) == [
        "README.md: aivss is required once a record is not a draft in the schema but is not in the required fields list"]
    assert every_check(**{"README.md": readme(draft="`id`")}) == [
        "README.md: title is part of the draft core in the schema but is not in the draft core sentence"]
    assert every_check(**{"CONTRIBUTING.md": contributing(required="id · title\nsev")}) == [
        "CONTRIBUTING.md: aivss is required once a record is not a draft in the schema but is not in the required fields list"]


# a field a document names that the schema does not have, or has elsewhere

def test_a_field_the_schema_does_not_have_is_reported():
    assert every_check(**{"CLAUDE.md": claude(optional=("alpha · beta · gamma",))}) == [
        "CLAUDE.md: gamma is in the optional field paragraphs but the schema has no such field"]
    assert every_check(**{"README.md": readme(optional="`alpha` · `beta` · `aivss.notes` · `gamma`")}) == [
        "README.md: gamma is in the optional fields list but the schema has no such field"]
    assert every_check(**{"CONTRIBUTING.md": contributing(required=REQUIRED + "\ngamma")}) == [
        "CONTRIBUTING.md: gamma is in the required fields list but the schema has no such field"]


def test_a_field_in_the_wrong_list_is_reported_with_where_the_schema_has_it():
    assert every_check(**{"CLAUDE.md": claude(draft="id · title · sev")}) == [
        "CLAUDE.md: sev is in the draft core but the schema has it as required once a record is not a draft"]
    assert every_check(**{"CONTRIBUTING.md": contributing(required=REQUIRED + "\nalpha")}) == [
        "CONTRIBUTING.md: alpha is in the required fields list but the schema has it as optional"]
    assert every_check(**{"README.md": readme(optional="`alpha` · `beta` · `aivss.notes` · `sev`")}) == [
        "README.md: sev is in the optional fields list but the schema has it as required once a record is not a draft"]


def test_an_aivss_sub_field_in_the_required_list_is_reported():
    assert every_check(**{"README.md": readme(required=REQUIRED + "\naivss.notes")}) == [
        "README.md: aivss.notes is in the required fields list but the schema has it as an optional sub-field of aivss"]


def test_the_wrong_name_for_a_field_is_reported_in_both_directions():
    """A renamed field is a field the schema has that the document lacks and a field the
    document names that the schema does not have."""
    assert every_check(**{"CLAUDE.md": claude(optional=("alpha · betta",))}) == [
        "CLAUDE.md: beta is optional in the schema but is not in the optional field paragraphs",
        "CLAUDE.md: betta is in the optional field paragraphs but the schema has no such field"]


# a field listed twice

def test_a_field_listed_twice_is_reported():
    assert every_check(**{"README.md": readme(optional="`alpha` · `beta` · `alpha` · `aivss.notes`")}) == [
        "README.md: alpha is in the optional fields list more than once"]


def test_a_field_listed_in_two_claude_md_paragraphs_is_reported():
    assert every_check(**{"CLAUDE.md": claude(optional=("alpha · beta", "beta"))}) == [
        "CLAUDE.md: beta is in the optional field paragraphs more than once"]


# a count that lags

def test_a_count_that_lags_is_reported_in_every_form_it_is_stated():
    assert every_check(**{"CONTRIBUTING.md": contributing(count="5")}) == [
        "CONTRIBUTING.md: says 5 required fields, the schema has 4"]
    assert every_check(**{"CLAUDE.md": claude(required_head="**5 required fields**")}) == [
        "CLAUDE.md: says 5 required fields, the schema has 4"]
    assert every_check(**{"CLAUDE.md": claude(draft_head="**Draft submit-required core** (only needs these 3):")}) == [
        "CLAUDE.md: says 3 fields in the draft core, the schema has 2"]
    assert every_check(**{"README.md": readme(count="5")}) == [
        "README.md: says 5 required fields, the schema has 4",
        "README.md: says 5 required fields, the schema has 4"]
    assert every_check(**{"README.md": readme(draft_word="three")}) == [
        "README.md: says 3 fields in the draft core, the schema has 2"]


def test_a_word_that_is_not_a_number_is_not_a_count():
    assert count_drift("README.md", "a single-field core and the other required fields", SETS) == []


# a list that is missing or unreadable

def test_a_list_a_document_lacks_is_reported():
    assert every_check(**{"CLAUDE.md": claude(required=None)}) == ["CLAUDE.md has no '**N required fields**' paragraph"]
    assert every_check(**{"CLAUDE.md": claude(draft=None)}) == ["CLAUDE.md has no '**Draft submit-required core**' paragraph"]
    assert every_check(**{"CLAUDE.md": claude(optional=())}) == ["CLAUDE.md has no '**Optional ...**' paragraph"]
    assert every_check(**{"README.md": readme(required=None)}) == ["README.md has no '**N required fields:**' and a fenced list"]
    assert every_check(**{"README.md": readme(draft=None)}) == ["README.md has no 'reduced N-field core (...)'"]
    assert every_check(**{"README.md": readme(optional=None)}) == ["README.md has no '**All optional fields:**' and a list"]
    assert every_check(**{"CONTRIBUTING.md": contributing(required=None)}) == [
        "CONTRIBUTING.md has no 'The N required fields are:' and a fenced list"]


def test_a_word_that_is_not_a_field_name_is_reported_not_skipped():
    assert every_check(**{"CONTRIBUTING.md": contributing(required=REQUIRED + "\nTitle")}) == [
        "CONTRIBUTING.md: could not read 'Title' in the required fields list; expected field names separated by ·"]


# the real documents through the path the real tests use

def test_drift_in_a_real_tree_is_reported_through_the_real_data_path(tmp_path):
    (tmp_path / "schema").mkdir()
    (tmp_path / SCHEMA).write_text(json.dumps(SCHEMA_SMALL), encoding="utf-8")
    (tmp_path / "README.md").write_text(readme(optional="`alpha` · `aivss.notes`"), encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text(claude(), encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text(contributing(count="9"), encoding="utf-8")

    assert documented_fields_drift(tmp_path) == [
        "README.md: beta is optional in the schema but is not in the optional fields list",
        "CONTRIBUTING.md: says 9 required fields, the schema has 4",
    ]
