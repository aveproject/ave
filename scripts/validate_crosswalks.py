# What: validates every file in crosswalks/ against schema/crosswalk-1.0.0.schema.json,
#       the same way scripts/validate_records.py validates records/ against the record
#       schema, plus four checks the schema cannot express on its own: that the $schema
#       a crosswalk declares is a schema this repository actually ships, that every
#       AVE identifier a crosswalk cites resolves to a record in records/, that a side
#       declaring itself unpinnable really has no repository behind it, and -- as a
#       warning, not a failure -- that a side stating a record count pins the tree it
#       counted
# Why:  every crosswalk in this repository declares
#       https://aveproject.org/schema/crosswalk-1.0.0.schema.json and, until that file
#       existed, nothing validated any of them. A dangling $schema URL is worse than
#       none: it reads as validated. The identifier check is the other half -- a
#       crosswalk row pointing at an AVE id that was never published, or that was
#       renumbered before the immutability rule, is a broken mapping that no schema
#       pattern can catch, because the id is well-formed and simply does not exist.
# How:  jsonschema.Draft202012Validator with format checking enabled, so the date and
#       uri formats in the schema are enforced rather than annotated, over every
#       crosswalks/*.json; then a set membership test of every cited id against the
#       ave_id values in records/. jsonschema implements the date checker itself but
#       registers uri only when rfc3986-validator is installed, so that package is a
#       dev dependency here; without it "format": "uri" parses and then constrains
#       nothing, and the ^https?:// pattern beside it is the only thing refusing a
#       bad url. The unpinnable check is offline and host-based by default, so a run
#       of this script needs no network and returns the same verdict everywhere;
#       --probe-unpinnable adds a git ls-remote for sides that are not on a known
#       repository host, and treats anything other than a clean answer as
#       inconclusive rather than as a finding.
import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import jsonschema

CROSSWALKS_DIR = Path("crosswalks")
RECORDS_DIR = Path("records")
SCHEMA_PATH = Path("schema/crosswalk-1.0.0.schema.json")

# Hosts where a URL of the form <host>/<owner>/<name> is a git repository by
# construction, so an endpoint declaring itself unpinnable while pointing at one
# is refuted without asking the network anything. Deliberately a short list of
# hosts where that shape is unambiguous rather than a guess at every forge.
REPOSITORY_HOSTS = {
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "www.bitbucket.org",
    "codeberg.org", "www.codeberg.org",
    "sr.ht", "git.sr.ht",
}

PROBE_TIMEOUT_SECONDS = 20


def known_ave_ids() -> set[str]:
    ids: set[str] = set()
    for path in sorted(RECORDS_DIR.glob("AVE-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        ave_id = record.get("ave_id")
        if isinstance(ave_id, str):
            ids.add(ave_id)
    return ids


def cited_ave_ids(node: object) -> set[str]:
    """Every value under an ave_id / primary_ave_id / ave_ids key, at any depth.

    Only these three keys are read. Prose fields mention identifiers too, and a
    substring sweep would flag a record named in a note as if it were a mapping
    target.
    """
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("ave_id", "primary_ave_id") and isinstance(value, str):
                found.add(value)
            elif key == "ave_ids" and isinstance(value, list):
                found.update(item for item in value if isinstance(item, str))
            found |= cited_ave_ids(value)
    elif isinstance(node, list):
        for item in node:
            found |= cited_ave_ids(item)
    return found


def commit_is_required(schema: dict) -> bool:
    """Whether the schema has promoted commit from optional to required.

    This is the escalation switch for the record-count check below, and it is
    read off the schema rather than held in a constant or a date: while commit
    is optional a stated count with no pin is a warning, and on the day commit
    appears in a required list in the endpoint definition the same finding
    becomes a failure. Nobody has to remember to flip anything, and the
    enforcement cannot arrive early or late, because there is only one fact and
    both the schema and the validator read it from the same place.

    A required list underneath `not` is the opposite claim, and 1.0.x contains
    one: a declared-unpinnable endpoint must *not* carry commit. Those subtrees
    are skipped, or forbidding the field would read as requiring it.
    """
    def promoted(node: object) -> bool:
        if isinstance(node, list):
            return any(promoted(item) for item in node)
        if not isinstance(node, dict):
            return False
        if "commit" in node.get("required", []):
            return True
        return any(promoted(value) for key, value in node.items() if key != "not")

    return promoted(schema.get("$defs", {}).get("endpoint", {}))


def build_validator(schema: dict) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )


def check_schema(document: dict, validator: jsonschema.Draft202012Validator) -> list[str]:
    return [f"schema: {e.message} (at {'/'.join(str(p) for p in e.path) or '<root>'})"
            for e in validator.iter_errors(document)]


def check_declared_schema_is_shipped(document: dict) -> list[str]:
    declared = document.get("$schema")
    if not isinstance(declared, str):
        return []
    filename = declared.rsplit("/", 1)[-1]
    if not (Path("schema") / filename).is_file():
        return [f"$schema declares {declared}, which this repository does not ship "
                f"as schema/{filename}"]
    return []


def check_ave_ids_resolve(document: dict, published: set[str]) -> list[str]:
    # Only the record-format ids are checked. ave-to-ast10.json carries free text
    # under gaps_in_ast10[].ave_id ("all 56 records"), which is a prose value in a
    # field whose name suggests otherwise; it is left alone here rather than
    # reported as a dangling record.
    return [f"cites {ave_id}, which is not a record in {RECORDS_DIR}/"
            for ave_id in sorted(cited_ave_ids(document) - published)
            if ave_id.startswith("AVE-") and len(ave_id) == len("AVE-0000-00000")]


def endpoints(document: dict) -> list[tuple[str, dict]]:
    return [(side, document[side]) for side in ("source", "target")
            if isinstance(document.get(side), dict)]


def is_repository_url(url: object) -> bool:
    """True when the URL is a repository on a known forge, by its shape alone.

    <host>/<owner>/<name> on one of REPOSITORY_HOSTS is a repository; a bare
    host, or a host with a single path segment, is not. Nothing else is judged
    here, because a project site and a repository are not distinguishable from
    a URL in the general case, which is what --probe-unpinnable is for.
    """
    if not isinstance(url, str):
        return False
    parsed = urlparse(url)
    if parsed.netloc.lower() not in REPOSITORY_HOSTS:
        return False
    return len([segment for segment in parsed.path.split("/") if segment]) >= 2


def check_declared_unpinnable_has_no_repository(document: dict) -> list[str]:
    """Refutes an unpinnable declaration that is contradicted by its own url.

    An endpoint saying it cannot be pinned is an exemption from the record-count
    warning below, and an exemption nobody can check is not a declaration: it is
    the box anything awkward gets put in. This is the offline half of checking
    it, and it only ever reports the case it has proved.
    """
    return [f"{side} declares pin_status unpinnable, but its url {endpoint.get('url')} "
            f"is a repository, which can be pinned"
            for side, endpoint in endpoints(document)
            if endpoint.get("pin_status") == "unpinnable"
            and is_repository_url(endpoint.get("url"))]


def probe_declared_unpinnable(document: dict) -> tuple[list[str], list[str]]:
    """The network half: asks git whether a declared-unpinnable url resolves.

    Returns (problems, notes). A problem is reported only when git ls-remote
    exits zero and names at least one ref, which proves a history exists. Every
    other outcome -- a non-zero exit, a timeout, no git on the path -- is
    inconclusive and goes in notes, because a url that is unreachable from here
    and a url with nothing behind it are indistinguishable from here.
    """
    problems: list[str] = []
    notes: list[str] = []
    for side, endpoint in endpoints(document):
        url = endpoint.get("url")
        if endpoint.get("pin_status") != "unpinnable" or not isinstance(url, str):
            continue
        if is_repository_url(url):
            continue  # already refuted offline; do not report it twice
        try:
            completed = subprocess.run(
                ["git", "ls-remote", "--heads", url],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            notes.append(f"{side}: probe of {url} did not run ({exc}); "
                         f"the unpinnable declaration is unchecked, not confirmed")
            continue
        if completed.returncode == 0 and completed.stdout.strip():
            problems.append(f"{side} declares pin_status unpinnable, but git ls-remote "
                            f"resolves {url} to a history, which can be pinned")
        else:
            notes.append(f"{side}: probe of {url} returned no history "
                         f"(git exit {completed.returncode}); the unpinnable "
                         f"declaration is unrefuted, which is not the same as verified")
    return problems, notes


def warn_stated_count_without_pin(document: dict) -> list[str]:
    """Soft warning only, while commit is optional in 1.0.x.

    A side stating how many records it counted, without pinning the tree it
    counted them in and without declaring that it cannot be pinned, cannot be
    re-derived by a reader: the corpus keeps moving, and a date does not
    identify a tree. That is the staleness this field exists to fix, but the
    check cannot hard-fail until commit is required, or it would go red on
    files already in the repository. See commit_is_required, which is what
    decides whether the caller reports this as a warning or as a failure.
    """
    return [f"{side} states record_count {endpoint['record_count']} but carries no "
            f"commit and does not declare pin_status unpinnable, so the count "
            f"cannot be re-derived from this file"
            for side, endpoint in endpoints(document)
            if "record_count" in endpoint
            and "commit" not in endpoint
            and endpoint.get("pin_status") != "unpinnable"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate every crosswalk in crosswalks/ against the crosswalk schema.")
    parser.add_argument(
        "--probe-unpinnable", action="store_true",
        help="additionally ask git ls-remote whether a declared-unpinnable side that "
             "is not on a known repository host resolves to a history. Needs network; "
             "reports a failure only on a clean positive answer.",
    )
    args = parser.parse_args()

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = build_validator(schema)
    unpinned_count_is_fatal = commit_is_required(schema)
    published = known_ave_ids()

    paths = sorted(CROSSWALKS_DIR.glob("*.json"))
    if not paths:
        print(f"FAIL: {CROSSWALKS_DIR}/ holds no .json files", file=sys.stderr)
        return 1

    failed = 0
    warned = 0
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        problems = (check_schema(document, validator)
                    + check_declared_schema_is_shipped(document)
                    + check_ave_ids_resolve(document, published)
                    + check_declared_unpinnable_has_no_repository(document))
        notes: list[str] = []
        if args.probe_unpinnable:
            probe_problems, notes = probe_declared_unpinnable(document)
            problems += probe_problems

        warnings = warn_stated_count_without_pin(document)
        if unpinned_count_is_fatal:
            problems += warnings
            warnings = []

        if problems:
            failed += 1
            print(f"FAIL {path}")
            for problem in problems:
                print(f"  {problem}")
        else:
            print(f"ok   {path}")
        for warning in warnings:
            # Reported, and deliberately not counted against the exit code.
            print(f"WARNING [{path.name}]: {warning}")
        for note in notes:
            print(f"note    [{path.name}]: {note}")
        warned += len(warnings)

    print(f"\n{len(paths) - failed}/{len(paths)} crosswalk(s) valid "
          f"against {SCHEMA_PATH}")
    if warned:
        print(f"{warned} warning(s): a stated record count that no commit pins and "
              f"no declaration exempts. These become failures when commit is required.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
