# What: verifies the files of an AVE catalog release (ave-records.json,
#       ave-records.manifest.json, ave-taxonomy.json, SHA256SUMS) against each other, against the
#       release tag and against the commit the release was built from.
# Why:  a catalog release is what implementers pin to, so each file must
#       describe the others exactly: a checksum that no longer matches, a
#       record count that drifted or a manifest naming the wrong commit would
#       each be pinned along with the release. The same script runs in the
#       catalog-release workflow before anything is published and on an
#       implementer's machine after download.
# How:  python scripts/check_release_assets.py <dir> --tag vX.Y.Z
#           [--git-dir <repo> | --commit <sha>] [--repo owner/name]
#       ave-taxonomy.json is regenerated from ave-records.json with
#       scripts/build_taxonomy.py and must match it byte for byte; releases from
#       v1.3.0 on must carry it, earlier releases need not.
#       --git-dir checks source_commit against the commit <tag> points at in
#       that repository; --commit checks it against a given commit instead (the
#       workflow, which runs before the tag exists). Exit 0 when every check
#       passes, 1 with one line per failure otherwise.
from __future__ import annotations  # an implementer may run this on Python 3.8 or later

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

try:  # imported as scripts.check_release_assets (tests) or run as a script from scripts/
    from scripts import build_taxonomy as bt
except ImportError:
    import build_taxonomy as bt

RECORDS_FILE = "ave-records.json"
MANIFEST_FILE = "ave-records.manifest.json"
SUMS_FILE = "SHA256SUMS"
TAXONOMY_FILE = "ave-taxonomy.json"
# The first release that carries the SARIF taxonomy. A release from this tag on without it is refused;
# an earlier one (v1.0.0 to v1.2.0 shipped before it existed) may omit it.
TAXONOMY_FROM = (1, 3, 0)
DEFAULT_REPO = "aveproject/ave"
TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
# sha256sum's own output: digest, a space, then " " (text) or "*" (binary), then the name
SUMS_LINE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")


# What: the SHA-256 of a file, as lowercase hex
# Why:  every checksum in a release is compared in this one form
# How:  hashlib over the file's bytes
def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# What: every way SHA256SUMS disagrees with the files beside it
# Why:  `sha256sum -c SHA256SUMS` is the first thing an implementer runs, so it
#       must cover both release files and match each byte for byte
# How:  parse each line in sha256sum format; refuse malformed lines and names
#       that leave the directory; compare each digest; require both files listed
def check_sums(directory: Path, extra_required=()) -> list[str]:
    sums = directory / SUMS_FILE
    if not sums.is_file():
        return [f"{SUMS_FILE} is missing"]
    errors = []
    listed = set()
    for number, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        match = SUMS_LINE.fullmatch(line)
        if not match:
            errors.append(f"{SUMS_FILE} line {number} is not in sha256sum format: {line!r}")
            continue
        digest, name = match.group(1).lower(), match.group(2)
        if "/" in name or "\\" in name or name in (".", ".."):
            errors.append(f"{SUMS_FILE} line {number} names a file outside the release: {name!r}")
            continue
        listed.add(name)
        target = directory / name
        if not target.is_file():
            errors.append(f"{SUMS_FILE} lists {name}, which is missing")
        elif sha256_of(target) != digest:
            errors.append(f"{SUMS_FILE}: {name} does not match its checksum")
    for required in (RECORDS_FILE, MANIFEST_FILE, *extra_required):
        if required not in listed:
            errors.append(f"{SUMS_FILE} does not list {required}")
    return errors


# What: the commit a tag points at in a local repository
# Why:  an annotated tag is an object of its own; source_commit must name the
#       commit under it, not the tag object
# How:  git rev-list -n 1 refs/tags/<tag>, which peels annotated tags and never
#       matches a branch of the same name; None when git fails
def commit_for_tag(git_dir: Path, tag: str) -> str | None:
    found = subprocess.run(
        ["git", "-C", str(git_dir), "rev-list", "-n", "1", f"refs/tags/{tag}", "--"], capture_output=True, text=True
    )
    if found.returncode != 0:
        return None
    return found.stdout.strip() or None


# What: every way the manifest disagrees with the records file, the tag and the
#       commit the release was built from
# Why:  the manifest is the release's own description of itself; each field an
#       implementer relies on is checked against the thing it describes
# How:  load both JSON files, then compare sha256, record_count, each record's
#       schema_version, release and source_commit in turn
def check_manifest(directory: Path, tag: str, git_dir: Path | None, commit: str | None) -> list[str]:
    records_path = directory / RECORDS_FILE
    manifest_path = directory / MANIFEST_FILE
    missing = [p.name for p in (records_path, manifest_path) if not p.is_file()]
    if missing:
        return [f"{name} is missing" for name in missing]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{MANIFEST_FILE} is not valid JSON: {exc}"]
    try:
        records = json.loads(records_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{RECORDS_FILE} is not valid JSON: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{MANIFEST_FILE} is not a JSON object"]
    if not isinstance(records, list):
        return [f"{RECORDS_FILE} is not a JSON array"]

    errors = []
    if manifest.get("sha256") != sha256_of(records_path):
        errors.append(f"{MANIFEST_FILE} sha256 {manifest.get('sha256')!r} is not the SHA-256 of {RECORDS_FILE}")
    if manifest.get("record_count") != len(records):
        errors.append(f"{MANIFEST_FILE} record_count {manifest.get('record_count')!r} but {RECORDS_FILE} has {len(records)}")
    declared = manifest.get("schema_version")
    for index, record in enumerate(records):
        version = record.get("schema_version") if isinstance(record, dict) else None
        if version != declared:
            rid = record.get("ave_id", f"record {index}") if isinstance(record, dict) else f"record {index}"
            errors.append(f"{rid} declares schema_version {version!r}, the manifest says {declared!r}")
    if manifest.get("release") != tag:
        errors.append(f"{MANIFEST_FILE} release {manifest.get('release')!r} is not the tag {tag!r}")

    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or not COMMIT_PATTERN.fullmatch(source_commit):
        errors.append(f"{MANIFEST_FILE} source_commit {source_commit!r} is not a 40-character commit SHA")
    elif commit is not None and source_commit != commit:
        errors.append(f"{MANIFEST_FILE} source_commit {source_commit} is not the commit being released, {commit}")
    elif git_dir is not None:
        tagged = commit_for_tag(git_dir, tag)
        if tagged is None:
            errors.append(f"tag {tag} was not found in {git_dir}")
        elif source_commit != tagged:
            errors.append(f"{MANIFEST_FILE} source_commit {source_commit} is not {tag}'s commit, {tagged}")
    return errors


# What: whether a release must carry the taxonomy, from its tag
# Why:  releases before the taxonomy existed stay valid; from TAXONOMY_FROM on it is part of the release
# How:  compare the tag's (major, minor, patch) with TAXONOMY_FROM; a malformed tag requires nothing here (the tag check reports it)
def taxonomy_required(tag: str) -> bool:
    match = TAG_PATTERN.fullmatch(tag)
    return bool(match) and tuple(int(g) for g in match.groups()) >= TAXONOMY_FROM


# What: every way ave-taxonomy.json disagrees with the release it ships in
# Why:  tools copy this file into their SARIF output, so a wrong guid, version, link or taxon would be copied
#       with it; the only trustworthy file is the one the generator produces from the release's own records
# How:  regenerate it from ave-records.json with the tag, the manifest's date and the asset's own URL, and
#       compare byte for byte; when it differs, name the fields and taxa that differ before the generic message
def check_taxonomy(directory: Path, tag: str, repo: str = DEFAULT_REPO) -> list[str]:
    path = directory / TAXONOMY_FILE
    if not path.is_file():
        return [f"{TAXONOMY_FILE} is missing (releases from v{'.'.join(map(str, TAXONOMY_FROM))} carry it)"] if taxonomy_required(tag) else []
    try:
        records = json.loads((directory / RECORDS_FILE).read_text(encoding="utf-8"))
        manifest = json.loads((directory / MANIFEST_FILE).read_text(encoding="utf-8"))
        actual_text = path.read_text(encoding="utf-8")
        actual = json.loads(actual_text)
    except (OSError, ValueError) as exc:
        return [f"{TAXONOMY_FILE} cannot be checked, a release file is unreadable or not JSON: {exc}"]
    if not (isinstance(records, list) and isinstance(manifest, dict) and isinstance(actual, dict) and TAG_PATTERN.fullmatch(tag)):
        return [f"{TAXONOMY_FILE} cannot be checked against malformed records, manifest or tag"]
    date = str(manifest.get("generated_at", ""))[:10]
    uri = f"https://github.com/{repo}/releases/download/{tag}/{TAXONOMY_FILE}"
    try:
        expected = bt.build(records, release=tag, release_date=date, download_uri=uri)
    except (ValueError, KeyError, TypeError) as exc:
        return [f"{TAXONOMY_FILE} cannot be regenerated from {RECORDS_FILE}: {exc}"]
    if actual_text == bt.dumps(expected):
        return []
    errors = []
    for key in ("guid", "name", "version", "semanticVersion", "releaseDateUtc", "downloadUri", "isComprehensive"):
        if actual.get(key) != expected.get(key):
            errors.append(f"{TAXONOMY_FILE} {key} is {actual.get(key)!r}, expected {expected.get(key)!r}")
    have = {t.get("id"): t for t in actual.get("taxa", []) if isinstance(t, dict)}
    want = {t["id"]: t for t in expected["taxa"]}
    for missing in sorted(set(want) - set(have)):
        errors.append(f"{TAXONOMY_FILE} has no taxon for {missing}, which is in {RECORDS_FILE}")
    for extra in sorted(set(have) - set(want)):
        errors.append(f"{TAXONOMY_FILE} has a taxon for {extra}, which is not in {RECORDS_FILE}")
    for common in sorted(set(have) & set(want)):
        if have[common] != want[common]:
            errors.append(f"{TAXONOMY_FILE} taxon {common} is not what {RECORDS_FILE} produces")
    return errors or [f"{TAXONOMY_FILE} is not what scripts/build_taxonomy.py produces from {RECORDS_FILE} (same content, different bytes)"]


# What: every check on one release directory, in the order they are reported
# Why:  main() and the tests both call this, so a check dropped from the
#       pipeline fails a test instead of passing silently
# How:  the tag's form, then SHA256SUMS, then the manifest, then the taxonomy
def release_errors(directory: Path, tag: str, git_dir: Path | None = None, commit: str | None = None, repo: str = DEFAULT_REPO) -> list[str]:
    errors = []
    if not TAG_PATTERN.fullmatch(tag):
        errors.append(f"tag {tag!r} is not vX.Y.Z")
    if commit is not None and not COMMIT_PATTERN.fullmatch(commit):
        errors.append(f"--commit {commit!r} is not a 40-character commit SHA")
        commit = None
    needs = (TAXONOMY_FILE,) if (directory / TAXONOMY_FILE).is_file() or taxonomy_required(tag) else ()
    return errors + check_sums(directory, needs) + check_manifest(directory, tag, git_dir, commit) + check_taxonomy(directory, tag, repo)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AVE catalog release: SHA256SUMS, the manifest, the records and the source commit."
    )
    parser.add_argument("directory", type=Path, help=f"directory holding {RECORDS_FILE}, {MANIFEST_FILE} and {SUMS_FILE}")
    parser.add_argument("--tag", required=True, help="the release tag, vX.Y.Z")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--git-dir", type=Path, help="a clone of aveproject/ave; source_commit must be the tag's commit there")
    source.add_argument("--commit", help="source_commit must be this full commit SHA (before the tag exists)")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="owner/name the release is published under; the taxonomy's downloadUri must point there")
    args = parser.parse_args(argv)

    errors = release_errors(args.directory, args.tag, args.git_dir, args.commit, args.repo)
    if errors:
        for error in errors:
            print(error)
        print(f"\n{len(errors)} problem(s); this is not a verified AVE {args.tag} release.")
        return 1

    manifest = json.loads((args.directory / MANIFEST_FILE).read_text(encoding="utf-8"))
    checked = "the tag's commit" if args.git_dir else ("the given commit" if args.commit else "its form only")
    taxonomy = (
        f" ave-taxonomy.json regenerated from the records and matches ({manifest['record_count']} taxa)."
        if (args.directory / TAXONOMY_FILE).is_file()
        else ""
    )
    print(
        f"AVE {args.tag}: {manifest['record_count']} records on schema {manifest['schema_version']}, "
        f"checksums match, source_commit {manifest['source_commit']} (checked against {checked})." + taxonomy
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
