# What: verifies the three files of an AVE catalog release (ave-records.json,
#       ave-records.manifest.json, SHA256SUMS) against each other, against the
#       release tag and against the commit the release was built from.
# Why:  a catalog release is what implementers pin to, so each file must
#       describe the others exactly: a checksum that no longer matches, a
#       record count that drifted or a manifest naming the wrong commit would
#       each be pinned along with the release. The same script runs in the
#       catalog-release workflow before anything is published and on an
#       implementer's machine after download.
# How:  python scripts/check_release_assets.py <dir> --tag vX.Y.Z
#           [--git-dir <repo> | --commit <sha>]
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

RECORDS_FILE = "ave-records.json"
MANIFEST_FILE = "ave-records.manifest.json"
SUMS_FILE = "SHA256SUMS"
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
def check_sums(directory: Path) -> list[str]:
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
    for required in (RECORDS_FILE, MANIFEST_FILE):
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


# What: every check on one release directory, in the order they are reported
# Why:  main() and the tests both call this, so a check dropped from the
#       pipeline fails a test instead of passing silently
# How:  the tag's form, then SHA256SUMS, then the manifest
def release_errors(directory: Path, tag: str, git_dir: Path | None = None, commit: str | None = None) -> list[str]:
    errors = []
    if not TAG_PATTERN.fullmatch(tag):
        errors.append(f"tag {tag!r} is not vX.Y.Z")
    if commit is not None and not COMMIT_PATTERN.fullmatch(commit):
        errors.append(f"--commit {commit!r} is not a 40-character commit SHA")
        commit = None
    return errors + check_sums(directory) + check_manifest(directory, tag, git_dir, commit)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AVE catalog release: SHA256SUMS, the manifest, the records and the source commit."
    )
    parser.add_argument("directory", type=Path, help=f"directory holding {RECORDS_FILE}, {MANIFEST_FILE} and {SUMS_FILE}")
    parser.add_argument("--tag", required=True, help="the release tag, vX.Y.Z")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--git-dir", type=Path, help="a clone of aveproject/ave; source_commit must be the tag's commit there")
    source.add_argument("--commit", help="source_commit must be this full commit SHA (before the tag exists)")
    args = parser.parse_args(argv)

    errors = release_errors(args.directory, args.tag, args.git_dir, args.commit)
    if errors:
        for error in errors:
            print(error)
        print(f"\n{len(errors)} problem(s); this is not a verified AVE {args.tag} release.")
        return 1

    manifest = json.loads((args.directory / MANIFEST_FILE).read_text(encoding="utf-8"))
    checked = "the tag's commit" if args.git_dir else ("the given commit" if args.commit else "its form only")
    print(
        f"AVE {args.tag}: {manifest['record_count']} records on schema {manifest['schema_version']}, "
        f"checksums match, source_commit {manifest['source_commit']} (checked against {checked})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
