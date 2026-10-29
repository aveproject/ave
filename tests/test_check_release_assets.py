"""scripts/check_release_assets.py refuses every way a catalog release can disagree with itself."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_release_assets as cra

TAG = "v1.2.0"
COMMIT = "a" * 40


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_sums(directory: Path, names=("ave-records.json", "ave-records.manifest.json")) -> None:
    lines = [f"{_sha(directory / name)}  {name}" for name in names]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _release(directory: Path, records=None, commit=COMMIT, **manifest_overrides) -> Path:
    """A consistent release, built the way the workflow builds one, with the manifest
    then overridden and SHA256SUMS written last, so each test breaks one thing only."""
    directory.mkdir(parents=True, exist_ok=True)
    if records is None:
        records = [
            {"ave_id": "AVE-2026-00001", "schema_version": "1.2.0"},
            {"ave_id": "AVE-2026-00002", "schema_version": "1.2.0"},
        ]
    records_path = directory / "ave-records.json"
    records_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "release": TAG,
        "schema_version": "1.2.0",
        "record_count": len(records),
        "generated_at": "2026-11-01T00:00:00.000Z",
        "source": "https://github.com/aveproject/ave",
        "sha256": _sha(records_path),
        "source_commit": commit,
    }
    manifest.update(manifest_overrides)
    (directory / "ave-records.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _write_sums(directory)
    return directory


def test_a_consistent_release_passes(tmp_path):
    assert cra.release_errors(_release(tmp_path), TAG, commit=COMMIT) == []


def test_without_a_commit_source_only_the_form_of_source_commit_is_checked(tmp_path):
    assert cra.release_errors(_release(tmp_path), TAG) == []


# --- SHA256SUMS -------------------------------------------------------------------


def test_a_file_changed_after_its_checksum_is_refused(tmp_path):
    release = _release(tmp_path)
    (release / "ave-records.json").write_text("[]\n", encoding="utf-8")

    errors = cra.check_sums(release)

    assert errors == ["SHA256SUMS: ave-records.json does not match its checksum"]


def test_sums_must_list_both_files(tmp_path):
    release = _release(tmp_path)
    _write_sums(release, names=("ave-records.json",))

    assert cra.check_sums(release) == ["SHA256SUMS does not list ave-records.manifest.json"]


def test_missing_sums_file_is_refused(tmp_path):
    release = _release(tmp_path)
    (release / "SHA256SUMS").unlink()

    assert cra.check_sums(release) == ["SHA256SUMS is missing"]


def test_a_malformed_sums_line_is_refused(tmp_path):
    release = _release(tmp_path)
    with (release / "SHA256SUMS").open("a", encoding="utf-8") as sums:
        sums.write("not a checksum line\n")

    errors = cra.check_sums(release)

    assert len(errors) == 1 and "not in sha256sum format" in errors[0]


def test_a_sums_line_naming_a_file_outside_the_release_is_refused(tmp_path):
    release = _release(tmp_path / "release")
    (tmp_path / "elsewhere.json").write_text("{}", encoding="utf-8")
    with (release / "SHA256SUMS").open("a", encoding="utf-8") as sums:
        sums.write(f"{_sha(tmp_path / 'elsewhere.json')}  ../elsewhere.json\n")

    errors = cra.check_sums(release)

    assert errors == ["SHA256SUMS line 3 names a file outside the release: '../elsewhere.json'"]


def test_a_sums_line_for_a_missing_file_is_refused(tmp_path):
    release = _release(tmp_path)
    with (release / "SHA256SUMS").open("a", encoding="utf-8") as sums:
        sums.write(f"{'0' * 64}  gone.json\n")

    assert cra.check_sums(release) == ["SHA256SUMS lists gone.json, which is missing"]


def test_binary_mode_sums_lines_are_accepted(tmp_path):
    release = _release(tmp_path)
    text = (release / "SHA256SUMS").read_text(encoding="utf-8").replace("  ave-", " *ave-")
    (release / "SHA256SUMS").write_text(text, encoding="utf-8")

    assert cra.check_sums(release) == []


# --- the manifest -------------------------------------------------------------------


def test_a_manifest_sha256_that_is_not_the_records_file_is_refused(tmp_path):
    release = _release(tmp_path, sha256="0" * 64)

    errors = cra.release_errors(release, TAG, commit=COMMIT)

    assert len(errors) == 1 and "is not the SHA-256 of ave-records.json" in errors[0]


def test_a_record_count_that_is_not_the_array_length_is_refused(tmp_path):
    release = _release(tmp_path, record_count=3)

    assert cra.release_errors(release, TAG, commit=COMMIT) == [
        "ave-records.manifest.json record_count 3 but ave-records.json has 2"
    ]


def test_a_record_on_another_schema_version_is_refused(tmp_path):
    records = [
        {"ave_id": "AVE-2026-00001", "schema_version": "1.2.0"},
        {"ave_id": "AVE-2026-00002", "schema_version": "1.1.0"},
    ]
    release = _release(tmp_path, records=records)

    assert cra.release_errors(release, TAG, commit=COMMIT) == [
        "AVE-2026-00002 declares schema_version '1.1.0', the manifest says '1.2.0'"
    ]


def test_a_release_field_that_is_not_the_tag_is_refused(tmp_path):
    release = _release(tmp_path, release="v1.1.0")

    assert cra.release_errors(release, TAG, commit=COMMIT) == [
        "ave-records.manifest.json release 'v1.1.0' is not the tag 'v1.2.0'"
    ]


def test_a_missing_release_field_is_refused(tmp_path):
    release = _release(tmp_path)
    manifest = json.loads((release / "ave-records.manifest.json").read_text(encoding="utf-8"))
    del manifest["release"]
    (release / "ave-records.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _write_sums(release)

    assert cra.release_errors(release, TAG, commit=COMMIT) == [
        "ave-records.manifest.json release None is not the tag 'v1.2.0'"
    ]


@pytest.mark.parametrize("bad", [None, "abc123", "A" * 40, "a" * 39, "a" * 41])
def test_a_source_commit_that_is_not_a_full_sha_is_refused(tmp_path, bad):
    release = _release(tmp_path, source_commit=bad)

    errors = cra.release_errors(release, TAG)

    assert len(errors) == 1 and "is not a 40-character commit SHA" in errors[0]


def test_a_source_commit_that_is_not_the_given_commit_is_refused(tmp_path):
    release = _release(tmp_path)

    errors = cra.release_errors(release, TAG, commit="b" * 40)

    assert errors == [f"ave-records.manifest.json source_commit {COMMIT} is not the commit being released, {'b' * 40}"]


def test_a_malformed_commit_option_is_refused(tmp_path):
    errors = cra.release_errors(_release(tmp_path), TAG, commit="HEAD")

    assert errors == ["--commit 'HEAD' is not a 40-character commit SHA"]


@pytest.mark.parametrize("bad", ["1.2.0", "v1.2", "v1.2.0-rc1", "v01.2.0"])
def test_a_tag_that_is_not_vxyz_is_refused(tmp_path, bad):
    release = _release(tmp_path, release=bad)

    errors = cra.release_errors(release, bad)

    assert errors == [f"tag {bad!r} is not vX.Y.Z"]


def test_unreadable_json_is_refused_not_crashed_on(tmp_path):
    release = _release(tmp_path)
    (release / "ave-records.manifest.json").write_text("{not json", encoding="utf-8")
    _write_sums(release)

    errors = cra.release_errors(release, TAG)

    assert len(errors) == 1 and "is not valid JSON" in errors[0]


# --- against a real tag -------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def tagged_repo(tmp_path):
    """A repository whose v1.2.0 is an annotated tag, so the tag object and its
    commit have different SHAs, plus a later commit that is not the tag."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "release me")
    _git(repo, "tag", "-a", TAG, "-m", "AVE v1.2.0")
    tagged = _git(repo, "rev-parse", "HEAD")
    (repo / "b.txt").write_text("b", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "after the release")
    return repo, tagged, _git(repo, "rev-parse", "HEAD"), _git(repo, "rev-parse", TAG)


def test_source_commit_matches_the_annotated_tags_commit(tmp_path, tagged_repo):
    repo, tagged, _, tag_object = tagged_repo
    assert tag_object != tagged  # the check below must peel the tag, not compare the tag object

    release = _release(tmp_path / "release", commit=tagged)

    assert cra.release_errors(release, TAG, git_dir=repo) == []


def test_source_commit_from_another_commit_is_refused_against_the_tag(tmp_path, tagged_repo):
    repo, tagged, later, _ = tagged_repo
    release = _release(tmp_path / "release", commit=later)

    assert cra.release_errors(release, TAG, git_dir=repo) == [
        f"ave-records.manifest.json source_commit {later} is not v1.2.0's commit, {tagged}"
    ]


def test_a_tag_missing_from_the_repository_is_refused(tmp_path, tagged_repo):
    repo, tagged, _, _ = tagged_repo
    release = _release(tmp_path / "release", commit=tagged, release="v9.9.9")

    assert cra.release_errors(release, "v9.9.9", git_dir=repo) == [f"tag v9.9.9 was not found in {repo}"]


def test_a_branch_named_like_the_tag_does_not_stand_in_for_it(tmp_path, tagged_repo):
    repo, tagged, later, _ = tagged_repo
    _git(repo, "branch", "v9.9.9")  # a branch, at the later commit, with a tag's name
    release = _release(tmp_path / "release", commit=later, release="v9.9.9")

    assert cra.release_errors(release, "v9.9.9", git_dir=repo) == [f"tag v9.9.9 was not found in {repo}"]


# --- the command line ---------------------------------------------------------------


def test_main_passes_a_consistent_release(tmp_path, capsys):
    release = _release(tmp_path)

    assert cra.main([str(release), "--tag", TAG, "--commit", COMMIT]) == 0
    assert "2 records on schema 1.2.0" in capsys.readouterr().out


def test_main_fails_and_lists_each_problem(tmp_path, capsys):
    release = _release(tmp_path, record_count=5, release="v1.1.0")

    assert cra.main([str(release), "--tag", TAG, "--commit", COMMIT]) == 1
    out = capsys.readouterr().out
    assert "record_count 5" in out and "release 'v1.1.0'" in out and "2 problem(s)" in out


def test_git_dir_and_commit_cannot_both_be_given(tmp_path):
    with pytest.raises(SystemExit):
        cra.main([str(_release(tmp_path)), "--tag", TAG, "--commit", COMMIT, "--git-dir", str(tmp_path)])
