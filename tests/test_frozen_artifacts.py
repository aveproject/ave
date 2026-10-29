"""Versioned files are frozen once published: a change ships in a new version instead.

Two checks. drift() compares every file in schema/frozen-artifacts.json with the
hash recorded for it. The ratchet compares the manifest with the one at the point
this change left its base branch, so an entry can be added but never removed or
rehashed; without it, editing a frozen file and its hash in one commit would pass.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

MANIFEST = Path("schema/frozen-artifacts.json")
NO_BASE = ("", "0000000000000000000000000000000000000000")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def drift(manifest=MANIFEST):
    m = json.loads(Path(manifest).read_text(encoding="utf-8"))
    out = []
    for path, want in sorted(m["files"].items()):
        if not Path(path).exists():
            out.append(f"{path}: frozen file is missing")
        elif sha(path) != want:
            out.append(f"{path}: changed after it was frozen; ship the change in a new version instead")
    return out


# What: every way a head manifest drops or alters what a base manifest froze
# Why:  adding an entry is how a version is frozen; removing or rehashing one is
#       how a frozen file would be silently unfrozen
# How:  each base entry must exist in the head with the identical hash
def regressions(base_files: dict, head_files: dict) -> list[str]:
    out = []
    for path, want in sorted(base_files.items()):
        if path not in head_files:
            out.append(f"{path}: entry removed from {MANIFEST}")
        elif head_files[path] != want:
            out.append(f"{path}: entry rehashed from {want[:12]} to {head_files[path][:12]}")
    return out


# What: the frozen manifest as it was where this change left BASE
# Why:  commits that landed on BASE afterwards are not this change's doing, so
#       comparing with BASE's tip (two-dot) would blame the change for them
# How:  git merge-base BASE HEAD, then git show <merge-base>:<manifest>; None when
#       the manifest did not exist there yet; RuntimeError when git cannot answer,
#       because a ratchet that cannot read the base must not report a clean change
def manifest_at_merge_base(base: str, repo: Path | None = None) -> dict | None:
    prefix = ["git"] if repo is None else ["git", "-C", str(repo)]
    found = subprocess.run(prefix + ["merge-base", base, "HEAD"], capture_output=True, text=True)
    if found.returncode != 0:
        raise RuntimeError(found.stderr.strip() or f"git merge-base exited {found.returncode}")
    shown = subprocess.run(
        prefix + ["show", f"{found.stdout.strip()}:{MANIFEST.as_posix()}"], capture_output=True, text=True
    )
    if shown.returncode != 0:
        return None
    return json.loads(shown.stdout)["files"]


def test_frozen_artifacts_are_unchanged():
    assert drift() == []


def test_the_moving_files_are_not_frozen():
    files = json.loads(MANIFEST.read_text(encoding="utf-8"))["files"]
    assert "schema/ave-record.schema.json" not in files
    assert not any("latest" in path for path in files)


def test_no_frozen_entry_is_removed_or_rehashed_since_the_base():
    base = os.environ.get("FROZEN_BASE", "")
    if base in NO_BASE:
        resolvable = subprocess.run(["git", "rev-parse", "--verify", "-q", "origin/develop"], capture_output=True)
        if resolvable.returncode != 0:
            pytest.skip("no FROZEN_BASE given and origin/develop is not available here")
        base = "origin/develop"
    base_files = manifest_at_merge_base(base)
    if base_files is None:
        pytest.skip(f"{MANIFEST} did not exist at the merge base with {base}; nothing was frozen before")
    head_files = json.loads(MANIFEST.read_text(encoding="utf-8"))["files"]
    assert regressions(base_files, head_files) == []


# --- fixtures: drift ------------------------------------------------------------


def _frozen_tree(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("a.json").write_text('{"a": 1}\n', encoding="utf-8")
    Path("b.json").write_text('{"b": 2}\n', encoding="utf-8")
    Path("frozen.json").write_text(
        json.dumps({"files": {"a.json": sha("a.json"), "b.json": sha("b.json")}}), encoding="utf-8"
    )


def test_a_clean_tree_reports_nothing(tmp_path, monkeypatch):
    _frozen_tree(tmp_path, monkeypatch)
    assert drift("frozen.json") == []


def test_a_one_byte_change_is_reported(tmp_path, monkeypatch):
    _frozen_tree(tmp_path, monkeypatch)
    Path("a.json").write_text('{"a": 2}\n', encoding="utf-8")
    assert drift("frozen.json") == ["a.json: changed after it was frozen; ship the change in a new version instead"]


def test_a_deleted_file_is_reported(tmp_path, monkeypatch):
    _frozen_tree(tmp_path, monkeypatch)
    Path("b.json").unlink()
    assert drift("frozen.json") == ["b.json: frozen file is missing"]


# --- fixtures: the ratchet ----------------------------------------------------------


def test_an_added_entry_passes_the_ratchet():
    assert regressions({"a": "1" * 64}, {"a": "1" * 64, "b": "2" * 64}) == []


def test_a_removed_entry_fails_the_ratchet():
    assert regressions({"a": "1" * 64, "b": "2" * 64}, {"a": "1" * 64}) == [f"b: entry removed from {MANIFEST}"]


def test_a_rehashed_entry_fails_the_ratchet():
    assert regressions({"a": "1" * 64}, {"a": "3" * 64}) == ["a: entry rehashed from 111111111111 to 333333333333"]


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        check=True, capture_output=True,
    )


def _commit_manifest(repo, files, message):
    (repo / "schema").mkdir(exist_ok=True)
    (repo / MANIFEST).write_text(json.dumps({"files": files}), encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def test_the_ratchet_compares_with_the_merge_base_not_the_moved_base(tmp_path):
    repo = tmp_path
    _git(repo, "init", "-q", "-b", "develop")
    _commit_manifest(repo, {"a": "1" * 64}, "freeze a")
    _git(repo, "checkout", "-q", "-b", "change")
    (repo / "unrelated.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "unrelated work on the change")
    _git(repo, "checkout", "-q", "develop")
    _commit_manifest(repo, {"a": "1" * 64, "b": "2" * 64}, "base moves on and freezes b")
    _git(repo, "checkout", "-q", "change")

    base_files = manifest_at_merge_base("develop", repo)
    head_files = json.loads((repo / MANIFEST).read_text(encoding="utf-8"))["files"]

    # three-dot: the change never had b, so it removed nothing
    assert regressions(base_files, head_files) == []
    # two-dot, against the moved base's tip, would wrongly blame the change for b
    tip_files = json.loads(
        subprocess.run(["git", "-C", str(repo), "show", f"develop:{MANIFEST.as_posix()}"],
                       capture_output=True, text=True, check=True).stdout
    )["files"]
    assert regressions(tip_files, head_files) == [f"b: entry removed from {MANIFEST}"]


def test_an_unreadable_base_is_an_error_not_a_pass(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "develop")
    _commit_manifest(tmp_path, {"a": "1" * 64}, "freeze a")
    with pytest.raises(RuntimeError):
        manifest_at_merge_base("no-such-ref", tmp_path)
