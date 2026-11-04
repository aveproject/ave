"""scripts/check_release_assets.py and the taxonomy asset: a release carries the file the generator produces from its own records."""

import hashlib
import json
from pathlib import Path

import pytest

from scripts import build_taxonomy as bt
from scripts import check_release_assets as cra

COMMIT = "b" * 40
REPO = "aveproject/ave"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _records():
    return [
        {"ave_id": "AVE-2026-00001", "title": "Class one", "status": "active", "severity": "HIGH", "schema_version": "1.3.0",
         "detection_stage": "static_detection", "attack_class": "A - one", "behavioral_fingerprint": "One thing.", "aivss": {"aivss_score": 7.5}},
        {"ave_id": "AVE-2026-00002", "title": "Class two", "status": "rejected", "severity": "MEDIUM", "schema_version": "1.3.0",
         "detection_stage": "runtime_observed", "attack_class": "A - two", "behavioral_fingerprint": "Two things.", "aivss": {"aivss_score": 5.0},
         "rejection_reason": "https://example.org/decision"},
    ]


def release(directory: Path, tag="v1.3.0", taxonomy=True, sums=True, records=None, **override):
    """A consistent release built the way the workflow builds one; `override` replaces fields of the taxonomy."""
    directory.mkdir(parents=True, exist_ok=True)
    records = _records() if records is None else records
    rpath = directory / "ave-records.json"
    rpath.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    manifest = {"release": tag, "schema_version": "1.3.0", "record_count": len(records), "generated_at": "2026-11-05T09:30:00.000Z",
                "source": "https://github.com/aveproject/ave", "sha256": _sha(rpath), "source_commit": COMMIT}
    (directory / "ave-manifest.tmp").write_text("", encoding="utf-8")
    (directory / "ave-manifest.tmp").unlink()
    (directory / "ave-records.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    names = ["ave-records.json", "ave-records.manifest.json"]
    if taxonomy:
        comp = bt.build(records, release=tag, release_date="2026-11-05", download_uri=f"https://github.com/{REPO}/releases/download/{tag}/ave-taxonomy.json")
        comp.update(override)
        (directory / "ave-taxonomy.json").write_text(bt.dumps(comp), encoding="utf-8")
        names.append("ave-taxonomy.json")
    if sums:
        (directory / "SHA256SUMS").write_text("".join(f"{_sha(directory / n)}  {n}\n" for n in names), encoding="utf-8")
    return directory


def errors(directory, tag="v1.3.0", **kw):
    return cra.release_errors(directory, tag, commit=COMMIT, **kw)


def test_a_consistent_release_with_its_taxonomy_passes(tmp_path):
    assert errors(release(tmp_path)) == []


def test_a_release_from_v1_3_0_without_the_taxonomy_is_refused(tmp_path):
    out = errors(release(tmp_path, taxonomy=False))
    assert any("ave-taxonomy.json is missing" in e for e in out)


@pytest.mark.parametrize("tag,required", [("v1.2.9", False), ("v1.3.0", True), ("v1.3.1", True), ("v2.0.0", True), ("v1.10.0", True), ("v0.9.9", False)])
def test_the_taxonomy_is_required_from_the_first_taxonomy_release_on(tmp_path, tag, required):
    out = errors(release(tmp_path, tag=tag, taxonomy=False), tag=tag)
    assert any("ave-taxonomy.json is missing" in e for e in out) is required


def test_an_earlier_release_with_no_taxonomy_still_passes(tmp_path):
    assert errors(release(tmp_path, tag="v1.2.0", taxonomy=False), tag="v1.2.0") == []


def test_an_earlier_release_that_has_a_taxonomy_is_checked_like_any_other(tmp_path):
    assert errors(release(tmp_path, tag="v1.2.0"), tag="v1.2.0") == []
    out = errors(release(tmp_path / "bad", tag="v1.2.0", version="9.9.9"), tag="v1.2.0")
    assert any("version" in e for e in out)


def test_a_taxonomy_missing_from_sha256sums_is_refused(tmp_path):
    d = release(tmp_path)
    (d / "SHA256SUMS").write_text("".join(f"{_sha(d / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json")), encoding="utf-8")
    assert "SHA256SUMS does not list ave-taxonomy.json" in errors(d)


def test_a_taxonomy_changed_after_its_checksum_is_refused(tmp_path):
    d = release(tmp_path)
    (d / "ave-taxonomy.json").write_text((d / "ave-taxonomy.json").read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert "SHA256SUMS: ave-taxonomy.json does not match its checksum" in errors(d)


@pytest.mark.parametrize("field,value", [("version", "9.9.9"), ("semanticVersion", "9.9.9"), ("releaseDateUtc", "2020-01-01"), ("guid", "00000000-0000-4000-8000-000000000000"),
                                         ("downloadUri", "https://example.org/ave-taxonomy.json"), ("isComprehensive", False), ("name", "Other")])
def test_a_taxonomy_header_field_that_is_not_the_releases_is_refused(tmp_path, field, value):
    out = errors(release(tmp_path, **{field: value}))
    assert any(e.startswith(f"ave-taxonomy.json {field} is {value!r}") for e in out), out


def test_a_taxonomy_that_points_at_another_repository_is_refused(tmp_path):
    out = errors(release(tmp_path), repo="someone/fork")
    assert any("downloadUri" in e for e in out)
    assert errors(release(tmp_path / "ok", ), repo=REPO) == []


def test_a_missing_taxon_is_refused_and_named(tmp_path):
    d = release(tmp_path)
    comp = json.loads((d / "ave-taxonomy.json").read_text(encoding="utf-8")); comp["taxa"].pop()
    (d / "ave-taxonomy.json").write_text(bt.dumps(comp), encoding="utf-8")
    (d / "SHA256SUMS").write_text("".join(f"{_sha(d / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json", "ave-taxonomy.json")), encoding="utf-8")
    assert "ave-taxonomy.json has no taxon for AVE-2026-00002, which is in ave-records.json" in errors(d)


def test_an_extra_taxon_is_refused_and_named(tmp_path):
    d = release(tmp_path)
    comp = json.loads((d / "ave-taxonomy.json").read_text(encoding="utf-8")); comp["taxa"].append({"id": "AVE-2026-00099", "name": "Invented"})
    (d / "ave-taxonomy.json").write_text(bt.dumps(comp), encoding="utf-8")
    (d / "SHA256SUMS").write_text("".join(f"{_sha(d / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json", "ave-taxonomy.json")), encoding="utf-8")
    assert "ave-taxonomy.json has a taxon for AVE-2026-00099, which is not in ave-records.json" in errors(d)


def test_a_taxon_that_is_not_what_its_record_produces_is_refused(tmp_path):
    d = release(tmp_path)
    comp = json.loads((d / "ave-taxonomy.json").read_text(encoding="utf-8")); comp["taxa"][0]["name"] = "Renamed"
    (d / "ave-taxonomy.json").write_text(bt.dumps(comp), encoding="utf-8")
    (d / "SHA256SUMS").write_text("".join(f"{_sha(d / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json", "ave-taxonomy.json")), encoding="utf-8")
    assert "ave-taxonomy.json taxon AVE-2026-00001 is not what ave-records.json produces" in errors(d)


def test_the_same_content_in_other_bytes_is_refused(tmp_path):
    d = release(tmp_path)
    comp = json.loads((d / "ave-taxonomy.json").read_text(encoding="utf-8"))
    (d / "ave-taxonomy.json").write_text(json.dumps(comp, indent=4), encoding="utf-8")
    (d / "SHA256SUMS").write_text("".join(f"{_sha(d / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json", "ave-taxonomy.json")), encoding="utf-8")
    assert any("same content, different bytes" in e for e in errors(d))


def test_a_taxonomy_that_is_not_json_is_refused_not_crashed_on(tmp_path):
    d = release(tmp_path)
    (d / "ave-taxonomy.json").write_text("{not json", encoding="utf-8")
    (d / "SHA256SUMS").write_text("".join(f"{_sha(d / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json", "ave-taxonomy.json")), encoding="utf-8")
    assert any("cannot be checked" in e for e in errors(d))


def _with_stand_in_taxonomy(directory: Path, records):
    """A release whose taxonomy was written by some other tool, because the generator refuses these records."""
    release(directory, taxonomy=False, records=records)
    (directory / "ave-taxonomy.json").write_text("{}\n", encoding="utf-8")
    (directory / "SHA256SUMS").write_text("".join(f"{_sha(directory / n)}  {n}\n" for n in ("ave-records.json", "ave-records.manifest.json", "ave-taxonomy.json")), encoding="utf-8")
    return directory


def test_records_the_generator_cannot_use_are_reported_not_crashed_on(tmp_path):
    out = errors(_with_stand_in_taxonomy(tmp_path / "dup", _records() + [_records()[0]]))
    assert any("cannot be regenerated" in e and "duplicate" in e for e in out)
    out = errors(_with_stand_in_taxonomy(tmp_path / "bad", [{"schema_version": "1.3.0"}]))
    assert any("cannot be regenerated" in e for e in out)


def test_main_passes_a_consistent_release_and_names_what_it_checked(tmp_path, capsys):
    d = release(tmp_path)
    assert cra.main([str(d), "--tag", "v1.3.0", "--commit", COMMIT]) == 0
    out = capsys.readouterr().out
    assert "AVE v1.3.0: 2 records" in out and "ave-taxonomy.json regenerated from the records and matches (2 taxa)" in out


def test_main_does_not_claim_a_taxonomy_check_for_a_release_without_one(tmp_path, capsys):
    d = release(tmp_path, tag="v1.2.0", taxonomy=False)
    assert cra.main([str(d), "--tag", "v1.2.0", "--commit", COMMIT]) == 0
    assert "ave-taxonomy.json" not in capsys.readouterr().out


def test_main_fails_a_release_without_its_taxonomy(tmp_path, capsys):
    d = release(tmp_path, taxonomy=False)
    assert cra.main([str(d), "--tag", "v1.3.0", "--commit", COMMIT]) == 1
    assert "ave-taxonomy.json is missing" in capsys.readouterr().out


def test_main_takes_the_repository_the_release_is_published_under(tmp_path, capsys):
    d = release(tmp_path)
    assert cra.main([str(d), "--tag", "v1.3.0", "--commit", COMMIT, "--repo", "someone/fork"]) == 1
    assert "downloadUri" in capsys.readouterr().out
