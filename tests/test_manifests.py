"""A manifest that states a sha256 must state the SHA-256 of the records file beside it.

Manifests are frozen together with their records files, so one that predates the
field cannot gain it later; those are skipped, and the skip says why. The moving
"latest" manifest is rebuilt on every change and must always carry the field.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest

DIST = Path("dist")
MANIFESTS = sorted(DIST.glob("ave-records-*.manifest.json"))
LATEST = "ave-records-latest.manifest.json"


# What: the records file that sits next to a manifest
# Why:  the manifest's sha256 describes that file and no other
# How:  swap the ".manifest.json" suffix for ".json"
def records_file_for(manifest: Path) -> Path:
    return manifest.with_name(manifest.name.replace(".manifest.json", ".json"))


def test_manifests_were_found():
    assert MANIFESTS, "no dist/ave-records-*.manifest.json found; run from the repository root"


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda path: path.name)
def test_manifest_sha256_matches_its_records_file(manifest):
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if "sha256" not in data:
        if manifest.name == LATEST:
            pytest.fail(f"{LATEST} must carry a sha256; rebuild dist with scripts/build-records.js")
        pytest.skip(f"{manifest.name} predates the sha256 field and is frozen")

    assert re.fullmatch(r"[0-9a-f]{64}", data["sha256"]), "sha256 must be 64 lowercase hex characters"
    records = records_file_for(manifest)
    assert records.exists(), f"{records} is missing"
    assert data["sha256"] == hashlib.sha256(records.read_bytes()).hexdigest(), (
        f"{manifest.name} sha256 does not match {records.name}"
    )
