"""The catalog-release workflow builds, verifies, attests and uploads the taxonomy with the other release files."""

import re
from pathlib import Path

WORKFLOW = Path(".github/workflows/catalog-release.yml")


def steps():
    text = WORKFLOW.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^      - name: ", text)[1:]
    return {p.split("\n", 1)[0].strip(): p for p in parts}


def step(prefix):
    found = [body for name, body in steps().items() if name.startswith(prefix)]
    assert len(found) == 1, (prefix, len(found))
    return found[0]


def test_the_header_says_the_release_carries_the_taxonomy():
    head = WORKFLOW.read_text(encoding="utf-8").split("\non:")[0]
    assert "ave-taxonomy.json" in head and "three data files" in head


def test_the_taxonomy_is_built_from_the_release_records_with_the_tag_the_date_and_the_assets_own_url():
    body = step("Build the release files")
    assert "python3 scripts/build_taxonomy.py" in body
    for needle in ('--records release/ave-records.json', '--release "v$VERSION"', "jq -r '.generated_at[:10]' release/ave-records.manifest.json",
                   '--download-uri "https://github.com/$GITHUB_REPOSITORY/releases/download/v$VERSION/ave-taxonomy.json"', "--out release/ave-taxonomy.json"):
        assert needle in body, needle


def test_the_taxonomy_is_built_before_the_checksums_and_the_checksums_cover_it():
    body = step("Build the release files")
    assert body.index("build_taxonomy.py") < body.index("sha256sum")
    assert "sha256sum ave-records.json ave-records.manifest.json ave-taxonomy.json > SHA256SUMS" in body


def test_the_verifier_is_told_which_repository_the_release_is_published_under():
    body = step("Verify the release files")
    assert "scripts/check_release_assets.py release" in body and '--repo "$GITHUB_REPOSITORY"' in body and '--tag "v$VERSION"' in body


def test_the_taxonomy_is_attested_with_the_other_data_files():
    body = step("Attest build provenance")
    for f in ("release/ave-records.json", "release/ave-records.manifest.json", "release/ave-taxonomy.json"):
        assert f in body, f


def test_the_taxonomy_and_the_checksums_are_uploaded_with_the_release():
    body = step("Create the release")
    assert "release/ave-taxonomy.json" in body and "release/SHA256SUMS" in body and "release/ave-records.json" in body


def test_no_run_step_interpolates_an_input_directly():
    # inputs reach the shell through env (VERSION, DRAFT) so a crafted input cannot inject commands
    text = WORKFLOW.read_text(encoding="utf-8")
    runs = re.findall(r"(?ms)^\s+run: (.*?)(?=^\s+- name:|\Z)", text)
    assert runs and not any("${{ inputs." in r for r in runs)
