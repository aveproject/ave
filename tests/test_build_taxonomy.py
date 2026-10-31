import copy
import hashlib
import json
import os
import urllib.request
import uuid
from pathlib import Path

import pytest

from scripts import ave_conformance as C
from scripts import build_taxonomy as bt

SARIF_COMMIT = "1742a253eb654bf8a4ed7c60eaef7412b2c23553"
SARIF_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
SARIF_URL = f"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/{SARIF_COMMIT}/sarif-2.1/schema/sarif-schema-2.1.0.json"
RECORDS = Path("dist/ave-records-latest.json")


def records():
    return json.loads(RECORDS.read_text(encoding="utf-8"))


def rec(i=1, **kw):
    r = {"ave_id": f"AVE-2026-{i:05d}", "title": f"Class {i}", "status": "active", "severity": "HIGH",
         "detection_stage": "static_detection", "attack_class": "Example - Class", "behavioral_fingerprint": "A component does a thing.",
         "aivss": {"aivss_score": 7.5}}
    r.update(kw)
    return r


def sarif_schema():
    """The official OASIS schema at a pinned commit and hash. Offline, the test is skipped locally and fails in CI."""
    path = os.environ.get("SARIF_SCHEMA_FILE")
    try:
        data = Path(path).read_bytes() if path else urllib.request.urlopen(SARIF_URL, timeout=20).read()
    except Exception as exc:
        if os.environ.get("CI"):
            pytest.fail(f"cannot fetch the pinned SARIF schema in CI: {exc}")
        pytest.skip(f"offline: {exc}")
    assert hashlib.sha256(data).hexdigest() == SARIF_SHA256, "the SARIF schema does not match the pinned hash"
    return json.loads(data)


def log(component, guid=bt.GUID):
    ref = {"id": "AVE-2026-00001", "toolComponent": {"name": "AVE", "guid": guid}}
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "example-scanner", "rules": [{"id": "r1", "relationships": [{"target": ref, "kinds": ["relevant"]}]}],
                             "supportedTaxonomies": [{"name": "AVE", "guid": guid}]}},
        "taxonomies": [component],
        "results": [{"ruleId": "r1", "message": {"text": "m"}, "taxa": [ref]}]}]}


def test_the_guid_is_frozen_and_is_the_documented_derivation():
    assert bt.GUID == "5110b285-34d7-5334-94db-0308b24cfb49"
    assert bt.GUID == str(uuid.uuid5(uuid.NAMESPACE_URL, "https://aveproject.org/taxonomy/AVE"))
    assert C.AVE_GUID == bt.GUID


def test_the_committed_taxonomy_is_what_the_committed_records_produce():
    assert bt.main(["--check"]) == 0


def test_check_mode_fails_when_the_file_is_stale_or_missing(tmp_path):
    out = tmp_path / "t.json"
    assert bt.main(["--check", "--out", str(out)]) == 1
    out.write_text("{}\n", encoding="utf-8")
    assert bt.main(["--check", "--out", str(out)]) == 1
    assert bt.main(["--out", str(out)]) == 0 and bt.main(["--check", "--out", str(out)]) == 0


def test_the_output_is_deterministic_and_sorted_by_id():
    rs = [rec(3), rec(1), rec(2)]
    a, b = bt.dumps(bt.build(rs)), bt.dumps(bt.build(list(reversed(rs))))
    assert a == b
    assert [t["id"] for t in json.loads(a)["taxa"]] == ["AVE-2026-00001", "AVE-2026-00002", "AVE-2026-00003"]


def test_latest_carries_no_version_because_it_has_no_release():
    comp = bt.build([rec()], release_date="2026-11-05", download_uri="https://example.org/x")
    for key in ("version", "semanticVersion", "releaseDateUtc", "downloadUri"):
        assert key not in comp


def test_a_release_carries_its_version_date_and_uri():
    comp = bt.build([rec()], release="v1.3.0", release_date="2026-11-05", download_uri="https://example.org/x")
    assert (comp["version"], comp["semanticVersion"], comp["releaseDateUtc"], comp["downloadUri"]) == ("1.3.0", "1.3.0", "2026-11-05", "https://example.org/x")


def test_a_release_without_a_date_or_uri_omits_them_instead_of_writing_null():
    comp = bt.build([rec()], release="v1.3.0")
    assert comp["version"] == "1.3.0" and "releaseDateUtc" not in comp and "downloadUri" not in comp


@pytest.mark.parametrize("bad", ["1.3.0", "v1.3", "v1.3.0-rc1", "latest", ""])
def test_a_malformed_release_is_refused(bad):
    with pytest.raises(ValueError):
        bt.build([rec()], release=bad)


def test_a_subset_is_not_comprehensive_and_the_full_taxonomy_is():
    rs = [rec(1), rec(2)]
    assert bt.build(rs)["isComprehensive"] is True
    sub = bt.build(rs, only=["AVE-2026-00002"])
    assert sub["isComprehensive"] is False and [t["id"] for t in sub["taxa"]] == ["AVE-2026-00002"]


def test_an_unknown_id_in_a_subset_is_refused():
    with pytest.raises(ValueError, match="AVE-2026-00009"):
        bt.build([rec(1)], only=["AVE-2026-00009"])


def test_duplicate_ids_are_refused():
    with pytest.raises(ValueError, match="duplicate"):
        bt.build([rec(1), rec(1)])


def test_a_taxon_follows_its_record_including_a_status_that_is_not_active():
    t = bt.taxon(rec(5, status="merged", merged_into="AVE-2026-00001"))
    assert t["id"] == "AVE-2026-00005" and t["name"] == "Class 5"
    assert t["helpUri"] == "https://aveproject.org/registry.html#AVE-2026-00005"
    assert t["properties"] == {"status": "merged", "severity": "HIGH", "aivss_score": 7.5, "detection_stage": "static_detection", "merged_into": "AVE-2026-00001"}
    assert bt.taxon(rec(6, status="rejected", rejection_reason="https://example.org/d"))["properties"]["rejection_reason"] == "https://example.org/d"
    assert "merged_into" not in bt.taxon(rec(7))["properties"]


def test_a_record_with_missing_optional_fields_still_makes_a_taxon():
    t = bt.taxon({"ave_id": "AVE-2026-00001", "title": "T"})
    assert t == {"id": "AVE-2026-00001", "name": "T", "helpUri": "https://aveproject.org/registry.html#AVE-2026-00001", "properties": {}}


def test_the_generator_adds_no_em_dash_of_its_own():
    comp = bt.build([rec()])
    own = {k: v for k, v in comp.items() if k != "taxa"}
    assert "\u2014" not in json.dumps(own, ensure_ascii=False)


@pytest.mark.parametrize("kind", ["full", "subset", "release"])
def test_the_taxonomy_in_a_sarif_log_validates_against_the_official_schema(kind):
    jsonschema = pytest.importorskip("jsonschema")
    v = jsonschema.Draft7Validator(sarif_schema())
    rs = records()
    comp = {"full": lambda: bt.build(rs), "subset": lambda: bt.build(rs, only=["AVE-2026-00001"]),
            "release": lambda: bt.build(rs, release="v1.3.0", release_date="2026-11-05", download_uri="https://example.org/a.json", only=["AVE-2026-00001"])}[kind]()
    assert [e.message for e in v.iter_errors(log(comp))] == []


def test_the_schema_check_is_live_because_a_broken_component_fails_it():
    jsonschema = pytest.importorskip("jsonschema")
    v = jsonschema.Draft7Validator(sarif_schema())
    comp = bt.build(records(), only=["AVE-2026-00001"])
    bad = copy.deepcopy(comp); del bad["name"]
    assert any("'name' is a required property" in e.message for e in v.iter_errors(log(bad)))
    bad = copy.deepcopy(comp); bad["taxa"][0].pop("id")
    assert any("'id' is a required property" in e.message for e in v.iter_errors(log(bad)))
