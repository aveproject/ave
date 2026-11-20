import ast
import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import ave_conformance as C

DATA = Path(__file__).parent / "conformance_data"
SPEC = Path("docs/specs/ave-in-sarif.md")
CATALOG_FILE = DATA / "catalog.json"


def load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def catalog():
    records, info, issue = C.load_catalog(CATALOG_FILE)
    assert issue is None
    return records, info


def report(doc, with_catalog=True, require_ids=False):
    records, info = catalog() if with_catalog else (None, None)
    return C.check_document(doc, records, info, require_ids=require_ids)


def codes(rep, severity=None):
    return sorted(i["code"] for i in rep["issues"] if severity in (None, i["severity"]))


def messages(rep, code):
    return [i["message"] for i in rep["issues"] if i["code"] == code]


def spec_examples():
    """The complete SARIF examples in docs/specs/ave-in-sarif.md (form A, form B, form C, then the scan-and-digest example), read from the spec at test time so the two cannot drift."""
    blocks = re.findall(r"```json\n(.*?)\n```", SPEC.read_text(encoding="utf-8"), flags=re.S)
    docs = []
    for block in blocks:
        try:
            docs.append(json.loads(block))
        except ValueError:
            pass  # a fragment, such as the taxonomies block, not a document
    found = [d for d in docs if isinstance(d, dict) and "runs" in d]
    assert len(found) == 4, "the spec should have exactly four complete SARIF examples: form A, form B, form C and the scan-and-digest example"
    return found


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return p


# ── 1. the spec's own example ────────────────────────────────────────────────

@pytest.mark.parametrize("n, ave_id, via", [
    (0, "AVE-2026-00001", "sarif.result.ruleId"),
    (1, "AVE-2026-00001", "sarif.result.properties.ave_id"),
    (2, "AVE-2026-00001", "sarif.rule.relationships"),
    (3, "AVE-2026-00002", "sarif.result.ruleId"),
], ids=["form A", "form B", "form C", "scan time and target digest"])
def test_each_spec_example_is_conformant_against_the_catalog_it_names(n, ave_id, via):
    records, info, issue = C.load_catalog("dist/ave-records-v1.2.0.json")
    assert issue is None
    example = spec_examples()[n]
    rep = C.check_document(example, records, info)
    assert rep["issues"] == []
    assert rep["result"] == "pass"
    assert [(f["ave_id"], f["via"]) for f in C.extract_findings(example)] == [(ave_id, via)]


def test_the_scan_and_digest_example_also_passes_when_a_digest_is_required():
    records, info, _ = C.load_catalog("dist/ave-records-v1.2.0.json")
    rep = C.check_document(spec_examples()[3], records, info, require_target=True)
    assert rep["issues"] == [] and rep["result"] == "pass"


def test_the_spec_examples_checked_against_another_records_file_are_flagged_not_failed():
    records, info, _ = C.load_catalog("dist/ave-records-latest.json")
    for example in spec_examples():
        rep = C.check_document(example, records, info)
        assert codes(rep) == ["catalog_sha_differs"]
        assert rep["result"] == "warn"


# ── 2. results with no AVE id ────────────────────────────────────────────────

def test_a_tool_rule_id_and_no_ave_property_extracts_nothing_and_is_a_warning_by_default():
    doc = load("unmapped.json")
    assert C.extract_findings(doc) == []
    rep = report(doc)
    assert codes(rep, "error") == []
    assert codes(rep, "warn") == ["no_ave_id", "no_ave_ids", "taxonomies_missing"]
    assert "'tool-rule-7'" in messages(rep, "no_ave_id")[0] and "--require-ids" in messages(rep, "no_ave_id")[0]
    assert rep["result"] == "warn"


def test_require_ids_makes_a_result_with_no_ave_id_an_error():
    rep = report(load("unmapped.json"), require_ids=True)
    assert codes(rep, "error") == ["no_ave_id"]
    assert "'tool-rule-7'" in messages(rep, "no_ave_id")[0] and "--require-ids" not in messages(rep, "no_ave_id")[0]
    assert rep["result"] == "fail"


def test_a_run_that_reports_findings_outside_ave_is_judged_on_the_ones_that_name_a_class():
    doc = load("form_b_mixed.json")
    assert [f["ave_id"] for f in C.extract_findings(doc)] == ["AVE-2026-90001", "AVE-2026-90005"]
    rep = report(doc)
    assert codes(rep, "error") == []
    named = messages(rep, "no_ave_id")
    assert len(named) == 2 and all("example-hygiene" in m for m in named)
    assert rep["result"] == "warn"
    strict = report(doc, require_ids=True)
    assert codes(strict, "error") == ["no_ave_id", "no_ave_id"] and strict["result"] == "fail"


def test_a_sarif_with_results_but_no_id_at_all_says_so_once():
    rep = report(load("unmapped.json"))
    assert messages(rep, "no_ave_ids") == ["the SARIF has results, but none names an AVE class"]
    assert "no_ave_ids" not in codes(report(load("form_b_mixed.json")))
    # a SARIF with no results at all is the separate no_results warning, not this one
    assert "no_ave_ids" not in codes(report({"version": "2.1.0", "runs": [{"results": []}]}))


# ── 3. the two SARIF forms ───────────────────────────────────────────────────

def test_form_a_is_conformant():
    rep = report(load("form_a.json"))
    assert rep["issues"] == [] and rep["result"] == "pass"
    assert rep["extracted"] == {"count": 1, "via": {"sarif.result.ruleId": 1}}


def test_form_b_is_conformant():
    rep = report(load("form_b.json"))
    assert rep["issues"] == [] and rep["result"] == "pass"
    assert rep["extracted"] == {"count": 1, "via": {"sarif.result.properties.ave_id": 1}}


def test_form_b_without_run_properties_or_taxonomies_has_only_warnings():
    rep = report(load("form_b_bare.json"))
    assert codes(rep, "error") == []
    assert codes(rep) == ["run_property_missing"] * 3 + ["taxonomies_missing"]
    assert rep["result"] == "warn"


def test_each_missing_run_property_is_named():
    doc = load("form_a.json")
    del doc["runs"][0]["properties"]["ave_records_sha256"]
    del doc["runs"][0]["properties"]["ave_catalog"]
    rep = report(doc)
    named = " ".join(messages(rep, "run_property_missing"))
    assert "ave_records_sha256" in named and "ave_catalog" in named and "ave_schema_version" not in named


def test_form_a_result_with_no_matching_rule_is_an_error():
    doc = load("form_a.json")
    doc["runs"][0]["tool"]["driver"]["rules"] = []
    assert codes(report(doc), "error") == ["rule_missing"]


def test_form_b_result_with_no_matching_rule_is_an_error():
    doc = load("form_b.json")
    doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "another-rule"
    assert "rule_missing" in codes(report(doc), "error")


def test_form_b_needs_the_id_on_the_result():
    doc = load("form_b.json")
    del doc["runs"][0]["results"][0]["properties"]
    rep = report(doc)
    assert codes(rep, "error") == ["result_ave_id_missing"]
    # a tolerant reader still finds it, on the rule, and says so
    assert C.extract_findings(doc)[0]["via"] == "sarif.rule.properties.ave_id"


def test_form_b_needs_the_id_on_the_rule():
    doc = load("form_b.json")
    del doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert codes(report(doc), "error") == ["rule_ave_id_missing"]


def test_form_b_result_and_rule_must_name_the_same_id():
    doc = load("form_b.json")
    doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["ave_id"] = "AVE-2026-90005"
    assert codes(report(doc), "error") == ["id_mismatch"]


def test_form_a_ruleid_and_result_property_must_agree():
    doc = load("form_a.json")
    doc["runs"][0]["results"][0]["properties"] = {"ave_id": "AVE-2026-90005"}
    rep = report(doc)
    assert codes(rep, "error") == ["id_mismatch"]
    assert C.extract_findings(doc)[0]["via"] == "sarif.result.ruleId"


def test_form_a_ruleid_and_rule_property_must_agree():
    doc = load("form_a.json")
    doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"] = {"ave_id": "AVE-2026-90005"}
    assert codes(report(doc), "error") == ["id_mismatch"]


@pytest.mark.parametrize("bad, code", [
    ("AVE-26-1", "ave_id_malformed"), ("AVE-2026-9000", "ave_id_malformed"), ("AVE-2026-900011", "ave_id_malformed"),
    ("AVE-2026-90001\n", "ave_id_malformed"), ("AVE-2026-9000٣", "ave_id_malformed"),
    ("ave-2026-90001", "no_ave_id"), ("example-rule", "no_ave_id"),
])
def test_a_malformed_id_is_not_an_id(bad, code):
    doc = load("form_a.json")
    doc["runs"][0]["results"][0]["ruleId"] = bad
    doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] = bad
    assert C.extract_findings(doc) == []
    # a ruleId that tries to be an AVE id and is not one is an error; one that is plainly another tool's rule id is only a warning
    rep = report(doc)
    assert code in codes(rep, "error" if code == "ave_id_malformed" else "warn")
    assert rep["result"] == ("fail" if code == "ave_id_malformed" else "warn")
    assert report(doc, require_ids=True)["result"] == "fail"


def test_a_malformed_ave_id_on_a_form_b_result_is_named_as_the_result_s():
    doc = load("form_b.json")
    doc["runs"][0]["results"][0]["properties"]["ave_id"] = "AVE-26-1"
    rep = report(doc)
    assert codes(rep, "error") == ["ave_id_malformed", "id_mismatch"]
    assert "the result's properties.ave_id 'AVE-26-1'" in messages(rep, "ave_id_malformed")[0]


def test_a_malformed_ave_id_on_a_form_b_rule_is_named_as_the_rule_s():
    doc = load("form_b.json")
    doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["ave_id"] = "AVE-26-1"
    rep = report(doc)
    assert codes(rep, "error") == ["ave_id_malformed", "id_mismatch"]
    assert "the rule 'example-rule-7' properties.ave_id 'AVE-26-1'" in messages(rep, "ave_id_malformed")[0]


def test_the_same_problem_on_many_results_is_one_issue_with_a_count():
    doc = load("unmapped.json")
    doc["runs"][0]["results"] = doc["runs"][0]["results"] * 4
    rep = report(doc, require_ids=True)
    assert codes(rep, "error") == ["no_ave_id"]
    assert rep["issues"][0]["count"] == 4


def test_result_taxa_are_found_when_they_name_another_class():
    doc = load("form_a.json")
    doc["runs"][0]["results"][0]["taxa"] = [{"id": "AVE-2026-90001"}, {"id": "AVE-2026-90005"}, {"id": "nope"}]
    found = C.extract_findings(doc)
    assert [(f["ave_id"], f["via"]) for f in found] == [("AVE-2026-90001", "sarif.result.ruleId"), ("AVE-2026-90005", "sarif.result.taxa")]


def test_a_result_may_name_its_rule_as_rule_dot_id():
    doc = load("form_a.json")
    result = doc["runs"][0]["results"][0]
    result["rule"] = {"id": result.pop("ruleId")}
    assert [(f["ave_id"], f["via"]) for f in C.extract_findings(doc)] == [("AVE-2026-90001", "sarif.result.ruleId")]
    assert report(doc)["issues"] == []


def test_the_report_counts_how_many_ids_were_found_each_way():
    doc = load("form_a.json")
    doc["runs"][0]["results"] *= 3
    assert report(doc)["extracted"] == {"count": 3, "via": {"sarif.result.ruleId": 3}}


def test_where_is_the_artifact_uri_for_sarif():
    assert C.extract_findings(load("form_a.json"))[0]["where"] == "skills/example.md"


# ── taxonomies and run properties ────────────────────────────────────────────

def test_the_taxonomy_version_must_equal_the_catalog_release_without_its_v():
    doc = load("form_a.json")
    doc["runs"][0]["taxonomies"][0]["version"] = "9.9.8"
    assert codes(report(doc), "error") == ["taxonomy_version_mismatch"]


def test_a_taxonomy_with_no_version_is_a_warning_when_a_release_is_named():
    doc = load("form_a.json")
    del doc["runs"][0]["taxonomies"][0]["version"]
    rep = report(doc)
    assert codes(rep) == ["taxonomy_version_missing"] and rep["result"] == "warn"


def test_latest_means_the_taxonomy_omits_its_version():
    doc = load("form_a.json")
    doc["runs"][0]["properties"]["ave_catalog"] = "latest"
    assert codes(report(doc), "error") == ["taxonomy_version_mismatch"]
    del doc["runs"][0]["taxonomies"][0]["version"]
    assert codes(report(doc), "error") == []


def test_a_taxonomy_at_the_document_level_counts():
    doc = load("form_a.json")
    doc["taxonomies"] = doc["runs"][0].pop("taxonomies")
    assert "taxonomies_missing" not in codes(report(doc))


def test_a_taxonomy_not_named_ave_and_without_its_guid_does_not_count():
    doc = load("form_a.json")
    doc["runs"][0]["taxonomies"][0]["name"] = "Other"
    del doc["runs"][0]["taxonomies"][0]["guid"]
    assert codes(report(doc)) == ["taxonomies_missing"]


def test_the_guid_decides_so_a_renamed_taxonomy_with_the_ave_guid_still_counts():
    doc = load("form_a.json")
    doc["runs"][0]["taxonomies"][0]["name"] = "Renamed"
    assert codes(report(doc)) == []


def test_a_cited_class_with_no_taxon_is_a_warning():
    doc = load("form_a.json")
    doc["runs"][0]["taxonomies"][0]["taxa"] = [{"id": "AVE-2026-90005"}]
    rep = report(doc)
    assert codes(rep) == ["taxon_missing"] and "AVE-2026-90001" in messages(rep, "taxon_missing")[0]


def test_the_records_hash_in_the_run_is_compared_with_the_catalog_given():
    doc = load("form_a.json")
    assert "catalog_sha_differs" not in codes(report(doc))
    # a hash written in capitals, or with stray whitespace, is still the same hash
    doc["runs"][0]["properties"]["ave_records_sha256"] = " " + doc["runs"][0]["properties"]["ave_records_sha256"].upper() + "\n"
    assert "catalog_sha_differs" not in codes(report(doc))
    doc["runs"][0]["properties"]["ave_records_sha256"] = "0" * 64
    rep = report(doc)
    assert codes(rep) == ["catalog_sha_differs"] and rep["result"] == "warn"


# ── 4. JSON outputs ──────────────────────────────────────────────────────────

def test_json_ids_are_found_under_any_spelling_of_the_key_at_any_depth():
    found = C.extract_findings(load("json_findings.json"))
    assert [(f["ave_id"], f["via"], f["where"]) for f in found] == [
        ("AVE-2026-90001", "json.ave_id", "$.findings[0]"),
        ("AVE-2026-90005", "json.AVEID", "$.findings[1]"),
        ("AVE-2026-90002", "json.AveId", "$.findings[2].detail"),
        ("AVE-2026-90003", "json.ave-id", "$.findings[3]"),
        ("AVE-2026-90004", "json.ave_ids", "$.findings[4]"),
    ]


def test_json_at_the_top_level_and_in_lists():
    assert [f["ave_id"] for f in C.extract_findings([{"ave_id": "AVE-2026-90001"}, [{"AVEID": "AVE-2026-90005"}]])] == ["AVE-2026-90001", "AVE-2026-90005"]
    assert [f["ave_id"] for f in C.extract_findings({"ave_id": "AVE-2026-90001"})] == ["AVE-2026-90001"]
    assert C.extract_findings("AVE-2026-90001") == [] and C.extract_findings(None) == [] and C.extract_findings(3) == []


def test_json_output_is_judged_for_its_ids_only():
    rep = report(load("json_findings.json"))
    assert rep["format"] == "json"
    assert rep["extracted"]["count"] == 5
    # 90002 deprecated, 90003 merged, 90004 rejected: warnings, no errors
    assert codes(rep) == ["not_active"] * 3
    assert rep["result"] == "warn"


def test_json_with_no_id_at_all_is_a_warning():
    rep = report({"findings": []})
    assert codes(rep) == ["no_ave_ids"] and rep["result"] == "warn"


# ── 5. ids against the catalog ───────────────────────────────────────────────

def test_an_id_that_is_not_in_the_catalog_is_an_error():
    doc = load("form_a.json")
    doc["runs"][0]["results"][0]["ruleId"] = doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "AVE-2026-99999"
    rep = report(doc)
    assert codes(rep, "error") == ["unknown_ave_id"] and "AVE-2026-99999" in messages(rep, "unknown_ave_id")[0]


def test_a_deprecated_merged_or_rejected_id_is_a_warning_that_says_where_to_look():
    records, _ = catalog()
    found = lambda i: [{"ave_id": i, "via": "x", "where": ""}]
    deprecated = C.check_catalog(found("AVE-2026-90002"), records)
    merged = C.check_catalog(found("AVE-2026-90003"), records)
    rejected = C.check_catalog(found("AVE-2026-90004"), records)
    assert [(i["severity"], i["code"]) for i in deprecated + merged + rejected] == [("warn", "not_active")] * 3
    assert "is deprecated" in deprecated[0]["message"]
    assert "merged_into AVE-2026-90001" in merged[0]["message"]
    assert "rejection_reason https://example.invalid/decision" in rejected[0]["message"]


@pytest.mark.parametrize("status", ["frozen", "draft", "", None, 7])
def test_any_status_other_than_active_is_not_active(status):
    record = {"ave_id": "AVE-2026-90009", "status": status}
    out = C.check_catalog([{"ave_id": "AVE-2026-90009", "via": "x", "where": ""}], [record])
    assert [i["code"] for i in out] == ["not_active"]
    assert C.check_catalog([{"ave_id": "AVE-2026-90009", "via": "x", "where": ""}], [{"ave_id": "AVE-2026-90009"}])[0]["code"] == "not_active"


def test_an_id_cited_twice_is_reported_once():
    found = [{"ave_id": "AVE-2026-99999", "via": "x", "where": "a"}, {"ave_id": "AVE-2026-99999", "via": "x", "where": "b"}]
    assert len(C.check_catalog(found, catalog()[0])) == 1


def test_no_catalog_means_ids_are_not_checked_and_the_report_says_so():
    rep = report(load("form_a.json"), with_catalog=False)
    assert codes(rep) == ["catalog_not_supplied"] and rep["catalog"] is None


# ── the catalog file ─────────────────────────────────────────────────────────

def test_the_catalog_report_names_the_file_hash_and_its_manifest():
    _, info = catalog()
    manifest = load("catalog.manifest.json")
    assert info["sha256"] == manifest["sha256"]
    assert (info["release"], info["schema_version"], info["records"]) == ("v9.9.9", "9.9.9", 5)


def test_a_catalog_with_no_manifest_still_loads(tmp_path):
    p = write(tmp_path, "records.json", CATALOG_FILE.read_bytes())
    records, info, issue = C.load_catalog(p)
    assert issue is None and len(records) == 5
    assert info["release"] is None and info["schema_version"] is None and len(info["sha256"]) == 64


def test_a_latest_manifest_has_no_release(tmp_path):
    write(tmp_path, "records.json", CATALOG_FILE.read_bytes())
    write(tmp_path, "records.manifest.json", json.dumps({"schema_version": "1.3.0"}))
    _, info, _ = C.load_catalog(tmp_path / "records.json")
    assert info["release"] is None and info["schema_version"] == "1.3.0"


@pytest.mark.parametrize("content", [b"", b"not json", b"{}", b'{"records": 3}', b'[1, 2]', b'[{"title": "no id"}]', b"\xff\xfe\x00"])
def test_an_unusable_catalog_is_a_clear_error(tmp_path, content):
    records, info, issue = C.load_catalog(write(tmp_path, "c.json", content))
    assert records is None and issue["code"] == "catalog_unreadable" and issue["severity"] == "error"


def test_a_catalog_wrapped_in_an_object_is_accepted(tmp_path):
    p = write(tmp_path, "c.json", json.dumps({"records": json.loads(CATALOG_FILE.read_text())}))
    assert C.load_catalog(p)[2] is None


# ── 6. malformed input: a clear error, never a traceback ─────────────────────

@pytest.mark.parametrize("content, code, needle", [
    (b"", "not_json", "is empty"),
    (b"   \n", "not_json", "is empty"),
    (b"this is not json", "not_json", "is not JSON"),
    (b"\xff\xfe\x00\x01", "not_json", "UTF-8"),
    (b'{"version": "2.1.0", "$schema": "https://x/sarif-schema-2.1.0.json"}', "sarif_no_runs", "no runs array"),
    (b'{"runs": "x"}', "sarif_no_runs", "no runs array"),
])
def test_malformed_input_is_one_clear_error(tmp_path, content, code, needle):
    rep, exit_code = C.run_check(write(tmp_path, "out.json", content), CATALOG_FILE, strict=False)
    assert exit_code == 2 and rep["result"] == "fail"
    assert [i["code"] for i in rep["issues"] if i["severity"] == "error"] == [code]
    assert needle in rep["issues"][0]["message"]


def test_a_missing_file_is_a_clear_error(tmp_path):
    rep, exit_code = C.run_check(tmp_path / "nope.json", CATALOG_FILE, strict=False)
    assert exit_code == 2 and rep["issues"][0]["code"] == "input_unreadable"


def test_a_bom_is_tolerated(tmp_path):
    p = write(tmp_path, "out.json", b"\xef\xbb\xbf" + (DATA / "form_a.json").read_bytes())
    assert C.run_check(p, CATALOG_FILE, strict=False)[1] == 0


@pytest.mark.parametrize("doc", [
    {"runs": [1, "x", None, [], {}]},
    {"runs": [{"tool": [], "results": "a", "properties": [], "taxonomies": "x"}]},
    {"runs": [{"tool": {"driver": {"rules": [1, None, {"id": ["x"]}]}}, "results": [1, None, {"ruleId": ["x"], "properties": [], "locations": "x", "taxa": "x"}]}]},
    {"runs": [{"results": [{"ruleId": {"a": 1}, "rule": {"id": 5}, "properties": {"ave_id": {"x": 1}}, "taxa": [1, {"id": []}]}]}]},
    {"runs": [{"taxonomies": [1, {"name": "AVE", "taxa": "x", "version": []}], "properties": {"ave_catalog": 5}}]},
])
def test_odd_shapes_inside_sarif_never_raise(doc):
    rep = report(doc)
    assert rep["result"] in ("pass", "warn", "fail")
    C.extract_findings(doc)


def test_an_unusable_catalog_stops_the_check_with_exit_2(tmp_path):
    rep, exit_code = C.run_check(DATA / "form_a.json", write(tmp_path, "c.json", b"nope"), strict=False)
    assert exit_code == 2 and [i["code"] for i in rep["issues"]] == ["catalog_unreadable"]


def test_a_recursion_error_while_reading_is_reported_not_raised(tmp_path, monkeypatch):
    def too_deep(*args, **kwargs):
        raise RecursionError
    monkeypatch.setattr(C, "check_document", too_deep)
    rep, exit_code = C.run_check(DATA / "form_a.json", CATALOG_FILE, strict=False)
    assert exit_code == 2 and "nested too deeply" in rep["issues"][0]["message"]
    monkeypatch.setattr(C, "extract_findings", too_deep)
    assert C.main(["extract", str(DATA / "form_a.json")]) == 2


def test_deeply_nested_json_is_reported_not_raised(tmp_path):
    deep = "[" * 5000 + "]" * 5000
    rep, exit_code = C.run_check(write(tmp_path, "deep.json", deep), CATALOG_FILE, strict=False)
    assert exit_code == 2 and rep["issues"][0]["severity"] == "error"


# ── the report and the exit codes ────────────────────────────────────────────

def test_the_report_has_the_documented_shape():
    rep, _ = C.run_check(DATA / "form_a.json", CATALOG_FILE, strict=False)
    assert list(rep) == ["result", "file", "format", "extracted", "catalog", "issues"]
    assert rep["format"] == "sarif"
    assert rep["catalog"] == {"file": str(CATALOG_FILE), "sha256": catalog()[1]["sha256"], "release": "v9.9.9", "schema_version": "9.9.9", "records": 5}
    assert all(set(i) >= {"severity", "code", "message"} for i in report(load("unmapped.json"))["issues"])


def test_exit_codes(tmp_path):
    assert C.run_check(DATA / "form_a.json", CATALOG_FILE, strict=False)[1] == 0
    assert C.run_check(DATA / "form_a.json", CATALOG_FILE, strict=True)[1] == 0
    assert C.run_check(DATA / "form_b_bare.json", CATALOG_FILE, strict=False)[1] == 0     # warnings pass
    assert C.run_check(DATA / "form_b_bare.json", CATALOG_FILE, strict=True)[1] == 1      # unless --strict
    assert C.run_check(DATA / "unmapped.json", CATALOG_FILE, strict=False)[1] == 0        # no AVE id is only a warning ...
    assert C.run_check(DATA / "unmapped.json", CATALOG_FILE, strict=True)[1] == 1
    assert C.run_check(DATA / "unmapped.json", CATALOG_FILE, strict=False, require_ids=True)[1] == 2    # ... unless ids are required
    assert C.run_check(DATA / "unmapped.json", CATALOG_FILE, strict=True, require_ids=True)[1] == 2
    assert C.run_check(DATA / "form_b.json", CATALOG_FILE, require_ids=True)[1] == 0   # and --require-ids changes nothing when ids are there


def test_errors_are_listed_before_warnings():
    # the run-level warnings are found before the catalog's error for an id that does not exist
    doc = load("form_a.json")
    del doc["runs"][0]["properties"]
    doc["runs"][0]["results"][0]["ruleId"] = doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "AVE-2026-99999"
    severities = [i["severity"] for i in report(doc)["issues"]]
    assert severities.count("error") == 1 and severities.count("warn") >= 3
    assert severities[0] == "error"


def test_an_empty_runs_array_has_nothing_to_judge_and_is_a_warning_not_an_error():
    assert codes(report({"version": "2.1.0", "runs": []})) == ["no_results"]


def test_a_sarif_with_no_results_is_a_warning():
    rep = report({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [], "properties": load("form_a.json")["runs"][0]["properties"], "taxonomies": load("form_a.json")["runs"][0]["taxonomies"]}]})
    assert codes(rep) == ["no_results"]


# ── the command line ─────────────────────────────────────────────────────────

def cli(*args):
    return subprocess.run([sys.executable, "scripts/ave_conformance.py", *args], capture_output=True, text=True)


def test_extract_prints_the_findings_as_json():
    out = cli("extract", str(DATA / "form_b.json"))
    assert out.returncode == 0
    assert json.loads(out.stdout) == [{"ave_id": "AVE-2026-90001", "via": "sarif.result.properties.ave_id", "where": "skills/example.md"}]


def test_check_prints_a_json_report_and_a_one_line_summary():
    out = cli("check", str(DATA / "unmapped.json"), "--catalog", str(CATALOG_FILE), "--require-ids")
    assert out.returncode == 2
    assert json.loads(out.stdout)["result"] == "fail"
    assert out.stderr.strip().startswith("ave_conformance: fail:") and "tool-rule-7" in out.stderr


def test_require_ids_is_a_command_line_flag_and_off_by_default():
    args = ("check", str(DATA / "form_b_mixed.json"), "--catalog", str(CATALOG_FILE))
    plain = cli(*args)
    assert plain.returncode == 0 and json.loads(plain.stdout)["result"] == "warn"
    assert plain.stderr.strip().startswith("ave_conformance: warn:")
    assert cli(*args, "--require-ids").returncode == 2


def test_strict_changes_the_exit_code_for_warnings():
    args = ("check", str(DATA / "form_b_bare.json"), "--catalog", str(CATALOG_FILE))
    assert cli(*args).returncode == 0
    assert cli(*args, "--strict").returncode == 1


def test_a_markdown_file_is_a_clear_error_not_a_traceback():
    out = cli("check", str(SPEC))
    assert out.returncode == 2
    assert "Traceback" not in out.stdout + out.stderr
    assert "is not JSON" in out.stderr


def test_extract_of_malformed_input_exits_2_with_a_message(tmp_path):
    out = cli("extract", str(write(tmp_path, "x.json", b"nope")))
    assert out.returncode == 2 and out.stdout == "" and "is not JSON" in out.stderr and "Traceback" not in out.stderr


# ── 7. what the scan read, and when ──────────────────────────────────────────

GOOD_DIGEST = "0123456789abcdef" * 4  # an obviously fake SHA-256
SERVER = "https://mcp.example.com/mcp"


def with_target(doc=None):
    """Form A plus a scan time, one remote-server artifact with a digest, and the result pointing at it."""
    doc = copy.deepcopy(doc if doc is not None else load("form_a.json"))
    run = doc["runs"][0]
    run["invocations"] = [{"executionSuccessful": True, "startTimeUtc": "2026-11-17T09:00:00Z", "endTimeUtc": "2026-11-17T09:00:04Z"}]
    run["artifacts"] = [{
        "location": {"uri": SERVER},
        "hashes": {"sha-256": GOOD_DIGEST},
        "properties": {"ave_digest_scope": "tools-list", "ave_digest_canonicalization": "jcs-rfc8785"},
    }]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"uri": SERVER, "index": 0}
    return doc


def target_report(doc, component_type=None, with_catalog=True, **kwargs):
    """The report with --require-target's inputs: the fixture catalog, every record given `component_type`."""
    records, info = catalog() if with_catalog else (None, None)
    if records is not None:
        records = [dict(r, component_type=component_type) if component_type else dict(r) for r in records]
    return C.check_document(doc, records, info, **kwargs)


def test_output_with_the_scan_and_target_fields_and_no_other_fault_passes():
    rep = report(with_target())
    assert rep["issues"] == [] and rep["result"] == "pass"


def test_output_without_the_scan_and_target_fields_is_not_judged_on_them():
    for name in ("form_a.json", "form_b.json", "form_b_bare.json"):
        assert not [c for c in codes(report(load(name))) if c.startswith(("scan_time", "digest", "artifact", "target"))], name


# the scan time

@pytest.mark.parametrize("value", ["2026-11-17T09:00Z", "2026-11-17T09:00:00Z", "2026-11-17T09:00:00.943Z", "2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z", "2026-12-31T23:59:60Z"],
                         ids=["no seconds", "seconds", "fraction", "leap day", "leap day in a century year divisible by 400", "leap second"])
def test_a_utc_date_time_is_a_valid_scan_time(value):
    doc = with_target()
    doc["runs"][0]["invocations"][0].update(startTimeUtc=value, endTimeUtc=value)  # equal, so the order is not what this test is about
    assert codes(report(doc)) == []


@pytest.mark.parametrize("value", ["2026-11-17", "2026-11-17T09:00:00+07:00", "2026-11-17 09:00:00Z", "2026-11-17T09:00:00", "2026-13-01T00:00:00Z",
                                   "2026-02-30T00:00:00Z", "2025-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-11-17T25:00:00Z", "2026-11-17T09:60:00Z",
                                   "2026-11-17T09:61:00Z", "2026-11-17T09:00:61Z", "2026-11-1709:00:00Z", "yesterday", 1731834000, None, ""],
                         ids=["date only", "offset", "space", "no Z", "month 13", "30 February", "29 February in a common year", "29 February in a century year not divisible by 400",
                              "hour 25", "minute 60", "minute 61", "second 61", "no T", "word", "number", "null", "empty"])
@pytest.mark.parametrize("field", ["startTimeUtc", "endTimeUtc"])
def test_anything_else_is_a_scan_time_error(field, value):
    doc = with_target()
    doc["runs"][0]["invocations"][0][field] = value
    rep = report(doc)
    assert codes(rep, "error") == ["scan_time_invalid"] and rep["result"] == "fail"
    assert f"runs[0].invocations[0].{field}" in messages(rep, "scan_time_invalid")[0]


def test_every_invocation_is_checked_and_the_message_says_which():
    doc = with_target()
    doc["runs"][0]["invocations"] = [{"startTimeUtc": "2026-11-17T09:00:00Z"}, {"startTimeUtc": "later"}, "not an object"]
    rep = report(doc)
    assert codes(rep) == ["scan_time_invalid"] and "invocations[1].startTimeUtc" in messages(rep, "scan_time_invalid")[0]


# the order of the scan time: the end may equal the start but not come before it. The pairs are written so that comparing the
# strings, or the clock fields without the calendar, would give the wrong answer for some of them.

NOT_REVERSED = [
    ("2026-11-17T09:00:00Z", "2026-11-17T09:00:00Z"),
    ("2026-11-17T09:00:00Z", "2026-11-17T09:00:04Z"),
    ("2026-11-17T09:00Z", "2026-11-17T09:00:00Z"),
    ("2026-11-17T09:00:00Z", "2026-11-17T09:00Z"),
    ("2026-11-17T09:00Z", "2026-11-17T09:00:01Z"),
    ("2026-11-17T09:00:00.25Z", "2026-11-17T09:00:00.5Z"),
    ("2026-11-17T09:00:00.5Z", "2026-11-17T09:00:00.50Z"),
    ("2026-11-17T09:00:00.50Z", "2026-11-17T09:00:00.5Z"),
    ("2026-11-17T09:00:00Z", "2026-11-17T09:00:00.000Z"),
    ("2026-11-17T23:59:59Z", "2026-11-18T00:00:00Z"),
    ("2026-02-28T23:59:59Z", "2026-03-01T00:00:00Z"),
    ("2024-02-28T12:00:00Z", "2024-02-29T12:00:00Z"),
    ("2024-02-29T12:00:00Z", "2024-03-01T00:00:00Z"),
    ("2026-12-31T23:59:59Z", "2027-01-01T00:00:00Z"),
    ("2026-11-17T24:00:00Z", "2026-11-18T00:00:00Z"),
    ("2026-11-18T00:00:00Z", "2026-11-17T24:00:00Z"),
    ("2026-02-28T24:00:00Z", "2026-03-01T00:00:00Z"),
    ("2026-03-01T00:00:00Z", "2026-02-28T24:00:00Z"),
    ("2024-02-29T24:00:00Z", "2024-03-01T00:00:00Z"),
    ("2024-03-01T00:00:00Z", "2024-02-29T24:00:00Z"),
    ("2100-02-28T24:00:00Z", "2100-03-01T00:00:00Z"),
    ("2100-03-01T00:00:00Z", "2100-02-28T24:00:00Z"),
    ("2026-12-31T24:00:00Z", "2027-01-01T00:00:00Z"),
    ("2027-01-01T00:00:00Z", "2026-12-31T24:00:00Z"),
    ("2026-11-17T09:29:59Z", "2026-11-17T09:30:00Z"),
    ("2026-11-17T23:59:59Z", "2026-11-17T24:00:00Z"),
    ("2016-12-31T23:59:59.9Z", "2016-12-31T23:59:60Z"),
    ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60.5Z"),
    ("2016-12-31T23:59:60.5Z", "2017-01-01T00:00:00Z"),
]
REVERSED = [
    ("2026-11-17T09:00:04Z", "2026-11-17T09:00:00Z"),
    ("2026-11-17T09:00:01Z", "2026-11-17T09:00Z"),
    ("2026-11-17T09:30:00Z", "2026-11-17T09:29:59Z"),
    ("2026-11-17T09:01:00Z", "2026-11-17T09:00:59Z"),
    ("2026-11-17T09:00:00.5Z", "2026-11-17T09:00:00.25Z"),
    ("2026-11-17T09:00:00.001Z", "2026-11-17T09:00:00Z"),
    ("2026-11-18T00:00:00Z", "2026-11-17T23:59:59Z"),
    ("2026-03-01T00:00:00Z", "2026-02-28T23:59:59Z"),
    ("2024-03-01T00:00:00Z", "2024-02-29T12:00:00Z"),
    ("2027-01-01T00:00:00Z", "2026-12-31T23:59:59Z"),
    ("2026-11-18T09:00:00Z", "2026-11-17T09:00:00Z"),
    ("2027-11-17T09:00:00Z", "2026-11-17T09:00:00Z"),
    ("2026-11-17T24:00:00Z", "2026-11-17T23:59:59Z"),
    ("2016-12-31T23:59:60Z", "2016-12-31T23:59:59.9Z"),
    ("2017-01-01T00:00:00Z", "2016-12-31T23:59:60.5Z"),
]


def times(start, end):
    doc = with_target()
    doc["runs"][0]["invocations"][0].update(startTimeUtc=start, endTimeUtc=end)
    return doc


@pytest.mark.parametrize("start, end", NOT_REVERSED)
def test_an_end_that_is_equal_to_or_after_the_start_is_not_a_warning(start, end):
    assert codes(report(times(start, end))) == []


@pytest.mark.parametrize("start, end", REVERSED)
def test_an_end_before_the_start_is_a_warning_not_an_error(start, end):
    rep = report(times(start, end))
    assert codes(rep) == ["scan_time_reversed"] and rep["result"] == "warn"
    msg = messages(rep, "scan_time_reversed")[0]
    assert "runs[0].invocations[0]" in msg and start in msg and end in msg


def test_only_one_of_the_two_times_has_nothing_to_compare():
    for keep in ("startTimeUtc", "endTimeUtc"):
        doc = with_target()
        inv = doc["runs"][0]["invocations"][0]
        for gone in {"startTimeUtc", "endTimeUtc"} - {keep}:
            del inv[gone]
        assert codes(report(doc)) == [], keep


def test_an_invalid_time_is_not_also_called_reversed():
    for start, end in (("2026-11-17T09:00:00Z", "2026-11-17"), ("2026-11-17", "2026-11-16T09:00:00Z"), ("2026-11-17T09:00:00Z", None)):
        rep = report(times(start, end))
        assert codes(rep) == ["scan_time_invalid"], (start, end)


def test_the_order_is_checked_for_every_invocation_and_the_message_says_which():
    doc = with_target()
    doc["runs"][0]["invocations"] = [
        {"startTimeUtc": "2026-11-17T09:00:00Z", "endTimeUtc": "2026-11-17T09:00:04Z"},
        {"startTimeUtc": "2026-11-17T09:00:04Z", "endTimeUtc": "2026-11-17T09:00:00Z"},
        "not an object",
    ]
    rep = report(doc)
    assert codes(rep) == ["scan_time_reversed"] and "invocations[1]" in messages(rep, "scan_time_reversed")[0]


def test_the_order_is_checked_in_every_run_and_each_reversed_invocation_is_reported():
    doc = with_target()
    doc["runs"].append(copy.deepcopy(doc["runs"][0]))
    reversed_times = {"startTimeUtc": "2026-11-17T09:00:04Z", "endTimeUtc": "2026-11-17T09:00:00Z"}
    for run in doc["runs"]:
        run["invocations"] = [dict(reversed_times), dict(reversed_times)] if run is doc["runs"][0] else [dict(reversed_times)]
    rep = report(doc)
    assert codes(rep).count("scan_time_reversed") == 3 and all("count" not in i for i in rep["issues"])


# the digest

@pytest.mark.parametrize("value", [GOOD_DIGEST.upper(), GOOD_DIGEST[:63], GOOD_DIGEST + "0", "z" * 64, "", 0, None, ["0" * 64]],
                         ids=["uppercase", "63 characters", "65 characters", "not hex", "empty", "number", "null", "list"])
def test_a_sha256_that_is_not_64_lowercase_hex_characters_is_an_error(value):
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["hashes"]["sha-256"] = value
    rep = report(doc)
    assert codes(rep, "error") == ["digest_malformed"] and rep["result"] == "fail"
    assert "runs[0].artifacts[0]" in messages(rep, "digest_malformed")[0]


def test_hashes_that_is_not_an_object_is_an_error():
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["hashes"] = GOOD_DIGEST
    assert codes(report(doc), "error") == ["digest_malformed"]


def test_another_hash_function_alone_is_not_judged_as_a_sha256():
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["hashes"] = {"sha-512": "ab" * 64}
    assert codes(report(doc), "error") == []


def test_an_ordinary_artifact_hash_with_no_ave_digest_properties_is_left_alone():
    doc = with_target()
    doc["runs"][0]["artifacts"].append({"location": {"uri": "skills/example.md"}, "hashes": {"sha-256": GOOD_DIGEST}})
    assert codes(report(doc)) == []


def test_a_plain_artifact_with_an_uppercase_sha256_and_no_ave_digest_property_is_not_judged():
    # SARIF itself does not say the hex is lowercase; only an artifact that claims to be an AVE target digest is held to it
    doc = with_target()
    doc["runs"][0]["artifacts"].append({"location": {"uri": "skills/example.md"}, "hashes": {"sha-256": GOOD_DIGEST.upper()}})
    assert codes(report(doc)) == []


@pytest.mark.parametrize("hashes", [{"sha-256": GOOD_DIGEST.upper()}, {"sha-256": GOOD_DIGEST[:63]}, {"sha-256": 7}, {"sha-256": None}, {"sha-1": "ab" * 20},
                                    {"sha-1": "ab" * 20, "sha-256": "z" * 64}, GOOD_DIGEST, ["sha-256"], None],
                         ids=["uppercase", "63 characters", "number", "null", "sha-1 only", "sha-1 and a bad sha-256", "not an object (string)", "not an object (list)", "null hashes"])
def test_a_plain_artifact_whose_hashes_are_odd_is_not_judged_at_all(hashes):
    doc = with_target()
    doc["runs"][0]["artifacts"].append({"location": {"uri": "skills/example.md"}, "hashes": hashes})
    assert codes(report(doc)) == []


@pytest.mark.parametrize("props", [{"scanner_note": "x"}, {"ave_digest": "x"}, {"ave_scope": "tools-list"}, {"digest_scope": "tools-list"}, {"AVE_DIGEST_SCOPE": "tools-list"}],
                         ids=["unrelated property", "ave_digest with no suffix", "ave_scope", "digest_scope", "uppercase"])
def test_other_properties_on_a_plain_artifact_do_not_make_it_a_declared_digest(props):
    doc = with_target()
    doc["runs"][0]["artifacts"].append({"location": {"uri": "skills/example.md"}, "hashes": {"sha-256": GOOD_DIGEST.upper()}, "properties": props})
    assert codes(report(doc)) == []


@pytest.mark.parametrize("prop, value", [("ave_digest_scope", "tools-list"), ("ave_digest_canonicalization", "bytes"), ("ave_digest_other", "x")],
                         ids=["scope", "canonicalization", "any other ave_digest_ property"])
def test_an_artifact_that_declares_an_ave_digest_property_is_held_to_a_well_formed_sha256(prop, value):
    doc = with_target()
    doc["runs"][0]["artifacts"].append({"location": {"uri": "https://other.example.com/mcp"}, "hashes": {"sha-256": GOOD_DIGEST.upper()}, "properties": {prop: value}})
    rep = report(doc)
    assert codes(rep, "error") == ["digest_malformed"] and rep["result"] == "fail"
    assert "runs[0].artifacts[1]" in messages(rep, "digest_malformed")[0]


def test_an_artifact_that_declares_only_a_scope_and_has_a_malformed_sha256_is_digest_malformed():
    doc = with_target()
    doc["runs"][0]["artifacts"] = [{"location": {"uri": SERVER}, "hashes": {"sha-256": GOOD_DIGEST.upper()}, "properties": {"ave_digest_scope": "tools-list"}}]
    rep = report(doc)
    assert codes(rep, "error") == ["digest_malformed"]
    assert codes(rep, "warn") == ["digest_incomplete"]  # and it lacks the canonicalization, which is its own finding


@pytest.mark.parametrize("value", ["JCS", "sha-256", "json", "", 7, None], ids=["uppercase", "a hash name", "another word", "empty", "number", "null"])
def test_a_canonicalization_other_than_the_two_is_an_error(value):
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["properties"]["ave_digest_canonicalization"] = value
    rep = report(doc)
    assert codes(rep, "error") == ["digest_canonicalization_invalid"]
    assert "jcs-rfc8785" in messages(rep, "digest_canonicalization_invalid")[0]


def test_bytes_is_a_valid_canonicalization():
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["properties"]["ave_digest_canonicalization"] = "bytes"
    assert codes(report(doc)) == []


@pytest.mark.parametrize("drop, named", [
    (("properties", "ave_digest_scope"), "ave_digest_scope"),
    (("properties", "ave_digest_canonicalization"), "ave_digest_canonicalization"),
    (("hashes", "sha-256"), "sha-256"),
], ids=["no scope", "no canonicalization", "no digest"])
def test_a_target_digest_missing_a_part_is_a_warning_that_names_the_part(drop, named):
    doc = with_target()
    del doc["runs"][0]["artifacts"][0][drop[0]][drop[1]]
    rep = report(doc)
    assert codes(rep) == ["digest_incomplete"] and rep["result"] == "warn"
    assert named in messages(rep, "digest_incomplete")[0]


def test_an_empty_scope_counts_as_missing():
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["properties"]["ave_digest_scope"] = "  "
    assert codes(report(doc)) == ["digest_incomplete"]


# the artifact index

@pytest.mark.parametrize("index", [2, 5, -2, True, False, "0", 0.0, None], ids=["one past the end", "far past the end", "below -1", "true", "false", "string", "float", "null"])
def test_an_artifact_index_that_does_not_resolve_is_an_error(index):
    doc = with_target()
    doc["runs"][0]["artifacts"].append({"location": {"uri": "https://other.example.com/mcp"}})  # two artifacts, so True and False would resolve if a boolean counted
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = index
    rep = report(doc)
    assert codes(rep, "error") == ["artifact_index_unresolved"] and rep["result"] == "fail"
    assert "runs[0].results[0].locations[0]" in messages(rep, "artifact_index_unresolved")[0]


def test_an_index_into_a_run_with_no_artifacts_is_an_error():
    doc = with_target()
    del doc["runs"][0]["artifacts"]
    assert codes(report(doc), "error") == ["artifact_index_unresolved"]


def test_minus_one_is_sarifs_default_and_means_no_index():
    doc = with_target()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = -1
    assert codes(report(doc)) == []


def test_the_same_bad_index_on_many_results_is_one_issue_with_a_count():
    doc = with_target()
    result = doc["runs"][0]["results"][0]
    result["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 3
    doc["runs"][0]["results"] = [copy.deepcopy(result) for _ in range(3)]
    rep = report(doc)
    assert codes(rep) == ["artifact_index_unresolved"] and rep["issues"][0]["count"] == 3


# --require-target

def test_a_digest_is_not_required_unless_asked_for():
    doc = with_target()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].pop("index")
    assert codes(target_report(doc, "mcp_server")) == []


def test_require_target_makes_a_missing_digest_on_an_mcp_server_finding_an_error():
    doc = with_target()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].pop("index")
    rep = target_report(doc, "mcp_server", require_target=True)
    assert codes(rep, "error") == ["target_digest_missing"] and rep["result"] == "fail"
    assert "AVE-2026-90001" in messages(rep, "target_digest_missing")[0] and "points at no artifact" in messages(rep, "target_digest_missing")[0]


def test_require_target_passes_when_the_finding_points_at_an_artifact_with_a_declared_digest():
    rep = target_report(with_target(), "mcp_server", require_target=True)
    assert rep["issues"] == [] and rep["result"] == "pass"


@pytest.mark.parametrize("scope", ["tools-list", "server-card", "some-other-document"])
@pytest.mark.parametrize("canonicalization", ["jcs-rfc8785", "bytes"])
def test_require_target_passes_for_any_scope_and_either_canonicalization(scope, canonicalization):
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["properties"] = {"ave_digest_scope": scope, "ave_digest_canonicalization": canonicalization}
    rep = target_report(doc, "mcp_server", require_target=True)
    assert rep["issues"] == [] and rep["result"] == "pass"


def test_require_target_fails_for_an_artifact_with_only_a_plain_sha256():
    # a SHA-256 in hashes is SARIF's own; with no scope and no canonicalization two tools' digests cannot be compared
    doc = with_target()
    doc["runs"][0]["artifacts"][0] = {"location": {"uri": SERVER}, "hashes": {"sha-256": GOOD_DIGEST}}
    rep = target_report(doc, "mcp_server", require_target=True)
    assert codes(rep, "error") == ["target_digest_missing"] and rep["result"] == "fail"
    msg = messages(rep, "target_digest_missing")[0]
    assert "AVE-2026-90001" in msg and gaps_named(msg) == "properties.ave_digest_scope, properties.ave_digest_canonicalization"
    assert codes(target_report(doc, "mcp_server")) == []  # and the same output is fine when the flag is not given


def gaps_named(message):
    """The parts the --require-target message says are missing or invalid, as the checker joined them."""
    return message.split("missing or invalid: ")[1].split(")")[0]


def _drop(*path):
    def apply(art):
        target = art
        for key in path[:-1]:
            target = target[key]
        target.pop(path[-1])
    return apply


def _set(*path_and_value):
    *path, value = path_and_value
    def apply(art):
        target = art
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return apply


SHA = 'hashes["sha-256"]'
SCOPE = "properties.ave_digest_scope"
CANON = "properties.ave_digest_canonicalization"


@pytest.mark.parametrize("change, named", [
    (_drop("hashes", "sha-256"), SHA),
    (_set("hashes", {"sha-1": "ab" * 20}), SHA),
    (_set("hashes", GOOD_DIGEST), SHA),
    (_set("hashes", "sha-256", GOOD_DIGEST.upper()), SHA),
    (_set("hashes", "sha-256", GOOD_DIGEST[:63]), SHA),
    (_set("hashes", "sha-256", GOOD_DIGEST + "0"), SHA),
    (_set("hashes", "sha-256", 7), SHA),
    (_set("hashes", "sha-256", None), SHA),
    (_drop("properties", "ave_digest_scope"), SCOPE),
    (_set("properties", "ave_digest_scope", ""), SCOPE),
    (_set("properties", "ave_digest_scope", "   "), SCOPE),
    (_set("properties", "ave_digest_scope", 7), SCOPE),
    (_set("properties", "ave_digest_scope", None), SCOPE),
    (_drop("properties", "ave_digest_canonicalization"), CANON),
    (_set("properties", "ave_digest_canonicalization", "JCS"), CANON),
    (_set("properties", "ave_digest_canonicalization", ""), CANON),
    (_set("properties", "ave_digest_canonicalization", None), CANON),
    (_set("properties", "ave_digest_canonicalization", ["bytes"]), CANON),
], ids=["no sha-256", "sha-1 only", "hashes not an object", "uppercase sha-256", "63 characters", "65 characters", "number", "null sha-256",
        "no scope", "empty scope", "blank scope", "number scope", "null scope",
        "no canonicalization", "unknown canonicalization", "empty canonicalization", "null canonicalization", "list canonicalization"])
def test_require_target_fails_when_the_digest_is_not_declared_and_valid_and_names_what_is_wrong(change, named):
    doc = with_target()
    change(doc["runs"][0]["artifacts"][0])
    rep = target_report(doc, "mcp_server", require_target=True)
    assert "target_digest_missing" in codes(rep, "error") and rep["result"] == "fail"
    assert gaps_named(messages(rep, "target_digest_missing")[0]) == named


def test_require_target_names_every_part_that_is_wrong():
    doc = with_target()
    doc["runs"][0]["artifacts"][0] = {"location": {"uri": SERVER}}
    msg = messages(target_report(doc, "mcp_server", require_target=True), "target_digest_missing")[0]
    assert gaps_named(msg) == f"{SHA}, {SCOPE}, {CANON}"


def test_require_target_judges_the_artifact_the_result_points_at_not_any_artifact_in_the_run():
    doc = with_target()
    plain = {"location": {"uri": "https://other.example.com/mcp"}, "hashes": {"sha-256": GOOD_DIGEST}}
    doc["runs"][0]["artifacts"].append(plain)
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    loc["index"] = 0
    assert target_report(doc, "mcp_server", require_target=True)["issues"] == []
    loc["index"] = 1
    assert "target_digest_missing" in codes(target_report(doc, "mcp_server", require_target=True), "error")


def test_require_target_does_not_follow_an_index_that_does_not_resolve():
    doc = with_target()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 1
    assert codes(target_report(doc, "mcp_server", require_target=True), "error") == ["artifact_index_unresolved", "target_digest_missing"]


def test_require_target_does_not_take_a_boolean_for_an_index():
    doc = with_target()
    doc["runs"][0]["artifacts"].insert(0, {"location": {"uri": "https://other.example.com/mcp"}})  # the digest is now at position 1, which True would equal
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = True
    assert "target_digest_missing" in codes(target_report(doc, "mcp_server", require_target=True), "error")


def test_require_target_fails_when_the_artifact_it_points_at_has_no_sha256():
    doc = with_target()
    doc["runs"][0]["artifacts"][0]["hashes"] = {"sha-512": "ab" * 64}
    assert "target_digest_missing" in codes(target_report(doc, "mcp_server", require_target=True), "error")


@pytest.mark.parametrize("component_type", ["skill", "agent", "plugin", None], ids=["skill", "agent", "plugin", "no component_type"])
def test_require_target_asks_nothing_of_a_record_that_is_not_an_mcp_server(component_type):
    doc = with_target()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].pop("index")
    assert codes(target_report(doc, component_type, require_target=True)) == []
    doc["runs"][0]["artifacts"][0] = {"location": {"uri": SERVER}, "hashes": {"sha-256": GOOD_DIGEST}}  # a plain hash is enough for a class that is not an MCP server
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 0
    assert codes(target_report(doc, component_type, require_target=True)) == []


def test_require_target_reads_the_class_from_form_b_too():
    doc = load("form_b.json")
    rep = target_report(doc, "mcp_server", require_target=True)
    assert codes(rep, "error") == ["target_digest_missing"]


def test_require_target_ignores_a_result_that_names_no_ave_class():
    rep = target_report(load("unmapped.json"), "mcp_server", require_target=True)
    assert "target_digest_missing" not in codes(rep)


def test_the_same_missing_digest_on_many_results_is_one_issue_with_a_count():
    doc = load("form_a.json")
    doc["runs"][0]["results"] = [copy.deepcopy(doc["runs"][0]["results"][0]) for _ in range(3)]
    rep = target_report(doc, "mcp_server", require_target=True)
    missing = [i for i in rep["issues"] if i["code"] == "target_digest_missing"]
    assert len(missing) == 1 and missing[0]["count"] == 3


def test_require_target_without_a_catalog_is_an_error_because_the_class_comes_from_the_catalog():
    rep = target_report(with_target(), with_catalog=False, require_target=True)
    assert "catalog_required" in codes(rep, "error") and "--catalog" in messages(rep, "catalog_required")[0]


def test_require_target_on_output_that_is_not_sarif_is_a_warning_that_it_was_not_judged():
    rep = target_report(load("json_findings.json"), "mcp_server", require_target=True)
    assert "target_not_judged" in codes(rep, "warn") and codes(rep, "error") == []
    assert "target_not_judged" not in codes(target_report(load("json_findings.json"), "mcp_server"))


def test_the_command_line_takes_require_target(tmp_path):
    doc = with_target()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].pop("index")
    records = [dict(r, component_type="mcp_server") for r in catalog()[0]]
    cat = write(tmp_path, "catalog.json", json.dumps(records))
    out_file = write(tmp_path, "out.sarif", json.dumps(doc))
    plain = cli("check", str(out_file), "--catalog", str(cat))
    strict = cli("check", str(out_file), "--catalog", str(cat), "--require-target")
    assert plain.returncode == 0
    assert strict.returncode == 2 and "target_digest_missing" in strict.stdout and "AVE-2026-90001" in strict.stderr


def test_the_command_line_fails_a_plain_sha256_under_require_target_and_passes_a_declared_digest(tmp_path):
    records = [dict(r, component_type="mcp_server") for r in catalog()[0]]
    cat = write(tmp_path, "catalog.json", json.dumps(records))
    plain = with_target()
    plain["runs"][0]["artifacts"][0] = {"location": {"uri": SERVER}, "hashes": {"sha-256": GOOD_DIGEST}}
    plain_file = write(tmp_path, "plain.sarif", json.dumps(plain))
    declared_file = write(tmp_path, "declared.sarif", json.dumps(with_target()))
    assert cli("check", str(plain_file), "--catalog", str(cat)).returncode == 0
    failed = cli("check", str(plain_file), "--catalog", str(cat), "--require-target")
    assert failed.returncode == 2 and "target_digest_missing" in failed.stdout
    assert cli("check", str(declared_file), "--catalog", str(cat), "--require-target").returncode == 0


# ── the checker stays offline and standard-library only ──────────────────────

def test_the_checker_imports_only_the_standard_library_and_nothing_that_reaches_the_network():
    tree = ast.parse(Path("scripts/ave_conformance.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"argparse", "hashlib", "json", "re", "sys", "pathlib", "__future__"}, imported
