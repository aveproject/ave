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
    """The complete SARIF examples in docs/specs/ave-in-sarif.md (form A, form B, then form C), read from the spec at test time so the two cannot drift."""
    blocks = re.findall(r"```json\n(.*?)\n```", SPEC.read_text(encoding="utf-8"), flags=re.S)
    docs = []
    for block in blocks:
        try:
            docs.append(json.loads(block))
        except ValueError:
            pass  # a fragment, such as the taxonomies block, not a document
    found = [d for d in docs if isinstance(d, dict) and "runs" in d]
    assert len(found) == 3, "the spec should have exactly three complete SARIF examples, form A, form B and form C"
    return found


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return p


# ── 1. the spec's own example ────────────────────────────────────────────────

@pytest.mark.parametrize("n, via", [(0, "sarif.result.ruleId"), (1, "sarif.result.properties.ave_id"), (2, "sarif.rule.relationships")], ids=["form A", "form B", "form C"])
def test_each_spec_example_is_conformant_against_the_catalog_it_names(n, via):
    records, info, issue = C.load_catalog("dist/ave-records-v1.2.0.json")
    assert issue is None
    example = spec_examples()[n]
    rep = C.check_document(example, records, info)
    assert rep["issues"] == []
    assert rep["result"] == "pass"
    assert [(f["ave_id"], f["via"]) for f in C.extract_findings(example)] == [("AVE-2026-00001", via)]


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
