import copy
import json
from pathlib import Path

import pytest

from scripts import ave_conformance as C
from scripts import build_taxonomy as bt

DATA = Path(__file__).parent / "conformance_data"
ID1, ID2, GONE = "AVE-2026-90001", "AVE-2026-90002", "AVE-2026-90099"


def catalog():
    records, info, issue = C.load_catalog(DATA / "catalog.json")
    assert issue is None
    return records, info


def form_c(rule_relationships=True, result_taxa=True, supported=True, ids=(ID1,), guid=C.AVE_GUID, taxonomy=True):
    """Form B's fixture turned into form C: the tool's own rule id, related to AVE classes through the taxonomy."""
    doc = json.loads((DATA / "form_b.json").read_text(encoding="utf-8"))
    run = doc["runs"][0]
    rule, res = run["tool"]["driver"]["rules"][0], run["results"][0]
    del rule["properties"], res["properties"]
    refs = [{"id": i, "toolComponent": {"name": "AVE", "guid": guid}} for i in ids]
    if rule_relationships:
        rule["relationships"] = [{"target": r, "kinds": ["relevant"]} for r in refs]
    if result_taxa:
        res["taxa"] = refs
    if supported:
        run["tool"]["driver"]["supportedTaxonomies"] = [{"name": "AVE", "guid": C.AVE_GUID}]
    if taxonomy:
        records, _ = catalog()
        comp = bt.build(records, release="v9.9.9", only=list(ids)) if all(i in {r["ave_id"] for r in records} for i in ids) else run["taxonomies"][0]
        comp["guid"] = guid if taxonomy is True else taxonomy
        run["taxonomies"] = [comp]
    else:
        run["taxonomies"] = []
    return doc


def report(doc, with_catalog=True):
    records, info = catalog() if with_catalog else (None, None)
    return C.check_document(doc, records, info)


def codes(rep, severity=None):
    return sorted(i["code"] for i in rep["issues"] if severity in (None, i["severity"]))


def test_the_guid_in_the_checker_is_the_one_the_generator_stamps():
    assert C.AVE_GUID == bt.GUID


def test_form_c_with_relationships_and_result_taxa_is_conformant():
    rep = report(form_c())
    assert rep["result"] == "pass" and codes(rep) == []
    assert {f for f in rep["extracted"]["via"]} == {"sarif.rule.relationships"}


def test_form_c_with_only_a_rule_relationship_extracts_the_class():
    rep = report(form_c(result_taxa=False))
    assert rep["result"] == "pass" and rep["extracted"]["via"] == {"sarif.rule.relationships": 1}


def test_form_c_with_only_result_taxa_is_conformant_and_says_where_it_found_the_id():
    rep = report(form_c(rule_relationships=False))
    assert rep["result"] == "pass" and rep["extracted"]["via"] == {"sarif.result.taxa": 1}


def test_form_c_missing_its_rule_is_an_error():
    doc = form_c()
    doc["runs"][0]["tool"]["driver"]["rules"] = []
    assert "rule_missing" in codes(report(doc), "error")


def test_a_reference_to_an_unknown_class_is_an_error():
    rep = report(form_c(ids=(GONE,)))
    assert "unknown_ave_id" in codes(rep, "error")


def test_a_reference_to_a_rejected_class_warns_that_it_is_not_active():
    rep = report(form_c(ids=("AVE-2026-90004",)))
    assert "not_active" in codes(rep, "warn") and rep["result"] != "fail"


def test_a_reference_to_a_component_called_ave_with_another_guid_is_an_error_and_is_not_counted():
    rep = report(form_c(guid="00000000-0000-4000-8000-000000000000", taxonomy=C.AVE_GUID))
    assert "reference_guid_mismatch" in codes(rep, "error")
    assert rep["extracted"]["count"] == 0


def test_a_reference_to_another_taxonomy_is_not_an_ave_class():
    doc = form_c()
    for ref in [doc["runs"][0]["results"][0]["taxa"][0], doc["runs"][0]["tool"]["driver"]["rules"][0]["relationships"][0]["target"]]:
        ref["toolComponent"] = {"name": "CWE"}
    rep = report(doc)
    assert rep["extracted"]["count"] == 0 and "no_ave_id" in codes(rep, "warn")


def test_using_the_taxonomy_without_declaring_it_is_a_warning():
    rep = report(form_c(supported=False))
    assert codes(rep) == ["supported_taxonomies_missing"] and rep["result"] == "warn"


def test_declaring_the_taxonomy_by_name_only_is_accepted():
    doc = form_c()
    doc["runs"][0]["tool"]["driver"]["supportedTaxonomies"] = [{"name": "AVE"}]
    assert codes(report(doc)) == []


def test_an_embedded_taxonomy_with_the_wrong_guid_is_an_error():
    doc = form_c()
    doc["runs"][0]["taxonomies"][0]["guid"] = "00000000-0000-4000-8000-000000000000"
    assert "taxonomy_guid_mismatch" in codes(report(doc), "error")


def test_an_embedded_taxonomy_without_a_guid_is_only_a_warning():
    doc = form_c()
    del doc["runs"][0]["taxonomies"][0]["guid"]
    rep = report(doc)
    assert codes(rep) == ["taxonomy_guid_missing"] and rep["result"] == "warn"


def test_the_guid_comparison_ignores_case():
    doc = form_c()
    doc["runs"][0]["taxonomies"][0]["guid"] = C.AVE_GUID.upper()
    assert codes(report(doc)) == []


def test_a_reference_with_an_upper_case_guid_still_counts_as_ave():
    doc = form_c(guid=C.AVE_GUID.upper(), taxonomy=C.AVE_GUID)
    rep = report(doc)
    assert rep["extracted"]["count"] == 1 and "reference_guid_mismatch" not in codes(rep)


def test_a_taxon_that_is_not_in_the_catalog_is_an_error():
    doc = form_c()
    doc["runs"][0]["taxonomies"][0]["taxa"].append({"id": GONE, "name": "Invented"})
    assert "taxon_unknown" in codes(report(doc), "error")


def test_a_taxon_whose_name_is_not_the_catalog_title_is_a_warning():
    doc = form_c()
    doc["runs"][0]["taxonomies"][0]["taxa"][0]["name"] = "Something else"
    rep = report(doc)
    assert codes(rep) == ["taxon_name_differs"] and rep["result"] == "warn"


def test_without_a_catalog_the_taxa_are_not_judged_against_it():
    doc = form_c()
    doc["runs"][0]["taxonomies"][0]["taxa"].append({"id": GONE, "name": "Invented"})
    assert "taxon_unknown" not in codes(report(doc, with_catalog=False))


def test_a_form_b_result_keeps_its_own_rule_and_is_not_confused_by_taxa():
    doc = json.loads((DATA / "form_b.json").read_text(encoding="utf-8"))
    assert report(doc)["result"] == "pass"


def test_form_a_and_form_b_still_extract_as_before():
    assert report(json.loads((DATA / "form_a.json").read_text(encoding="utf-8")))["extracted"]["via"] == {"sarif.result.ruleId": 1}
    assert report(json.loads((DATA / "form_b.json").read_text(encoding="utf-8")))["extracted"]["via"] == {"sarif.result.properties.ave_id": 1}
