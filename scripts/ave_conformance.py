#!/usr/bin/env python3
# What: finds the AVE ids in a tool's output (`extract`), and judges that output against
#       docs/specs/ave-in-sarif.md and a catalog file the caller supplies (`check`).
# Why:  the spec and the implementer guide say how a tool reports AVE findings, and nothing
#       checked it, so a tool could claim to emit AVE ids and nobody could find out whether
#       it did. Extraction and conformance are separate jobs on purpose: extraction is
#       tolerant, so any tool's output can be scored whatever shape it is in, and records how
#       each id was found; conformance is strict, so a tool author learns exactly what the
#       spec asks for that the output lacks. Conformance is not detection quality.
# How:  standard library only, and nothing is fetched: the catalog is a file (a catalog
#       release's ave-records.json, or dist/ave-records-latest.json) and its manifest is
#       read from beside it when there is one.
#         python scripts/ave_conformance.py extract <output-file>
#         python scripts/ave_conformance.py check <output-file> [--catalog <records.json>] [--strict] [--require-ids]
#       `check` prints a JSON report on stdout and a one-line summary on stderr. Exit status:
#       0 pass (or warnings), 1 warnings with --strict, 2 any error, or input it cannot read. A result that names no
#       AVE class is a warning, because a tool may report findings outside AVE in the same file; --require-ids makes it an error.
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ID = re.compile(r"AVE-[0-9]{4}-[0-9]{5}")
JSON_ID_KEY = re.compile(r"ave[_-]?ids?", re.IGNORECASE)
RUN_PROPERTIES = ("ave_catalog", "ave_schema_version", "ave_records_sha256")
# The AVE taxonomy's SARIF identity: a taxonomy is matched by guid first, so another tool's "AVE" is not this one.
# Frozen, and equal to GUID in scripts/build_taxonomy.py (a test pins the pair).
AVE_GUID = "5110b285-34d7-5334-94db-0308b24cfb49"


# What: the value if it is a dict, else an empty dict
# Why:  tool output is untrusted; a field of the wrong type must produce a finding, not a traceback
# How:  isinstance check
def _dict(x):
    return x if isinstance(x, dict) else {}


# What: the value if it is a list, else an empty list
# Why:  same as _dict
# How:  isinstance check
def _list(x):
    return x if isinstance(x, list) else []


# What: whether the value is a well-formed AVE id
# Why:  one definition of the id shape for extraction and for the checks
# How:  fullmatch on a string, so a trailing newline or non-ASCII digits do not pass
def _is_id(x):
    return isinstance(x, str) and ID.fullmatch(x) is not None


# What: one issue, as the report carries it
# Why:  every check reports the same three fields
# How:  a dict
def issue(severity, code, message):
    return {"severity": severity, "code": code, "message": message}


# What: collects issues, merging repeats of the same problem into one issue with a count
# Why:  a tool that gets one thing wrong gets it wrong on every result; the report should
#       name the problem once, not once per result
# How:  keyed by (code, subject); the first message is kept and `count` appears from the second
class Issues:
    def __init__(self):
        self._by = {}

    def add(self, severity, code, subject, message):
        key = (code, subject)
        if key in self._by:
            self._by[key]["count"] = self._by[key].get("count", 1) + 1
        else:
            self._by[key] = issue(severity, code, message)

    def items(self):
        return list(self._by.values())


# What: whether a parsed document is SARIF
# Why:  SARIF is judged against the spec; other JSON is only read for ids
# How:  a `runs` key, or a $schema naming SARIF (so a SARIF file whose runs array is missing is reported as such)
# What: whether a SARIF toolComponent reference names the AVE taxonomy
# Why:  taxa and relationships point at a taxonomy by guid or name; a different guid means a different taxonomy
# How:  a guid decides when there is one (case-insensitive); otherwise the name "AVE"
def _is_ave_component(comp):
    comp = _dict(comp)
    guid = comp.get("guid")
    if isinstance(guid, str):
        return guid.lower() == AVE_GUID
    return comp.get("name") == "AVE"


# What: whether a reportingDescriptorReference points at an AVE class
# Why:  result.taxa and rule relationships can point at any taxonomy; only AVE ids from AVE count here
# How:  no toolComponent (the id pattern decides, as for result.taxa before) or an AVE component
def _is_ave_ref(ref):
    comp = _dict(ref).get("toolComponent")
    return comp is None or _is_ave_component(comp)


# What: the AVE ids a rule relates itself to, and a result tags itself with (form C)
# How:  rule.relationships[].target and result.taxa[], AVE references only, in order, without repeats
def _form_c_ids(res, rule):
    refs = [_dict(_dict(rel).get("target")) for rel in _list(_dict(rule).get("relationships"))] + [_dict(t) for t in _list(res.get("taxa"))]
    return list(dict.fromkeys(r["id"] for r in refs if _is_id(r.get("id")) and _is_ave_ref(r)))


def is_sarif(doc):
    return isinstance(doc, dict) and ("runs" in doc or "sarif" in str(doc.get("$schema", "")).lower())


# What: a run's rules keyed by id
# Why:  a result's ruleId is looked up here, for the matching-rule check and for form B's rule property
# How:  tool.driver.rules, the first entry winning when an id repeats
def _rules_by_id(run):
    rules = {}
    for rule in _list(_dict(_dict(run.get("tool")).get("driver")).get("rules")):
        rid = _dict(rule).get("id")
        if isinstance(rid, str):
            rules.setdefault(rid, _dict(rule))
    return rules


# What: a result's rule id
# Why:  SARIF allows it as ruleId or as result.rule.id
# How:  ruleId first, then rule.id; None when neither is a string
def _rule_id(res):
    rid = res.get("ruleId")
    if not isinstance(rid, str):
        rid = _dict(res.get("rule")).get("id")
    return rid if isinstance(rid, str) else None


# What: where a result points
# Why:  the extracted finding says which artifact it was reported on
# How:  the first location's artifact URI, "" when there is none
def _uri(res):
    locations = _list(res.get("locations"))
    uri = _dict(_dict(_dict(locations[0] if locations else None).get("physicalLocation")).get("artifactLocation")).get("uri")
    return uri if isinstance(uri, str) else ""


# What: finds ids in JSON that is not SARIF
# Why:  tools that are not SARIF still carry an ave_id on each finding (the implementer guide's smallest integration)
# How:  any object with an ave_id / AVEID / AveId / ave-id key holding an id, or an ave_ids key holding a list of them;
#       `where` is the JSON path of the object that holds the key
def _walk(node, path, add):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and JSON_ID_KEY.fullmatch(key) and isinstance(value, str):
                add(value, f"json.{key}", path)
            elif isinstance(key, str) and JSON_ID_KEY.fullmatch(key) and isinstance(value, list) and all(isinstance(v, str) for v in value):
                for v in value:
                    add(v, f"json.{key}", path)
            else:
                _walk(value, f"{path}.{key}", add)
    elif isinstance(node, list):
        for n, item in enumerate(node):
            _walk(item, f"{path}[{n}]", add)


# What: the AVE ids a tool's output carries, and how each was found
# Why:  a scorer needs the ids from any tool, whatever its format; `via` lets it see which placement the tool used
# How:  SARIF: the result's ruleId when it is an AVE id (form A), else its properties.ave_id, else its rule's
#       properties.ave_id (form B), plus result.taxa entries that name another class. Other JSON: _walk.
#       Returns [{"ave_id", "via", "where"}], tolerant: it never judges.
def extract_findings(doc):
    out = []

    def add(ave_id, via, where):
        if _is_id(ave_id):
            out.append({"ave_id": ave_id, "via": via, "where": where})

    if not is_sarif(doc):
        _walk(doc, "$", add)
        return out
    for run in _list(doc.get("runs")):
        run = _dict(run)
        rules = _rules_by_id(run)
        for res in _list(run.get("results")):
            res = _dict(res)
            rid, where, before = _rule_id(res), _uri(res), len(out)
            if _is_id(rid):
                add(rid, "sarif.result.ruleId", where)
            else:
                add(_dict(res.get("properties")).get("ave_id"), "sarif.result.properties.ave_id", where)
                if len(out) == before:
                    add(_dict(_dict(rules.get(rid)).get("properties")).get("ave_id"), "sarif.rule.properties.ave_id", where)
            if len(out) == before:  # form C: the tool's rule relates itself to the class
                for rel in _list(_dict(rules.get(rid)).get("relationships")):
                    target = _dict(_dict(rel).get("target"))
                    if _is_id(target.get("id")) and _is_ave_ref(target):
                        add(target["id"], "sarif.rule.relationships", where)
            seen = {f["ave_id"] for f in out[before:]}
            for taxon in _list(res.get("taxa")):
                tid = _dict(taxon).get("id")
                if _is_id(tid) and tid not in seen and _is_ave_ref(taxon):
                    add(tid, "sarif.result.taxa", where)
                    seen.add(tid)
    return out


# What: reads a JSON file, or says why it cannot
# Why:  an input that is not JSON is the commonest mistake and must be one clear message, not a traceback
# How:  UTF-8 with an optional BOM; returns (document, None) or (None, issue)
def read_json(path):
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        return None, issue("error", "input_unreadable", f"cannot read {path}: {e.strerror or e}")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, issue("error", "not_json", f"{path} is not JSON: it is not UTF-8 text")
    if not text.strip():
        return None, issue("error", "not_json", f"{path} is empty")
    try:
        return json.loads(text), None
    except (ValueError, RecursionError) as e:
        return None, issue("error", "not_json", f"{path} is not JSON: {e}")


# What: loads the records file the caller supplies, with its hash and its sibling manifest
# Why:  findings are judged against this catalog, and the report names exactly which one
# How:  a list of records (or an object with a `records` list), each with a string ave_id; the SHA-256 is of the file's
#       bytes; `<name>.manifest.json` beside it supplies release and schema_version when it exists.
#       Returns (records, info, None) or (None, None, issue).
def load_catalog(path):
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        return None, None, issue("error", "catalog_unreadable", f"cannot read the catalog {p}: {e.strerror or e}")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        return None, None, issue("error", "catalog_unreadable", f"the catalog {p} is not JSON")
    records = data if isinstance(data, list) else _dict(data).get("records")
    if not isinstance(records, list) or not all(isinstance(r, dict) and isinstance(r.get("ave_id"), str) for r in records):
        return None, None, issue("error", "catalog_unreadable", f"the catalog {p} is not an AVE records file (a list of records, each with an ave_id)")
    manifest = {}
    if p.name.endswith(".json"):
        sibling = p.with_name(p.name[: -len(".json")] + ".manifest.json")
        if sibling.is_file():
            try:
                manifest = _dict(json.loads(sibling.read_text(encoding="utf-8-sig")))
            except (OSError, ValueError, RecursionError):
                manifest = {}
    text = lambda k: manifest.get(k) if isinstance(manifest.get(k), str) else None
    info = {"file": str(p), "sha256": hashlib.sha256(raw).hexdigest(), "release": text("release"),
            "schema_version": text("schema_version"), "records": len(records)}
    return records, info, None


# What: checks every cited id against the catalog
# Why:  an id that does not exist cannot be scored; one that is not active points at a record that was merged, rejected or retired
# How:  once per distinct id. Not in the catalog is an error. Any status other than `active` is a warning (statuses can be
#       added, so only `active` counts as active), naming merged_into and rejection_reason when the record has them.
def check_catalog(findings, records):
    by_id = {r["ave_id"]: r for r in records}
    out = []
    for ave_id in dict.fromkeys(f["ave_id"] for f in findings):
        record = by_id.get(ave_id)
        if record is None:
            out.append(issue("error", "unknown_ave_id", f"{ave_id} is not in the catalog"))
        elif record.get("status") != "active":
            status = record.get("status")
            message = f"{ave_id} is {status}" if isinstance(status, str) and status else f"{ave_id} has no usable status, so it is not active"
            if record.get("merged_into"):
                message += f"; merged_into {record['merged_into']}"
            if record.get("rejection_reason"):
                message += f"; rejection_reason {record['rejection_reason']}"
            out.append(issue("warn", "not_active", message))
    return out


# What: judges one result against the spec's two forms
# Why:  form A (ruleId is the AVE id) and form B (the tool's ruleId, with properties.ave_id on the rule and on the result)
#       are both conformant; anything else is a result that does not say which class it reports
# How:  see the branches; every problem is added to `found` keyed by the rule id so repeats merge. A result that names no
#       AVE class is a warning, or an error with require_ids.
def _check_result(res, rules, where, found, require_ids):
    rid = _rule_id(res)
    result_id = _dict(res.get("properties")).get("ave_id")
    rule = rules.get(rid)
    rule_id = _dict(_dict(rule).get("properties")).get("ave_id")
    if _is_id(rid):  # form A
        if rule is None:
            found.add("error", "rule_missing", rid, f"{where}: ruleId {rid} has no matching rules[].id")
        for name, other in (("result", result_id), ("rule", rule_id)):
            if other is not None and other != rid:
                found.add("error", "id_mismatch", (rid, name), f"{where}: ruleId is {rid} but the {name}'s properties.ave_id is {other!r}")
        return
    if isinstance(rid, str) and rid.startswith("AVE-") and result_id is None and rule_id is None:
        found.add("error", "ave_id_malformed", rid, f"{where}: ruleId {rid!r} looks like an AVE id but is not one (AVE-YYYY-NNNNN)")
        return
    if result_id is None and rule_id is None and _form_c_ids(res, rule):  # form C
        if rule is None:
            found.add("error", "rule_missing", rid, f"{where}: ruleId {rid!r} has no matching rules[].id")
        return
    if result_id is None and rule_id is None:
        note = "" if require_ids else "; not judged, --require-ids makes this an error"
        found.add("error" if require_ids else "warn", "no_ave_id", rid, f"{where}: ruleId {rid!r} is not an AVE id and the result carries no properties.ave_id (AVE-in-SARIF: ruleId is the ave_id, or properties.ave_id on the result and its rule names it){note}")
        return
    # form B
    if rule is None:
        found.add("error", "rule_missing", rid, f"{where}: ruleId {rid!r} has no matching rules[].id")
    if result_id is None:
        found.add("error", "result_ave_id_missing", rid, f"{where}: form B needs properties.ave_id on the result; only the rule {rid!r} carries one")
    elif not _is_id(result_id):
        found.add("error", "ave_id_malformed", (rid, "result"), f"{where}: the result's properties.ave_id {result_id!r} is not an AVE id")
    if rule_id is None:
        found.add("error", "rule_ave_id_missing", rid, f"{where}: form B needs properties.ave_id on the rule {rid!r}")
    elif not _is_id(rule_id):
        found.add("error", "ave_id_malformed", (rid, "rule"), f"{where}: the rule {rid!r} properties.ave_id {rule_id!r} is not an AVE id")
    if result_id is not None and rule_id is not None and result_id != rule_id:
        found.add("error", "id_mismatch", (rid, "form-b"), f"{where}: the result says {result_id!r} but its rule {rid!r} says {rule_id!r}")


# What: checks how a run points at the AVE taxonomy
# Why:  a reference with the wrong guid names some other taxonomy, and a tool that uses the taxonomy should declare it
# How:  rule relationships and result.taxa whose toolComponent is called AVE but carries another guid are errors; using the
#       taxonomy without declaring it in driver.supportedTaxonomies is a warning
def _check_references(run, rules, n, found):
    used = False
    refs = [(rid, _dict(_dict(rel).get("target"))) for rid, rule in rules.items() for rel in _list(rule.get("relationships"))]
    refs += [(_rule_id(_dict(res)), _dict(t)) for res in _list(run.get("results")) for t in _list(_dict(res).get("taxa"))]
    for rid, ref in refs:
        comp = _dict(ref.get("toolComponent"))
        if comp.get("name") == "AVE" and isinstance(comp.get("guid"), str) and comp["guid"].lower() != AVE_GUID:
            found.add("error", "reference_guid_mismatch", (rid, ref.get("id")), f"runs[{n}]: a reference to {ref.get('id')!r} names toolComponent AVE with guid {comp['guid']!r}, not {AVE_GUID}")
        elif _is_id(ref.get("id")) and _is_ave_ref(ref):
            used = True
    supported = _list(_dict(_dict(run.get("tool")).get("driver")).get("supportedTaxonomies"))
    if used and not any(_is_ave_component(s) or _dict(s).get("name") == "AVE" for s in supported):
        found.add("warn", "supported_taxonomies_missing", n, f"runs[{n}] relates results to AVE classes but tool.driver.supportedTaxonomies does not declare the AVE taxonomy")


# What: judges a SARIF document against docs/specs/ave-in-sarif.md
# Why:  to tell a tool author what the spec asks for that the output lacks
# How:  no runs array is an error; an empty one has nothing to judge. Per result: _check_result (errors; a result naming no
#       AVE class is a warning unless require_ids). Per run: the three ave_* properties (recommended, warnings), the hash against the
#       catalog given (warning), and the AVE taxonomy: absent (warning), `version` against ave_catalog (error when they
#       differ, warning when it is missing), one taxon for each class cited (warning). A SARIF with no results is a warning.
def check_sarif(doc, catalog_info=None, require_ids=False, records=None):
    found = Issues()
    if not isinstance(doc.get("runs"), list):
        return [issue("error", "sarif_no_runs", "the SARIF has no runs array, so there is nothing to judge")]
    runs = doc["runs"]
    any_result = False
    for n, run in enumerate(runs):
        run = _dict(run)
        rules = _rules_by_id(run)
        results = _list(run.get("results"))
        any_result = any_result or bool(results)
        for i, res in enumerate(results):
            _check_result(_dict(res), rules, f"runs[{n}].results[{i}]", found, require_ids)
        props = _dict(run.get("properties"))
        for key in RUN_PROPERTIES:
            if key not in props:
                found.add("warn", "run_property_missing", key, f"runs[{n}].properties.{key} is missing (recommended: it names the catalog the scan used)")
        recorded = props.get("ave_records_sha256")
        if catalog_info and isinstance(recorded, str) and recorded.strip().lower() != catalog_info["sha256"]:
            found.add("warn", "catalog_sha_differs", n, f"runs[{n}] says it used records with SHA-256 {recorded}, but the catalog given has {catalog_info['sha256']}: the ids are judged against a different catalog than the run used")
        _check_references(run, rules, n, found)
        taxonomies = _list(run.get("taxonomies")) + _list(doc.get("taxonomies"))
        taxonomy = next((_dict(t) for t in taxonomies if _dict(t).get("name") == "AVE" or str(_dict(t).get("guid", "")).lower() == AVE_GUID), None)
        if taxonomy is None:
            found.add("warn", "taxonomies_missing", n, f"runs[{n}] has no AVE taxonomy (recommended: taxonomies[] with name \"AVE\")")
            continue
        guid = taxonomy.get("guid")
        if guid is None:
            found.add("warn", "taxonomy_guid_missing", n, f"runs[{n}]: the AVE taxonomy has no guid (recommended: {AVE_GUID}, so it cannot be confused with another taxonomy named AVE)")
        elif not isinstance(guid, str) or guid.lower() != AVE_GUID:
            found.add("error", "taxonomy_guid_mismatch", n, f"runs[{n}]: the AVE taxonomy guid is {guid!r}, not {AVE_GUID}")
        if records is not None:
            by_id = {r.get("ave_id"): r for r in records if isinstance(r, dict)}
            for taxon in _list(taxonomy.get("taxa")):
                taxon = _dict(taxon)
                tid = taxon.get("id")
                if tid not in by_id:
                    found.add("error", "taxon_unknown", tid, f"runs[{n}]: the AVE taxonomy lists {tid!r}, which is not in the catalog")
                elif isinstance(taxon.get("name"), str) and taxon["name"] != by_id[tid].get("title"):
                    found.add("warn", "taxon_name_differs", tid, f"runs[{n}]: the taxon {tid} is named {taxon['name']!r}, the catalog title is {by_id[tid].get('title')!r}")
        catalog, version = props.get("ave_catalog"), taxonomy.get("version")
        if catalog == "latest" and version is not None:
            found.add("error", "taxonomy_version_mismatch", n, f"runs[{n}]: ave_catalog is \"latest\", which has no release, so the AVE taxonomy omits version, but it says {version!r}")
        elif isinstance(catalog, str) and catalog != "latest":
            want = catalog[1:] if catalog.startswith("v") else catalog
            if version is None:
                found.add("warn", "taxonomy_version_missing", n, f"runs[{n}]: the AVE taxonomy has no version; ave_catalog is {catalog!r}, so it should be {want!r}")
            elif version != want:
                found.add("error", "taxonomy_version_mismatch", n, f"runs[{n}]: the AVE taxonomy version is {version!r} but ave_catalog {catalog!r} means {want!r}")
        listed = {_dict(t).get("id") for t in _list(taxonomy.get("taxa"))}
        for f in extract_findings({"runs": [run]}):
            if f["ave_id"] not in listed:
                found.add("warn", "taxon_missing", f["ave_id"], f"runs[{n}]: {f['ave_id']} is cited by a result but has no taxon in the AVE taxonomy")
    if not any_result:
        found.add("warn", "no_results", None, "the SARIF has no results, so there is nothing to judge (a clean scan, or a tool that reports nothing)")
    return found.items()


# What: the report for one parsed document
# Why:  one place decides pass, warn and fail, so the command line and the tests agree
# How:  extraction, then the catalog checks when a catalog was given, then the SARIF checks when the document is SARIF.
#       Errors are listed before warnings. `result` is fail with any error, warn with any warning, else pass.
def check_document(doc, records=None, catalog_info=None, file=None, require_ids=False):
    sarif = is_sarif(doc)
    findings = extract_findings(doc)
    issues = []
    if sarif:
        issues += check_sarif(doc, catalog_info, require_ids, records)
    if records is None:
        issues.append(issue("warn", "catalog_not_supplied", "no --catalog was given, so the ids were not checked against a catalog"))
    else:
        issues += check_catalog(findings, records)
    if sarif and not findings and any(_list(_dict(run).get("results")) for run in _list(doc.get("runs"))):
        issues.append(issue("warn", "no_ave_ids", "the SARIF has results, but none names an AVE class"))
    elif not sarif and not findings:
        issues.append(issue("warn", "no_ave_ids", "no AVE id was found (a clean scan, or a format this checker does not read)"))
    issues.sort(key=lambda i: i["severity"] != "error")
    via = {}
    for f in findings:
        via[f["via"]] = via.get(f["via"], 0) + 1
    result = "fail" if any(i["severity"] == "error" for i in issues) else "warn" if issues else "pass"
    return {"result": result, "file": file, "format": "sarif" if sarif else "json",
            "extracted": {"count": len(findings), "via": via}, "catalog": catalog_info, "issues": issues}


# What: the report and exit status for one output file
# Why:  the command line and the tests share it
# How:  read the input and the catalog (an unreadable one is an error report), then check_document.
#       Exit 2 on any error, 1 on warnings with strict, else 0.
def run_check(path, catalog_path=None, strict=False, require_ids=False):
    failed = lambda i: ({"result": "fail", "file": str(path), "format": None, "extracted": {"count": 0, "via": {}}, "catalog": None, "issues": [i]}, 2)
    doc, problem = read_json(path)
    if problem:
        return failed(problem)
    records = info = None
    if catalog_path is not None:
        records, info, problem = load_catalog(catalog_path)
        if problem:
            return failed(problem)
    try:
        report = check_document(doc, records, info, file=str(path), require_ids=require_ids)
    except RecursionError:
        return failed(issue("error", "not_json", f"{path} is nested too deeply to read"))
    status = report["result"]
    return report, 2 if status == "fail" else 1 if (status == "warn" and strict) else 0


# What: the one line printed on stderr after a report
# Why:  the report is for machines; a person running the command wants the verdict and the first reason
# How:  the first error, else the number of warnings
def _summary(report):
    errors = [i for i in report["issues"] if i["severity"] == "error"]
    warnings = [i for i in report["issues"] if i["severity"] == "warn"]
    if errors:
        more = f" (+{len(errors) - 1} more errors, {len(warnings)} warnings)" if len(errors) > 1 or warnings else ""
        return f"ave_conformance: fail: {errors[0]['message']}{more}"
    if warnings:
        return f"ave_conformance: warn: {len(warnings)} warning(s), {report['extracted']['count']} AVE id(s) found"
    return f"ave_conformance: pass: {report['extracted']['count']} AVE id(s) found"


# What: the command line
# Why:  `extract` for scorers, `check` for tool authors and CI
# How:  see the header comment
def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract the AVE ids a tool's output carries, and check the output against the AVE-in-SARIF spec.")
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract", help="print the AVE ids found in an output file, and how each was found")
    ex.add_argument("output")
    ck = sub.add_parser("check", help="judge an output file against the spec and a catalog file")
    ck.add_argument("output")
    ck.add_argument("--catalog", help="an AVE records file (a catalog release's ave-records.json or dist/ave-records-latest.json)")
    ck.add_argument("--strict", action="store_true", help="exit 1 when there are warnings")
    ck.add_argument("--require-ids", action="store_true", help="make a result that names no AVE class an error (default: a warning)")
    args = parser.parse_args(argv)
    if args.command == "extract":
        doc, problem = read_json(args.output)
        if problem:
            print(f"ave_conformance: {problem['message']}", file=sys.stderr)
            return 2
        try:
            print(json.dumps(extract_findings(doc), indent=2))
        except RecursionError:
            print(f"ave_conformance: {args.output} is nested too deeply to read", file=sys.stderr)
            return 2
        return 0
    report, code = run_check(args.output, args.catalog, args.strict, args.require_ids)
    print(json.dumps(report, indent=2))
    sys.stdout.flush()
    print(_summary(report), file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
