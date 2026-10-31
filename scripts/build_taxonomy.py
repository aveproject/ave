#!/usr/bin/env python3
"""Build the canonical AVE taxonomy as a SARIF 2.1.0 standard-taxonomy toolComponent.

    python scripts/build_taxonomy.py                      # writes dist/ave-taxonomy-latest.json from dist/ave-records-latest.json
    python scripts/build_taxonomy.py --check              # exits 1 when the file on disk is not what the records produce
    python scripts/build_taxonomy.py --release v1.3.0 --release-date 2026-11-05 --download-uri URL --out PATH
    python scripts/build_taxonomy.py --only AVE-2026-00001,AVE-2026-00075 --out -   # the subset a scanner embeds

Standard library only. The output is deterministic: same records in, same bytes out.
"""
import argparse, json, re, sys, uuid
from pathlib import Path

# The taxonomy's identity. SARIF consumers match a taxonomy by guid, so a tool that names its own taxonomy "AVE"
# is not confused with this one. Frozen: a test pins the value; changing it breaks every consumer that stored it.
GUID = "5110b285-34d7-5334-94db-0308b24cfb49"  # uuid5(NAMESPACE_URL, "https://aveproject.org/taxonomy/AVE")
NAME = "AVE"
INFO_URI = "https://aveproject.org"
HELP_URI = "https://aveproject.org/registry.html#{id}"
ID = re.compile(r"AVE-[0-9]{4}-[0-9]{5}")
EXTRA = ("merged_into", "rejection_reason")  # present on records only when their status needs them


def _version(release):
    if release is None:
        return None
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release):
        raise ValueError(f"--release must look like v1.3.0, got {release!r}")
    return release[1:]


def taxon(rec):
    aivss = rec.get("aivss") if isinstance(rec.get("aivss"), dict) else {}
    props = {"status": rec.get("status"), "severity": rec.get("severity"), "aivss_score": aivss.get("aivss_score"),
             "detection_stage": rec.get("detection_stage")}
    for key in EXTRA:
        if rec.get(key) is not None:
            props[key] = rec[key]
    out = {"id": rec["ave_id"], "name": rec["title"]}
    if rec.get("attack_class"):
        out["shortDescription"] = {"text": rec["attack_class"]}
    if rec.get("behavioral_fingerprint"):
        out["fullDescription"] = {"text": rec["behavioral_fingerprint"]}
    out["helpUri"] = HELP_URI.format(id=rec["ave_id"])
    out["properties"] = {k: v for k, v in props.items() if v is not None}
    return out


def build(records, release=None, release_date=None, download_uri=None, only=None):
    ids = [r["ave_id"] for r in records]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate ave_id in the records")
    wanted = None if only is None else set(only)
    if wanted is not None:
        unknown = sorted(wanted - set(ids))
        if unknown:
            raise ValueError(f"not in the records: {', '.join(unknown)}")
    chosen = sorted((r for r in records if wanted is None or r["ave_id"] in wanted), key=lambda r: r["ave_id"])
    comp = {"guid": GUID, "name": NAME, "fullName": "Agentic Vulnerability Enumeration", "organization": "AVE Project",
            "product": "AVE", "informationUri": INFO_URI,
            "shortDescription": {"text": "Agentic Vulnerability Enumeration: behavioral vulnerability classes for agentic AI components"},
            "language": "en", "contents": ["nonLocalizedData"], "isComprehensive": wanted is None}
    version = _version(release)
    if version:
        comp["version"] = version
        comp["semanticVersion"] = version
        if release_date:
            comp["releaseDateUtc"] = release_date
        if download_uri:
            comp["downloadUri"] = download_uri
    comp["taxa"] = [taxon(r) for r in chosen]
    return comp


def dumps(comp):
    return json.dumps(comp, indent=2, ensure_ascii=False) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--records", default="dist/ave-records-latest.json")
    ap.add_argument("--out", default="dist/ave-taxonomy-latest.json")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--release"); ap.add_argument("--release-date"); ap.add_argument("--download-uri")
    ap.add_argument("--only")
    a = ap.parse_args(argv)
    records = json.loads(Path(a.records).read_text(encoding="utf-8"))
    text = dumps(build(records, a.release, a.release_date, a.download_uri, a.only.split(",") if a.only else None))
    if a.check:
        have = Path(a.out).read_text(encoding="utf-8") if Path(a.out).exists() else None
        if have != text:
            print(f"{a.out} is not what {a.records} produces; run: python scripts/build_taxonomy.py", file=sys.stderr)
            return 1
        print(f"{a.out} matches {a.records}")
        return 0
    if a.out == "-":
        sys.stdout.write(text)
    else:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"wrote {a.out}: {len(json.loads(text)['taxa'])} taxa")
    return 0


if __name__ == "__main__":
    sys.exit(main())
