#!/usr/bin/env python3
"""Where do AVE's CVSS 4.0 bases come from, and how much can the deployment table move a band?

Reads records/AVE-*.json, recomputes each cvss_base_vector with the `cvss` package, and prints:
  1. a reproduction check (counts the conformance statement quotes), and under it the D21 count of band-sensitive records,
  2. a one-assumption-at-a-time sensitivity table (which metrics decide the bands),
  3. the Subsequent System counterfactual (SC, SI and SA all N),
  4. the component-type column test: can the deployment-factor values in section 6.1 change a band?

Run from the repository root:   pip install cvss && python3 scripts/vector_sensitivity.py
Scores use the v0.8 arithmetic in scripts/aivss_v08.py. Bands in part 2 are BASE bands (CVSS only), not final scores.
Part 4 uses the feasible Factor_Sum range per component type (the four table factors are fixed) and every threat
maturity and mitigation level.
"""
import collections
import glob
import itertools
import json
import os
import statistics
import sys
from decimal import Decimal as D

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "."))
import aivss_v08 as A  # noqa: E402
from cvss import CVSS4  # noqa: E402

RECORDS = sys.argv[1] if len(sys.argv) > 1 else "records"
# Factor_Sum range per component type: the four table factors are fixed, the six mechanism factors are 0 to 6.
RANGE = {"skill": (4.0, 10.0), "agent": (4.0, 10.0), "mcp_server": (3.0, 9.0)}
DEFAULT_RANGE = (3.0, 10.0)


# What: the CVSS v4.0 qualitative band of a base score (FIRST Table 22: Critical 9.0, High 7.0, Medium 4.0, Low below)
# Why:  part 2 and 3 count how often an assumption changes the band, not just the number
# How:  compare the score with the three band floors
def base_band(b):
    return "CRITICAL" if b >= 9 else "HIGH" if b >= 7 else "MEDIUM" if b >= 4 else "LOW"


# What: a copy of a CVSS v4.0 vector string with the named base metrics replaced
# Why:  the sensitivity tests change one assumption at a time and rescore
# How:  split on '/', substitute the value of each metric named in kw, keep the order, join again
def with_metrics(vector, **kw):
    head, *rest = vector.split("/")
    return "/".join([head] + [f"{k}:{kw.get(k, v)}" for k, v in (p.split(":") for p in rest)])


# What: the v0.8 AIVSS score for a CVSS base, a Factor_Sum, a ThM level and a mitigation level
# Why:  part 4 varies Factor_Sum directly, which scripts/aivss_v08.score (it takes ten factors) does not
# How:  the same exact-decimal equation as aivss_v08: (base + AARS) x Mitigation_Factor, rounded half up
def score(base, fs, thm, mit):
    c = D(str(base))
    uplift = (D(10) - c) * (D(str(fs)) / D(10)) * A.THM[thm]
    return A.r1((c + uplift) * A.MITIGATION[mit])


# What: (ave_id, component_type, vector, base score) for every record whose vector is a valid CVSS v4.0 vector
# Why:  the corpus statistics are over valid vectors; the invalid ones (AVE-2026-00066) are left out, and part 1 prints the count
# How:  read each record, score its cvss_base_vector with the `cvss` package, skip the record if the package rejects it
def load():
    out = []
    for path in sorted(glob.glob(os.path.join(RECORDS, "AVE-*.json"))):
        rec = json.load(open(path, encoding="utf-8"))
        vec = rec.get("cvss_base_vector")
        try:
            out.append((rec["ave_id"], rec.get("component_type"), vec, float(CVSS4(vec).base_score)))
        except Exception:
            continue
    return out


# What: the stored Mitigation_Factor of every record, by ave_id
# Why:  D21 takes the floor and the ceiling times the record's own Mitigation_Factor, which is not in the (id, type, vector, base) rows
# How:  read aivss.mitigation_factor from each record as an exact Decimal; a record that stores none gets 1, no mitigation credit
def load_mitigation():
    out = {}
    for path in sorted(glob.glob(os.path.join(RECORDS, "AVE-*.json"))):
        rec = json.load(open(path, encoding="utf-8"))
        out[rec["ave_id"]] = D(str((rec.get("aivss") or {}).get("mitigation_factor", 1)))
    return out


# What: D21's floor and ceiling scores for a CVSS base and a Mitigation_Factor
# Why:  the floor is Factor_Sum 0 (no uplift) and the ceiling is Factor_Sum 10 at threat maturity Attacked 1.00, so the ceiling
#       is 10 times the Mitigation_Factor whatever the base is
# How:  the same exact-decimal rounding as aivss_v08: base x factor, and 10 x factor, each rounded half up to one decimal
def d21_floor_ceiling(base, mitigation):
    m = D(str(mitigation))
    return A.r1(D(str(base)) * m), A.r1(D(10) * m)


# What: the ave_ids whose band differs between the D21 floor and the D21 ceiling, in the order of the rows
# Why:  docs/specs/aivss-v0.8-conformance.md D21 sizes the full-assessment tier with this count (14 of 88 on the 2026-11-05 vectors)
# How:  compare the two bands per record; a floor below 0.1 has no band (3.5.2) and counts as different from any ceiling
def d21_band_sensitive(rows, mitigation):
    ids = []
    for ave_id, _, _, base in rows:
        floor, ceiling = d21_floor_ceiling(base, mitigation.get(ave_id, D(1)))
        if floor < D("0.1") or A.band(floor) != A.band(ceiling):
            ids.append(ave_id)
    return ids


# What: prints the four parts described at the top of the file
# Why:  one command reproduces the numbers the conformance statement quotes and the sensitivity behind its decisions
# How:  load the valid vectors, then compute and print each part in turn; a part with nothing to measure prints zeros
def main():
    rows = load()
    bases = [r[3] for r in rows]
    if not rows:
        print("1. Reproduction: no record has a valid CVSS v4.0 vector")
        return
    # the base metrics of a vector as a dict, for example {'AV': 'N', 'AC': 'L', ...}
    metric = lambda v: dict(x.split(":") for x in v.split("/")[1:])  # noqa: E731
    print(f"1. Reproduction: {len(rows)} valid vectors; base >= 9.0: {sum(b >= 9 for b in bases)}; "
          f">= 7.0: {sum(b >= 7 for b in bases)}; median {statistics.median(bases)}; "
          f"any of SC/SI/SA High: {sum('H' in (metric(r[2])['SC'] + metric(r[2])['SI'] + metric(r[2])['SA']) for r in rows)}")
    print(f"   D21 band-sensitive records: {len(d21_band_sensitive(rows, load_mitigation()))} of {len(rows)} valid vectors "
          "(the band differs between the floor, base x stored Mitigation_Factor at Factor_Sum 0, and the ceiling, "
          "Factor_Sum 10 at threat maturity Attacked 1.00 with the same Mitigation_Factor)")

    print("\n2. One assumption changed at a time (base band, not final score):")
    print(f"   {'change':34s} {'records':>7s} {'median drop':>11s} {'max drop':>8s} {'band changes':>12s}")
    tests = [("UI:N -> P", "UI", "N", "P"), ("PR:N -> L", "PR", "N", "L"), ("AV:N -> A", "AV", "N", "A"),
             ("AC:L -> H", "AC", "L", "H"), ("AT:N -> P", "AT", "N", "P"), ("VC:H -> L", "VC", "H", "L"),
             ("VI:H -> L", "VI", "H", "L"), ("VA:H -> L", "VA", "H", "L"), ("SC:H -> L", "SC", "H", "L"),
             ("SI:H -> L", "SI", "H", "L")]
    for name, key, old, new in tests:
        drops, flips = [], 0
        for r in rows:
            if metric(r[2])[key] != old:
                continue
            nb = float(CVSS4(with_metrics(r[2], **{key: new})).base_score)
            drops.append(r[3] - nb)
            flips += base_band(nb) != base_band(r[3])
        if not drops:
            print(f"   {name:34s} {0:7d} {'-':>11s} {'-':>8s} {flips:12d}")
            continue
        print(f"   {name:34s} {len(drops):7d} {statistics.median(drops):11.1f} {max(drops):8.1f} {flips:12d}")

    drops, flips = [], 0
    for r in rows:
        nb = float(CVSS4(with_metrics(r[2], SC="N", SI="N", SA="N")).base_score)
        if nb != r[3]:
            drops.append(r[3] - nb)
            flips += base_band(nb) != base_band(r[3])
    triples = collections.Counter("".join(metric(r[2])[k] for k in ("SC", "SI", "SA")) for r in rows)
    print(f"\n3. Subsequent System: SC,SI,SA all N changes {len(drops)} records, median drop "
          f"{statistics.median(drops) if drops else 0:.1f}, max {max(drops) if drops else 0:.1f}, base band changes {flips}; "
          f"{len(triples)} distinct (SC,SI,SA) combinations; "
          f"SC=H {sum(metric(r[2])['SC'] == 'H' for r in rows)}, SI=H {sum(metric(r[2])['SI'] == 'H' for r in rows)}, "
          f"SA=H {sum(metric(r[2])['SA'] == 'H' for r in rows)}")

    print("\n4. Can the deployment-factor values move a band? (Autonomy + Tools 0.5 -> 1.0 is a Factor_Sum step of 1.0)")
    for ctype in ("mcp_server", "skill", "agent"):
        subset = [r for r in rows if r[1] == ctype]
        if not subset:
            continue
        lo_fs, hi_fs = RANGE.get(ctype, DEFAULT_RANGE)
        flipped, max_move = [], 0.0
        for r in subset:
            for thm, mit in itertools.product(A.THM, A.MITIGATION):
                fs = lo_fs
                while fs + 1.0 <= 10.0 and fs <= hi_fs:
                    lo, hi = score(r[3], fs, thm, mit), score(r[3], fs + 1.0, thm, mit)
                    max_move = max(max_move, hi - lo)
                    if A.band(lo) != A.band(hi):
                        flipped.append(r[0])
                    fs += 0.5
        print(f"   {ctype:11s} {len(subset):3d} records, bases {min(r[3] for r in subset)} to {max(r[3] for r in subset)}; "
              f"largest score move {max_move:.2f}; records whose band can change: {len(set(flipped))}")


if __name__ == "__main__":
    main()
