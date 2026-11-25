# AIVSS 1.0 lookup table: band movement on AVE's records

Date: 2026-11-19. Non-normative. This audit supports the decision, recorded in the AIVSS v0.8 conformance statement, that AVE schema 2.0.0 stays on AIVSS v0.8.

## Question

If AVE scored its active records with the lookup table (Table 6) of AIVSS 1.0 (the OWASP reference calculator of 2026-10-22; the README of its repository calls it v1; no specification text is published), how many records would change severity band?

## Method

1. For each active record with a valid CVSS 4.0 base vector, compute the CVSS 4.0 base score and its band (Low below 4.0, Medium below 7.0, High below 9.0, Critical from 9.0).
2. For the Agentic Effect Class A1 and for A2, take the AIVSS score as the higher of the Table 6 cell for that CVSS band and the CVSS score. The classes A0 and AX leave the CVSS score unchanged, so they cannot move a band.
3. Compare the band at A1 and at A2 with the CVSS band. Reading the A1 and A2 columns brackets what the table can do to a record.

## Inputs

- Records: aveproject/ave `develop` at commit 673b641b2b712b68e282a7baac3af24ccad23b25. 89 records, 85 of them `active`.
- Table 6: copied from `aivss_calc/lookup.py` in github.com/kenhuangus/aivss-v1-calculator at commit 5683ee73634059006d55bdf95d2485c65f8e98d1. That is the repository OWASP's AIVSS 1.0 reference calculator names as authoritative; it was called aivss-v1-candidate until 2026-10-22. The values are: Low 5.5 and 7.1, Medium 7.5 and 8.9, High 8.7 and 9.5, Critical 9.7 and 10.0, for A1 and A2.
- CVSS 4.0 scores: the `cvss` Python package, version 3.6.

## Caveats

- CVSS base vectors only. The records carry a base vector and no threat or environmental metrics, so these are base scores, not the CVSS-BTE score AIVSS 1.0 starts from.
- The bands here come from the CVSS base vectors. They are not the `severity` field the records carry today, which comes from AVE's own v0.8 calculation (among the 85 active records: 1 CRITICAL, 18 HIGH, 64 MEDIUM and 2 LOW).
- AVE holds no values for the five agentic metrics, so the effect class of each record is unknown. The audit therefore assumes every record is at A1, then every record at A2.
- One active record is skipped because its vector does not parse: AVE-2026-00066 (`UI:R` is not a valid CVSS 4.0 value).
- The authors of Table 6 say its cell values are policy settings that have not been validated against independently rated findings, and that FIRST has not validated or endorsed the extension.

## Code

Run with `python3 -I band_movement.py records` from a checkout, with the `cvss` package installed (it is LGPLv3+ and is not a dependency of this repository).

```python
import collections, glob, json, sys
from cvss import CVSS4

T6 = {"Low": (5.5, 7.1), "Medium": (7.5, 8.9), "High": (8.7, 9.5), "Critical": (9.7, 10.0)}

def band(x):
    return "None" if x == 0 else "Low" if x < 4 else "Medium" if x < 7 else "High" if x < 9 else "Critical"

rows, skipped = [], []
for path in sorted(glob.glob(sys.argv[1] + "/AVE-*.json")):
    rec = json.load(open(path, encoding="utf-8"))
    if rec.get("status") != "active":
        continue
    try:
        rows.append((rec["ave_id"], float(CVSS4(rec["cvss_base_vector"]).base_score)))
    except Exception:
        skipped.append(rec["ave_id"])
print("active with valid vector:", len(rows), "skipped:", skipped)
print("base bands:", dict(collections.Counter(band(b) for _, b in rows)))
move = collections.Counter()
for _, b in rows:
    k = band(b)
    if k not in T6:
        continue
    a1, a2 = max(b, T6[k][0]), max(b, T6[k][1])
    move[(k, band(a1), band(a2))] += 1
for key, n in sorted(move.items()):
    print("base band, band at A1, band at A2:", key, n)
print("band changes at A1:", sum(n for (k, x, _), n in move.items() if x != k))
print("band changes at A2:", sum(n for (k, _, y), n in move.items() if y != k))
```

## Output

```text
active with valid vector: 84 skipped: ['AVE-2026-00066']
base bands: {'Critical': 64, 'High': 19, 'Low': 1}
base band, band at A1, band at A2: ('Critical', 'Critical', 'Critical') 64
base band, band at A1, band at A2: ('High', 'High', 'Critical') 19
base band, band at A1, band at A2: ('Low', 'Medium', 'High') 1
band changes at A1: 1
band changes at A2: 20
```

## Reading the output

- Of 84 active records with a valid vector, 64 are Critical, 19 High and 1 Low by CVSS base score.
- At A1, 1 record changes band (the Low one, to Medium). At A2, 20 records change band: 19 from High to Critical and the Low one to High.
- The 64 Critical records cannot move. Most of the severity distribution is therefore decided by the CVSS vectors, whatever the agentic metrics say.
