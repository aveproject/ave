# CVSS input reconciliation audit

Audits whether each AVE record's stored `aivss.cvss_base` is the CVSS v4.0 base score of the record's own
`cvss_base_vector`. Report only: no record, schema file or script was changed, and none is proposed here.

**Date:** 2026-10-31. **Records:** 89 (all `active`, schema 1.3.0, `aveproject/ave` `develop` at `dfb920f`).

## Summary

- 3 records have a stored `cvss_base` equal to the score their vector computes to (AVE-2026-00046, AVE-2026-00088, AVE-2026-00089).
- 85 records differ: 78 computed higher than stored (mean +1.03, up to +2.7) and 7 computed lower (mean -1.33, down to -4.2). Over the 85, computed minus stored has a mean of +0.84 and a mean absolute value of 1.06.
- 1 vector is not a valid CVSS v4.0 vector: AVE-2026-00066 uses `UI:R`, a CVSS 3.1 value. Both implementations reject it.
- Two independent implementations of the CVSS v4.0 equations agree on all 88 valid vectors.
- Neither explanation tested for the differences fits. The record notes say where the base came from for only 7 of the 85 differing records.

## Why it matters

OWASP AIVSS v0.8 takes a CVSS v4.0 base score as its baseline and warns against CVSS 3.1 inputs (section 3.1.1). Its equation adds the agentic uplift to the base (`AIVSS = (CVSS_Base + AARS) x Mitigation_Factor`, sections 3.3 and 3.4), so the base is the floor of the score: a record never scores below its `cvss_base` times its mitigation factor. Whatever AVE scores under v0.8 inherits this input whole. AVE's own equation (`((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor`) also counts it, as half of the average. See #395 for why the equation matters.

## Method

1. For each record, the CVSS v4.0 base score of `cvss_base_vector`, computed by two implementations:
   - **`cvss` 3.6**, the Python library from Red Hat Product Security (`pip install cvss`), `CVSS4(vector).base_score`.
   - **FIRST's own calculator source**, `FIRSTdotorg/cvss-v4-calculator` at commit `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a` (a browser application, BSD-2-Clause). Its scoring files (`cvss_score.js`, `cvss_lookup.js`, `max_severity.js`, `max_composed.js`, `metrics.js`) were read first: they touch no network, file system or DOM. They were then run unchanged in a bare Node 20 `vm` context with only the globals they define, by the driver in the appendix, with each vector parsed and validated against the calculator's own `expectedMetricOrder`. The two codebases are written in different languages; the Red Hat group also contributes to FIRST's calculator, so they are independent implementations, not independent authors.
2. Sanity check of both on published reference vectors: `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` gives 9.3, the same with `SC:H/SI:H/SA:H` gives 10.0, and all impacts `N` gives 0.0, in both.
3. A stored base and a computed base are equal when they differ by less than 0.05.

## Results

| | Records |
|---|---|
| Vector valid, both implementations agree | 88 |
| Stored equals computed | 3 |
| Stored differs from computed | 85 |
| Vector invalid (both implementations reject it) | 1 |

Size and direction of the 85 differences (computed minus stored):

| Size of difference | Computed higher | Computed lower |
|---|---|---|
| 0.5 or less | 21 | 2 |
| over 0.5 to 1.0 | 24 | 2 |
| over 1.0 to 2.0 | 30 | 2 |
| over 2.0 | 3 | 1 |

Where the stored values sit: 24 distinct values between 6.2 and 10, all to one decimal. The computed scores take 18 distinct values between 2.3 and 10; 67 of 88 are 9.0 or more, against 18 of 89 stored. 20 vectors set all three Subsequent System impacts (`SC`, `SI`, `SA`) to `H`.

### The invalid vector

`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`: `UI:R` ("required") is a CVSS 3.1 user-interaction value. CVSS v4.0 has `UI:N`, `UI:P` (passive) and `UI:A` (active). Its stored base is 9.

## Explanations tested

**A. The stored numbers are CVSS 3.1 scores of the same metrics.** A v4.0 vector has no exact 3.1 equivalent, so twelve mappings were tried (Scope unchanged, or changed when any Subsequent impact is not `N`, or when any is `H`; `AT:P` ignored or read as `AC:H`; `UI:P` read as `R` or `N`), each scored with the `cvss` library's `CVSS3`. The most favourable mapping reproduces the stored base for 12 of 88 records (45 within 0.5); the other eleven do no better. Choosing the best of twelve overstates the fit, and it is still a small minority. **This does not explain the differences.**

**B. The stored numbers were estimated by hand and have no fixed relation to the vector.** Over the 88 valid records the correlation between stored and computed is r = 0.46: a weak relation, with the stored values in a narrower, higher range. This is consistent with hand estimation and does not prove it. The record notes do not settle it: only 7 of the 85 differing records say in `aivss.notes` that `cvss_base` reflects a CVE or an NVD score; the other 78 say nothing about where the base came from. Whether a CVE-derived base is a CVSS 3.1 or 4.0 score is not stated either, and was not checked against NVD here.

**Conclusion.** Neither explanation fits, and no cause is asserted. What is established is that the stored `cvss_base` cannot be derived from the stored vector for 85 of 88 valid vectors, and that the vector set itself has a problem (one invalid vector, and 20 with all Subsequent impacts `H`, which was not examined against each class).

## Recommendation for the 2.0.0 migration

1. **The CVSS vector is the authoritative input; the base is computed from it.** For each record, re-derive the v4.0 vector from the class's impact (the Subsequent System metrics deserve the most care: v0.8 says to assess them from what a compromised agent can reach through its tools, delegation and inter-agent paths, section 3.1.1), compute the base with a named implementation, and store both.
2. **Add a validator rule** that `cvss_base` equals the base score of `cvss_base_vector`, with the implementation and its exact version pinned in the development requirements, and a test that fails if the two implementations used here disagree on any record's vector.
3. **Do this inside the 2.0.0 migration, once.** Changing `cvss_base` before then would silently rescore the corpus under the 1.x equation; changing it during the migration changes it together with everything else that moves, and `revisions` records it.
4. Treat the invalid vector as a defect to correct in the same pass, not as an input.

## What this audit did not do

- It did not change any record, and does not say which of the stored base or the computed base is nearer the truth for any class. That is a judgement about each class's impact, and belongs to the re-assessment.
- It did not check any base against NVD, or any vector's metric choices against the class it describes.
- It tested two explanations, not every possible one.

## Full table

| Record | Stored `cvss_base` | Computed | Computed minus stored | Class | Vector |
|---|---|---|---|---|---|
| AVE-2026-00001 | 8.5 | 9.5 | +1 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00002 | 8.7 | 9 | +0.3 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` |
| AVE-2026-00003 | 8.5 | 7 | -1.5 | lower, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| AVE-2026-00004 | 8.8 | 9.5 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00005 | 9.1 | 8.4 | -0.7 | lower, over 0.5 to 1.0 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H` |
| AVE-2026-00006 | 9.6 | 10 | +0.4 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00007 | 8.1 | 9.5 | +1.4 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00008 | 8.4 | 9.3 | +0.9 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00009 | 8.3 | 9.5 | +1.2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00010 | 7.9 | 9.5 | +1.6 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:L/SA:L` |
| AVE-2026-00011 | 8.2 | 9.5 | +1.3 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00012 | 7.8 | 9.5 | +1.7 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00013 | 8 | 9.1 | +1.1 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:L` |
| AVE-2026-00014 | 6.5 | 9 | +2.5 | higher, over 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` |
| AVE-2026-00015 | 6.2 | 8.9 | +2.7 | higher, over 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| AVE-2026-00016 | 8 | 9.4 | +1.4 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00017 | 8.3 | 8.8 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00018 | 7.5 | 9 | +1.5 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` |
| AVE-2026-00019 | 8 | 9.4 | +1.4 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00020 | 8.7 | 9.4 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00021 | 8.6 | 9.4 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00022 | 7.5 | 7.1 | -0.4 | lower, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N` |
| AVE-2026-00023 | 8 | 9.5 | +1.5 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00024 | 8.5 | 9 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` |
| AVE-2026-00025 | 7.8 | 9.4 | +1.6 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00026 | 9.1 | 8.9 | -0.2 | lower, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| AVE-2026-00027 | 8 | 9.4 | +1.4 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00028 | 8.2 | 8.6 | +0.4 | higher, 0.5 or less | `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00029 | 7.5 | 9 | +1.5 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` |
| AVE-2026-00030 | 7.8 | 8.8 | +1 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00031 | 7.5 | 9.4 | +1.9 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00032 | 7.8 | 7 | -0.8 | lower, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| AVE-2026-00033 | 8.5 | 9.5 | +1 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00034 | 9 | 9.5 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00035 | 7.5 | 9 | +1.5 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N` |
| AVE-2026-00036 | 8.8 | 9 | +0.2 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00037 | 8 | 8.8 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00038 | 7.8 | 9.5 | +1.7 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00039 | 8.5 | 7 | -1.5 | lower, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| AVE-2026-00040 | 7.5 | 8.8 | +1.3 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00041 | 9.3 | 10 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00042 | 9 | 9.5 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00043 | 8.5 | 8.9 | +0.4 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00044 | 8.2 | 8.9 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00045 | 9 | 9.5 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00046 | 10 | 10 |  | equal | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00047 | 8.7 | 9.3 | +0.6 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H` |
| AVE-2026-00048 | 9 | 9.5 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00049 | 8 | 9.2 | +1.2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N` |
| AVE-2026-00050 | 8.5 | 10 | +1.5 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00051 | 9.5 | 9.9 | +0.4 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00052 | 9.8 | 10 | +0.2 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00053 | 8.5 | 9.2 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N` |
| AVE-2026-00054 | 9.3 | 9.4 | +0.1 | higher, 0.5 or less | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00055 | 9.5 | 10 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00056 | 7.5 | 8.9 | +1.4 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| AVE-2026-00057 | 7.5 | 9.5 | +2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00058 | 6.5 | 2.3 | -4.2 | lower, over 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N` |
| AVE-2026-00059 | 8.7 | 9.5 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00060 | 9.8 | 10 | +0.2 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00061 | 7.5 | 8.8 | +1.3 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00062 | 7 | 9.2 | +2.2 | higher, over 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N` |
| AVE-2026-00063 | 8.5 | 9.3 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N` |
| AVE-2026-00064 | 9 | 9.4 | +0.4 | higher, 0.5 or less | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00065 | 8.7 | 10 | +1.3 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00066 | 9 |  |  | invalid vector | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00067 | 7.5 | 9.4 | +1.9 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:N` |
| AVE-2026-00068 | 8 | 8.7 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N` |
| AVE-2026-00069 | 8 | 9.4 | +1.4 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:N` |
| AVE-2026-00070 | 9 | 9.5 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N` |
| AVE-2026-00071 | 8.5 | 9.5 | +1 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00072 | 8.7 | 9.4 | +0.7 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00073 | 7 | 9 | +2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N` |
| AVE-2026-00074 | 8.7 | 9.5 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| AVE-2026-00075 | 7.5 | 9.5 | +2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00076 | 8.5 | 9.4 | +0.9 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:N` |
| AVE-2026-00077 | 8.3 | 9.4 | +1.1 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00078 | 8.3 | 9.1 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00079 | 8.5 | 9 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00080 | 8.2 | 9.1 | +0.9 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:H/SI:H/SA:N` |
| AVE-2026-00081 | 8 | 10 | +2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00082 | 6.8 | 7.2 | +0.4 | higher, 0.5 or less | `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N` |
| AVE-2026-00083 | 8.7 | 9.9 | +1.2 | higher, over 1.0 to 2.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| AVE-2026-00084 | 9 | 9.5 | +0.5 | higher, 0.5 or less | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00085 | 8.7 | 9.5 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00086 | 8.5 | 9.5 | +1 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00087 | 8.7 | 9.5 | +0.8 | higher, over 0.5 to 1.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L` |
| AVE-2026-00088 | 7.7 | 7.7 |  | equal | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| AVE-2026-00089 | 8.6 | 8.6 |  | equal | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

## Appendix: reproduction

Library check (run from the repository root after `pip install cvss==3.6`; `--markdown` prints the table above):

```python
"""Reconcile each record's stored cvss_base with the CVSS v4.0 base score computed from its own cvss_base_vector.
Run from the repo root:  pip install cvss==<pinned>  &&  python cvss_check.py [--markdown]"""
import glob, json, sys
from cvss import CVSS4
rows = []
for f in sorted(glob.glob("records/AVE-*.json")):
    r = json.load(open(f, encoding="utf-8")); v = r.get("cvss_base_vector"); stored = r["aivss"]["cvss_base"]
    try: calc = float(CVSS4(v).base_score); err = ""
    except Exception as e: calc, err = None, str(e)[:60]
    rows.append((r["ave_id"], stored, calc, err, v))
ok = sum(1 for x in rows if x[2] is not None and abs(x[2] - x[1]) < 0.05); bad = [x for x in rows if x[2] is not None and abs(x[2] - x[1]) >= 0.05]
inv = [x for x in rows if x[2] is None]
print(f"records {len(rows)} | stored equals computed {ok} | differs {len(bad)} | invalid vector {len(inv)}")
if bad:
    d = [x[2] - x[1] for x in bad]; print(f"difference (computed - stored): mean {sum(d)/len(d):+.2f}, min {min(d):+.1f}, max {max(d):+.1f}, mean absolute {sum(abs(x) for x in d)/len(d):.2f}")
if "--markdown" in sys.argv:
    print("\n| ave_id | stored | computed | note | vector |\n|---|---|---|---|---|")
    for a, s, c, e, v in rows: print(f"| {a} | {s} | {'' if c is None else c} | {e or ('match' if c is not None and abs(c - s) < 0.05 else 'differs')} | `{v}` |")
```

FIRST calculator driver (run from a directory other than the calculator's, as `node run.js <calculator checkout> <records directory>`):

```js
// Runs FIRST's reference CVSS v4.0 scoring code (FIRSTdotorg/cvss-v4-calculator, files loaded as text) on each record's vector.
// The files run in a vm context that has no require, no fs, no network and no DOM: only the globals they define.
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const [calcDir, recordsDir] = process.argv.slice(2);
const ctx = vm.createContext({ console });
for (const f of ["max_composed.js", "cvss_lookup.js", "max_severity.js", "metrics.js", "cvss_score.js"]) {
  vm.runInContext(fs.readFileSync(path.join(calcDir, f), "utf8"), ctx, { filename: f });
}
const run = (code) => vm.runInContext(code, ctx);
const order = run("expectedMetricOrder");              // metric -> allowed values (base, threat, environmental, supplemental)
const out = [];
for (const file of fs.readdirSync(recordsDir).filter((n) => /^AVE-\d{4}-\d{5}\.json$/.test(n)).sort()) {
  const rec = JSON.parse(fs.readFileSync(path.join(recordsDir, file), "utf8"));
  const vector = rec.cvss_base_vector;
  const row = { ave_id: rec.ave_id, vector };
  try {
    const parts = vector.split("/");
    if (parts[0] !== "CVSS:4.0") throw new Error("not a CVSS:4.0 vector");
    const sel = {};
    for (const k of Object.keys(order)) sel[k] = "X";
    for (const p of parts.slice(1)) {
      const [k, v] = p.split(":");
      if (!(k in order)) throw new Error(`unknown metric ${k}`);
      if (!order[k].includes(v)) throw new Error(`value ${v} is not valid for ${k}`);
      sel[k] = v;
    }
    ctx.__sel = sel;
    row.score = run("cvss_score(__sel, cvssLookup_global, maxSeverity, macroVector(__sel))");
  } catch (e) {
    row.error = String(e.message).slice(0, 80);
  }
  out.push(row);
}
console.log(JSON.stringify(out));
```
