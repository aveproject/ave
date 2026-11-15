"""The OWASP AIVSS v0.8 arithmetic, in exact decimal. Pure functions, no I/O.

Nothing imports this yet. It is the reference arithmetic that docs/specs/aivss-v0.8-conformance.md describes, kept
standalone until the maintainer approves that statement; schema 2.0.0 work would wire it into scripts/validate_records.py.

Source: "AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8", Part 2 (SHA-256
a2abbd215f0d7790d273c30a893a09c0dc37a6c109765eb0363c01af897fd9af):
  factors 2.1, 2.2 and Table 1, with the key names of Appendix A; AARS 3.3.1; ThM 3.3.2 (Table 4a);
  primary equation 3.4 and 3.4.0; Mitigation_Factor 3.4.1 (Table 4b); rounding 3.5.1; bands 3.5.2.

All arithmetic is exact decimal. A float product misrounds raw values that are exact ties (8.65 must become 8.7,
3.5.1): over the whole input grid a float implementation is one tenth low for 36 of 19,089 inputs.
"""

from decimal import ROUND_HALF_UP, Decimal

D = Decimal
FACTORS = ("autonomy", "tools", "language", "context", "non_determinism", "opacity", "persistence", "identity", "multi_agent", "self_mod")
FACTOR_LEVELS = (D("0.0"), D("0.5"), D("1.0"))
THM = {"attacked": D("1.00"), "poc": D("0.97"), "unreported": D("0.50")}      # Table 4a; the specification's default is poc
MITIGATION = {"none": D("1.00"), "partial": D("0.83"), "strong": D("0.67")}   # Table 4b; default none; 0.67 is provisional
BANDS = (("CRITICAL", D("9.0")), ("HIGH", D("7.0")), ("MEDIUM", D("4.0")), ("LOW", D("0.1")))   # 3.5.2; 0.0 has no band


# What: turns a number or a string into an exact Decimal
# Why:  Decimal(float) carries the binary error that Decimal(str(float)) does not
# How:  pass a Decimal through unchanged, convert anything else through its shortest string
def _d(x):
    return x if isinstance(x, Decimal) else D(str(x))


# What: rounds half up to one decimal (3.5.1: 8.64 becomes 8.6, 8.65 becomes 8.7)
# Why:  Python's round() is ties-to-even on a float, which is what AVE's 1.x scores used
# How:  exact Decimal quantize with ROUND_HALF_UP
def r1(x):
    return float(_d(x).quantize(D("0.1"), rounding=ROUND_HALF_UP))


# What: sums the ten factors exactly after checking the key set and every level
# Why:  an eleventh key, a missing factor or a value like 0.3 would change every score without any error
# How:  compare the keys with FACTORS, check each value is 0.0, 0.5 or 1.0, add as Decimals
def _factor_sum(aarf):
    if set(aarf) != set(FACTORS):
        raise ValueError(f"aarf must have exactly the ten v0.8 factors, got {sorted(set(aarf) ^ set(FACTORS))} different")
    for k, v in aarf.items():
        if _d(v) not in FACTOR_LEVELS:
            raise ValueError(f"{k}={v} is not one of {tuple(float(x) for x in FACTOR_LEVELS)}")
    return sum((_d(v) for v in aarf.values()), D(0))


# What: Factor_Sum as a float (3.3.1)
# Why:  callers store and compare it as a plain number; every legal sum is a multiple of 0.5, so the float is exact
# How:  the exact sum, converted
def factor_sum(aarf):
    return float(_factor_sum(aarf))


# What: the agentic uplift AARS = (10 - CVSS_Base) x (Factor_Sum / 10) x ThM, exact (3.3.1)
# Why:  the score uses the unrounded uplift (3.4.0 step 3), and a stored AARS needs all of its places (at most five)
# How:  Decimal arithmetic; cvss_base must lie in 0.0 to 10.0 and thm_level must be a key of THM
def aars_exact(cvss_base, aarf, thm_level):
    c = _d(cvss_base)
    if not D(0) <= c <= D(10):
        raise ValueError("cvss_base out of range")
    return (D(10) - c) * (_factor_sum(aarf) / D(10)) * THM[thm_level]


# What: the uplift as a float
# Why:  convenient for display and approximate comparison; never use it to compute a score
# How:  the exact uplift, converted
def aars(cvss_base, aarf, thm_level):
    return float(aars_exact(cvss_base, aarf, thm_level))


# What: AIVSS = RoundHalfUp((CVSS_Base + AARS) x Mitigation_Factor, 1) (3.4, 3.4.0, 3.5.1)
# Why:  this is the number a record states and a validator recomputes
# How:  one exact Decimal expression, rounded once at the end
def score(cvss_base, aarf, thm_level, mitigation_level):
    return r1((_d(cvss_base) + aars_exact(cvss_base, aarf, thm_level)) * MITIGATION[mitigation_level])


# What: the severity band of a reported score (3.5.2)
# Why:  CLAUDE.md hard rule 6 ties a record's severity to its score
# How:  the first band whose floor the score reaches; below 0.1 the specification defines no band, so raise
def band(s):
    v = _d(s)
    for name, floor in BANDS:
        if v >= floor:
            return name
    raise ValueError(f"{s} is below 0.1; AIVSS v0.8 defines no band for it (3.5.2)")
