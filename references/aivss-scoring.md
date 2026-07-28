# AIVSS scoring reference

The formula: `aivss_score = round(((cvss_base + aars) / 2) * thm * mitigation_factor, 1)`

Where `aars` is the sum of ten AARF (Agentic AI Risk Factor) values, each
scored 0, 0.5, or 1:

- `autonomy`: does this fire without further attacker interaction once
  triggered
- `tool_use`: does it require the agent's own tool-calling capability
- `multi_agent`: does it require or specifically involve more than one
  agent
- `non_determinism`: does exploitation reliability vary run to run
- `self_modification`: does the component modify its own behavior or the
  agent's runtime
- `dynamic_identity`: does it involve impersonation, identity claims, or
  trust-anchor confusion
- `persistent_memory`: does the effect persist beyond the current session
- `natural_language_input`: is the exploit mechanism itself natural
  language, versus a structural/syntactic mechanism that merely
  originates from an NL-driven call
- `data_access`: does exploitation grant or require broad data access
- `external_dependencies`: does severity depend on which specific SDK,
  library, or third-party service is in use

`thm` (technique has model): 1 if the mechanism is real and demonstrated
(a disclosed CVE, published research, a working exploit description), 1
means no discount; lower values exist for less-verified mechanisms but
every record in this corpus so far has scored 1, since the evidentiary
bar in Step 3 of the main workflow already requires real sourcing.

`mitigation_factor`: 1 if no broadly effective, ecosystem-wide mitigation
exists yet (don't discount just because a fix is theoretically possible);
0.83 if a simple, well-known, standard mitigation exists and is
reasonably expected to be applied (pinning a dependency, re-enabling TLS
verification). Never invent a value outside this observed 1/0.83 range
without a clearly stated reason, since every record so far has used one
of these two.

## Severity bands

- CRITICAL: 9.0 to 10.0
- HIGH: 7.0 to 8.9
- MEDIUM: 4.0 to 6.9
- LOW: below 4.0

## The counterintuitive part, worth internalizing before scoring anything

A mechanism that sounds severe in plain English can still land MEDIUM,
correctly, if it's narrow and single-vector. AARF's ten factors reward
*breadth* of amplification, not just raw impact. `cvss_base` alone
carries the raw severity of the underlying impact; a near-maximum
`cvss_base` (9.0+) on a narrow, single-mechanism class (no multi-agent
involvement, no persistence, no self-modification) will still average
down to MEDIUM once combined with a modest `aars`. This already happened
correctly for the zero-click auto-run record (`cvss_base` 9.0, landed at
5.2 MEDIUM) and the STDIO shell injection record landing HIGH rather than
CRITICAL despite being RCE (`cvss_base` 9.8, `aars` only 4.5). Do not
inflate AARF factors to force a class into a "more severe-sounding" band;
report the honest computed result and explain why in the record's own
`aivss.notes` field, the same way every record in this corpus already
does.

## Worked examples

**STDIO transport shell injection** (HIGH, 7.2): `cvss_base` 9.8 (near-max,
this is RCE), `aarf` sums to 4.5 (autonomy 1, tool_use 1, natural_language_input
0.5, data_access 1, external_dependencies 1, everything else 0), `thm` 1,
`mitigation_factor` 1 (patches exist but ecosystem-wide exposure wasn't
resolved at time of writing). `((9.8+4.5)/2)*1*1 = 7.15` rounds to 7.2.

**TLS verification disabled** (MEDIUM, 4.1): `cvss_base` 7.5, `aarf` sums
to 2.5 (autonomy 0.5, tool_use 0.5, data_access 1, external_dependencies
0.5), `thm` 1, `mitigation_factor` 0.83 (a simple, standard fix exists).
`((7.5+2.5)/2)*1*0.83 = 4.15` rounds to 4.1.

**A2A agent card poisoning** (HIGH, 7.1): `cvss_base` 8.7, `aarf` sums to
5.5 (autonomy 1, tool_use 0.5, multi_agent 1 at genuine maximum since
this is definitionally a two-agent mechanism, non_determinism 0.5,
dynamic_identity 0.5, natural_language_input 1, data_access 0.5,
external_dependencies 0.5), `thm` 1, `mitigation_factor` 1. `((8.7+5.5)/2)*1*1
= 7.1`.

**Zero-click IDE auto-run** (MEDIUM, 5.2, despite sounding severe):
`cvss_base` 9.0 (near-max, zero-click RCE-adjacent), `aarf` sums to only
3.5 (autonomy 1, tool_use 0.5, persistent_memory 0.5, data_access 1,
external_dependencies 0.5, no multi-agent, no self-modification), `thm`
1, `mitigation_factor` 0.83 (disabling auto-run is a known, standard
fix). `((9.0+3.5)/2)*1*0.83 = 5.1875` rounds to 5.2. This is the record
worth re-reading if a future score feels wrong, it's the clearest example
of a severe-sounding mechanism correctly landing MEDIUM.

**Unpinned dependency substitution** (MEDIUM, 4.4): `cvss_base` 7.0,
`aarf` sums to 3.5 (autonomy 0.5, tool_use 0.5, non_determinism 0.5,
persistent_memory 0.5, data_access 0.5, external_dependencies 1 at
maximum since this class is definitionally about dependency behavior),
`thm` 1, `mitigation_factor` 0.83. `((7.0+3.5)/2)*1*0.83 = 4.3575` rounds
to 4.4.

## Always independently re-verify

Compute the score by hand or by reasoning, then run the actual arithmetic
in `scripts/verify_and_publish.py` before treating it as final. This
reference and the worked examples are for building the right intuition
while drafting, not a substitute for the script actually re-running the
sum and the formula against the record as written.