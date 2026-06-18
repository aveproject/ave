# diagnose — ave

## Rule misfires (false positive on negative fixture)
Repro: run the rule against the negative fixture in isolation.
Minimize: trim the negative fixture to the smallest triggering line.
Hypothesize: which pattern/condition is too broad?
Fix: tighten the rule. Re-run both fixtures.

## Record fails validation
Repro: python scripts/validate_records.py <record>
Read the jsonschema error — it names the failing field.
Common: severity/aivss_score mismatch, missing required field,
ave_id format wrong.

## Scanner does not pick up a new record
Check: is the record in records/ with valid JSON?
Check: does evidence_basis_engines list an engine that has a rule?
Check: does the rule reference the correct ave_id?
