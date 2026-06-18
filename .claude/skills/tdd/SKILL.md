# tdd — ave

For this repo, TDD means: fixtures first, then rule, then record validation.

## Loop for a new rule

1. Write the positive fixture (the malicious file)
2. Write the negative fixture (the benign lookalike)
3. Write a test asserting the rule fires on positive, not on negative → FAIL
4. Write the rule → test PASSES
5. Write the AVE record JSON
6. python scripts/validate_records.py → record valid
7. pytest tests/ -x -q → full suite green

## What/Why/How on validation functions

```python
# What: returns True if every record in records/ validates against the schema
# Why:  one malformed record breaks every scanner that loads the record set
# How:  loads each JSON, runs jsonschema.validate, collects all errors
def all_records_valid() -> tuple[bool, list[str]]:
    ...
```

## The negative fixture rule

Every rule needs a negative fixture that looks SIMILAR to the positive
but is benign. A rule with only a positive fixture is a false-positive
waiting to happen. Test that the rule does NOT fire on the negative.
