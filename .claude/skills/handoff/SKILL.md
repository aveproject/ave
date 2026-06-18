# handoff — ave

End: docs/agents/handoffs/YYYY-MM-DD-HHMM.md
Start: read most recent, run python scripts/validate_records.py.

## End format

# Handoff — date

## Completed
- records/AVE-2026-00049.json — header injection (BadHost) record added
- rules/semgrep/ave-2026-00049.yaml — detection rule
- tests/fixtures/AVE-2026-00049_positive.md + _negative.md

## Status
python scripts/validate_records.py → all valid
pytest tests/ -q → N passed

## Next
AVE-2026-00050: database data-path exposure (Mads Hansen suggestion)
First: grill the behavioral_fingerprint.

Note: docs/agents/handoffs/ gitignored.
