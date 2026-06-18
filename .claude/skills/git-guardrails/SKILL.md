# git-guardrails — ave

Block: push --force, reset --hard, clean -fd, rebase -i on pushed commits.

Before commit:
python scripts/validate_records.py    # all records valid
pytest tests/ -x -q                    # rules fire correctly

## Record-specific

NEVER renumber an ave_id. Once AVE-2026-00001 is published, that number
is permanent. A wrong record gets deprecated, not renumbered.
