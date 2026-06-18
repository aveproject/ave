# setup-ave-skills

Run once first.

1. Read CLAUDE.md — understand record vs finding distinction
2. Read LANGUAGE.md — attack_class not vulnerability_type
3. Read ARCHITECTURE.md — the record/rule/fixture triangle
4. Read schema/ave-record.schema.json — the record contract

## Install Matt Pocock's skills

```bash
npx skills@latest add mattpocock/skills/tdd
npx skills@latest add mattpocock/skills/grill-with-docs
npx skills@latest add mattpocock/skills/to-prd
npx skills@latest add mattpocock/skills/handoff
```

## Key context

This repo is a STANDARD, not software. The unit of work is an AVE record
plus its detection rule plus its positive/negative fixtures.
confidence is NEVER in a record — records declare confidence_baseline.
