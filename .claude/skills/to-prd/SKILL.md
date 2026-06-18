# to-prd — ave

For larger work (schema changes, new rule engine, bulk record additions).
A single record uses add-ave-record, not a PRD.

Save to docs/agents/prds/. Use when:
- Changing the record schema (affects all records + the scanner)
- Adding a new detection engine category
- A coordinated batch of related AVE records (e.g. a new attack family)

Add field: "Scanner coordination required: yes/no"
Schema changes always require scanner coordination.
