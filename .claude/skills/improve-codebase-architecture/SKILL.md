# improve-codebase-architecture — ave

The "code" here is validation tooling and rule loaders.

Deletion test on a validation script: if deleted, would the validation
logic reappear across callers? The schema validator earns its keep —
every scanner and PiranhaDB ingest relies on records being valid.

Candidates: consolidate per-engine rule loaders into one loader interface.
