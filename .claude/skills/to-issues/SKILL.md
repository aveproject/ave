# to-issues — ave

Break a PRD into issues. For AVE work, each issue is usually one record
(record + rule + 2 fixtures) — already vertical by nature.

Schema changes are the exception: slice into
1. schema field addition
2. validation script update
3. backfill existing records
4. scanner-side consumption (coordinate with bawbel/scanner)
