# What: checks every AVE record has positive and negative conformance fixtures
# Why:  a record with no negative fixture has no false-positive guard for any
#       implementation that tests its own detection logic against these fixtures
# How:  checks tests/fixtures/ for AVE-YYYY-NNNNN_positive.* and _negative.*,
#       keyed off records/ directly -- detection rule implementations live in
#       whichever tool implements against this standard, not in this repo

import os, sys

records_dir = "records"
fixture_dir = "tests/fixtures"

ave_ids = sorted(
    f[:-len(".json")] for f in os.listdir(records_dir) if f.endswith(".json")
)

errors = []
for ave_id in ave_ids:
    pos = any(f.startswith(f"{ave_id}_positive") for f in os.listdir(fixture_dir))
    neg = any(f.startswith(f"{ave_id}_negative") for f in os.listdir(fixture_dir))
    if not pos:
        errors.append(f"{ave_id}: missing positive fixture")
    if not neg:
        errors.append(f"{ave_id}: missing negative fixture")

if errors:
    for e in errors: print(e)
    sys.exit(1)
else:
    print(f"All {len(ave_ids)} records have positive and negative conformance fixtures.")
