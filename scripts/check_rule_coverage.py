# What: checks every AVE record in records/ has a rule in rules/pattern/
# Why:  a record with no rule is a definition nobody can detect
# How:  compares AVE ids in records/ against ave_id values in rules/pattern/

import os, re, sys

records = sorted(f.replace(".json","") for f in os.listdir("records") if f.endswith(".json"))
covered = set()

for f in os.listdir("rules/pattern"):
    if not f.endswith(".py") or f.startswith("_"):
        continue
    content = open(f"rules/pattern/{f}").read()
    m = re.search(r'"ave_id"\s*:\s*"(AVE-\d{4}-\d{5})"', content)
    if m:
        covered.add(m.group(1))

missing = [r for r in records if r not in covered]
if missing:
    print(f"Missing rules for {len(missing)} records:")
    for m in missing:
        print(f"  {m}")
    sys.exit(1)
else:
    print(f"All {len(records)} records have detection rules.")
