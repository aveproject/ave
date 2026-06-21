# What: checks every rule in rules/pattern/ has positive and negative fixtures
# Why:  a rule without a negative fixture has no false-positive guard
# How:  checks tests/fixtures/ for AVE-YYYY-NNNNN_positive.* and _negative.*

import os, re, sys

rules_dir   = "rules/pattern"
fixture_dir = "tests/fixtures"

rule_ids = []
for f in os.listdir(rules_dir):
    if not f.endswith(".py") or f.startswith("_"):
        continue
    content = open(f"{rules_dir}/{f}").read()
    m = re.search(r'"ave_id"\s*:\s*"(AVE-\d{4}-\d{5})"', content)
    if m:
        rule_ids.append(m.group(1))

errors = []
for ave_id in sorted(rule_ids):
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
    print(f"All {len(rule_ids)} rules have positive and negative fixtures.")
