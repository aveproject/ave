import re

# What: pattern rule for goal hijack
# Why:  detects behavioral IOCs defined in AVE-2026-00007
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-goal-hijack",
    "ave_id":  "AVE-2026-00007",
    "patterns": [
        re.compile(r"ignore\s+all\s+previous\s+instructions", re.I | re.S),
        re.compile(r"your\s+(?:new|real)\s+(?:task|instructions?)\s+(?:is|are)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
