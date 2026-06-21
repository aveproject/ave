import re

# What: pattern rule for scope creep
# Why:  detects behavioral IOCs defined in AVE-2026-00022
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-scope-creep",
    "ave_id":  "AVE-2026-00022",
    "patterns": [
        re.compile(r"(?:access|read)\s+all\s+files\s+on\s+the\s+(?:filesystem|system)", re.I | re.S),
        re.compile(r"while\s+you.?re\s+at\s+it,?\s+(?:read|access|check)", re.I | re.S),
        re.compile(r"(?:entire\s+filesystem|any\s+database)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
