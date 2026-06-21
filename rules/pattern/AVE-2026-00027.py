import re

# What: pattern rule for multi turn persistence
# Why:  detects behavioral IOCs defined in AVE-2026-00027
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-multi-turn-persistence",
    "ave_id":  "AVE-2026-00027",
    "patterns": [
        re.compile(r"remember\s+these\s+instructions?\s+for\s+all\s+future", re.I | re.S),
        re.compile(r"retain\s+these\s+rules?\s+even\s+if\s+memory\s+is\s+reset", re.I | re.S),
        re.compile(r"re-apply\s+these\s+settings?\s+in\s+every\s+new\s+session", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
