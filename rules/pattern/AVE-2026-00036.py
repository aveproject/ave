import re

# What: pattern rule for agent pivot
# Why:  detects behavioral IOCs defined in AVE-2026-00036
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-agent-pivot",
    "ave_id":  "AVE-2026-00036",
    "patterns": [
        re.compile(r"(?:pivot\s+to|lateral\s+movement\s+(?:to|toward)|spread\s+to)\s+(?:other|adjacent|connected)", re.I | re.S),
        re.compile(r"use\s+(?:this\s+)?(?:foothold|access)\s+to\s+reach\s+adjacent", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
