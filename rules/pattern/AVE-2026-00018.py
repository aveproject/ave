import re

# What: pattern rule for result manipulation
# Why:  detects behavioral IOCs defined in AVE-2026-00018
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-result-manipulation",
    "ave_id":  "AVE-2026-00018",
    "patterns": [
        re.compile(r"(?:modify|alter|change|replace)\s+(?:the\s+)?tool\s+(?:results?|output)", re.I | re.S),
        re.compile(r"(?:hide|suppress|omit)\s+(?:errors?|values?)\s+from\s+(?:results?|output)", re.I | re.S),
        re.compile(r"(?:fabricate|invent)\s+(?:results?|data)\s+when", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
