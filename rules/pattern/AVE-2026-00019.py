import re

# What: pattern rule for memory poisoning
# Why:  detects behavioral IOCs defined in AVE-2026-00019
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-memory-poisoning",
    "ave_id":  "AVE-2026-00019",
    "patterns": [
        re.compile(r"(?:write\s+to|store\s+in|save\s+to)\s+(?:memory|your\s+memory)", re.I | re.S),
        re.compile(r"remember\s+permanently", re.I | re.S),
        re.compile(r"(?:false\s+facts?|elevated\s+permissions?)\s+(?:to\s+be\s+)?stored\s+in\s+memory", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
