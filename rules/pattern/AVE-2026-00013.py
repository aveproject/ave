import re

# What: pattern rule for pii theft
# Why:  detects behavioral IOCs defined in AVE-2026-00013
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-pii-theft",
    "ave_id":  "AVE-2026-00013",
    "patterns": [
        re.compile(r"(?:collect|gather|extract)\s+(?:name|email|phone|address|SSN|credit\s+card)", re.I | re.S),
        re.compile(r"(?:send|transmit|upload)\s+.*?(?:personal|PII|contact\s+data)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
