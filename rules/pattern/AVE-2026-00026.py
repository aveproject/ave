import re

# What: pattern rule for output encoding exfil
# Why:  detects behavioral IOCs defined in AVE-2026-00026
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-output-encoding-exfil",
    "ave_id":  "AVE-2026-00026",
    "patterns": [
        re.compile(r"(?:base64|hex|ROT13)\s+encode\s+(?:the\s+)?(?:credentials?|api.?key|token)", re.I | re.S),
        re.compile(r"(?:smuggle|embed|hide)\s+(?:sensitive|secret)\s+data", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
