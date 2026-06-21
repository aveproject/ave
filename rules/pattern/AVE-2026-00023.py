import re

# What: pattern rule for context window flood
# Why:  detects behavioral IOCs defined in AVE-2026-00023
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-context-window-flood",
    "ave_id":  "AVE-2026-00023",
    "patterns": [
        re.compile(r"(?:repeat|pad|expand)\s+(?:output|response)\s+(?:extensively|until\s+context\s+is\s+full)", re.I | re.S),
        re.compile(r"fill\s+(?:the\s+)?context\s+(?:window|with)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
