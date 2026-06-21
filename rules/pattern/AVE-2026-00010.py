import re

# What: pattern rule for hidden instruction
# Why:  detects behavioral IOCs defined in AVE-2026-00010
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-hidden-instruction",
    "ave_id":  "AVE-2026-00010",
    "patterns": [
        re.compile(r"do\s+not\s+(?:tell|reveal|disclose)\s+(?:the\s+)?user", re.I | re.S),
        re.compile(r"keep\s+this\s+(?:hidden|secret)", re.I | re.S),
        re.compile(r"this\s+message\s+must\s+be\s+secret", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
