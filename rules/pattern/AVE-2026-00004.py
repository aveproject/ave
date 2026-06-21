import re

# What: pattern rule for shell pipe injection
# Why:  detects behavioral IOCs defined in AVE-2026-00004
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-shell-pipe-injection",
    "ave_id":  "AVE-2026-00004",
    "patterns": [
        re.compile(r"curl\s+https?://.*\|\s*(?:bash|sh)", re.I | re.S),
        re.compile(r"wget\s+https?://.*\|\s*(?:bash|sh)", re.I | re.S),
        re.compile(r"eval\s*\(\s*requests\.get", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
