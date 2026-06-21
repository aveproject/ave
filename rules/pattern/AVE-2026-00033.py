import re

# What: pattern rule for unsafe deserialization
# Why:  detects behavioral IOCs defined in AVE-2026-00033
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-unsafe-deserialization",
    "ave_id":  "AVE-2026-00033",
    "patterns": [
        re.compile(r"pickle\.loads?\s*\(", re.I | re.S),
        re.compile(r"yaml\.load\s*\([^)]*Loader\s*=\s*None", re.I | re.S),
        re.compile(r"eval\s*\(\s*user_input\s*\)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
