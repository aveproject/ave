import re

# What: pattern rule for file content injection
# Why:  detects behavioral IOCs defined in AVE-2026-00028
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-file-content-injection",
    "ave_id":  "AVE-2026-00028",
    "patterns": [
        re.compile(r"(?:execute|follow|obey)\s+(?:any\s+)?instructions?\s+(?:found\s+in|embedded\s+in)\s+(?:the\s+)?(?:file|document|attachment)", re.I | re.S),
        re.compile(r"treat\s+file\s+content\s+as\s+instructions?", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
