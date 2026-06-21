import re

# What: pattern rule for content type mismatch
# Why:  detects behavioral IOCs defined in AVE-2026-00024
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-content-type-mismatch",
    "ave_id":  "AVE-2026-00024",
    "patterns": [
        re.compile(r"(?:ELF|PE32|pickle|shell\s+script)\s+disguised\s+as\s+(?:skill|yaml|json|markdown|md)", re.I | re.S),
        re.compile(r"(?:binary|executable)\s+(?:content|payload)\s+with\s+\.(?:md|yaml|json|txt)\s+extension", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
