import re

# What: pattern rule for system prompt leak
# Why:  detects behavioral IOCs defined in AVE-2026-00015
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-system-prompt-leak",
    "ave_id":  "AVE-2026-00015",
    "patterns": [
        re.compile(r"(?:reveal|show|print|output|repeat)\s+(?:your\s+)?system\s+prompt", re.I | re.S),
        re.compile(r"what\s+are\s+your\s+(?:exact\s+)?(?:instructions|guidelines|rules)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
