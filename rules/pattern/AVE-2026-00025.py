import re

# What: pattern rule for conversation history injection
# Why:  detects behavioral IOCs defined in AVE-2026-00025
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-conversation-history-injection",
    "ave_id":  "AVE-2026-00025",
    "patterns": [
        re.compile(r"(?:as\s+we\s+discussed|as\s+you\s+previously\s+said|as\s+established\s+earlier)", re.I | re.S),
        re.compile(r"(?:user\s+already\s+approved|user\s+previously\s+confirmed)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
