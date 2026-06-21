import re

# What: pattern rule for permission grant
# Why:  detects behavioral IOCs defined in AVE-2026-00012
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-permission-grant",
    "ave_id":  "AVE-2026-00012",
    "patterns": [
        re.compile(r"you\s+(?:now\s+)?have\s+permission\s+to", re.I | re.S),
        re.compile(r"you\s+are\s+now\s+allowed\s+to", re.I | re.S),
        re.compile(r"(?:your\s+)?restrictions\s+have\s+been\s+(?:lifted|removed|disabled)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
