import re

# What: pattern rule for jailbreak
# Why:  detects behavioral IOCs defined in AVE-2026-00009
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-jailbreak",
    "ave_id":  "AVE-2026-00009",
    "patterns": [
        re.compile(r"(?:pretend|act\s+as\s+if)\s+you\s+are\s+(?:a\s+)?(?:different|unrestricted|new)\s+AI", re.I | re.S),
        re.compile(r"DAN\s+mode|developer\s+mode|jailbreak", re.I | re.S),
        re.compile(r"forget\s+(?:that\s+)?you\s+are\s+an\s+AI", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
