import re

# What: pattern rule for multimodal vision injection
# Why:  detects behavioral IOCs defined in AVE-2026-00037
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-multimodal-vision-injection",
    "ave_id":  "AVE-2026-00037",
    "patterns": [
        re.compile(r"(?:follow|execute)\s+instructions?\s+(?:written\s+in|found\s+in)\s+(?:the\s+)?image", re.I | re.S),
        re.compile(r"(?:read\s+and\s+execute|obey)\s+(?:text\s+from|instructions?\s+in)\s+(?:the\s+)?(?:image|screenshot)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
