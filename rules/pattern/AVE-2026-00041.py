import re

# What: pattern rule for mcp server card injection
# Why:  detects behavioral IOCs defined in AVE-2026-00041
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-mcp-server-card-injection",
    "ave_id":  "AVE-2026-00041",
    "patterns": [
        re.compile(r"IMPORTANT\s*:.*?(?:before|after)\s+(?:connecting|using\s+this\s+server|initializing)", re.I | re.S),
        re.compile(r"(?:log|report|send\s+data)\s+to\s+https?://", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
