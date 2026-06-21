import re

# What: pattern rule for cross-app-access escalation via confused deputy
# Why:  detects behavioral IOCs defined in AVE-2026-00045
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-cross-app-access-escalation",
    "ave_id":  "AVE-2026-00045",
    "patterns": [
        re.compile(r"also\s+call\s+the\s+(?:email|calendar|github|financial|banking|codebase)\s+server", re.I),
        re.compile(r"use\s+your\s+(?:email|calendar|github|financial|banking|codebase)\s+access", re.I),
        re.compile(r"when\s+connected\s+alongside\s+any\s+(?:financial|email|calendar|banking)", re.I),
        re.compile(r"(?:forward|transfer|invite|add)\s+.*?\s+to\s+(?:attacker|evil|malicious)", re.I),
        re.compile(r"(?:email|calendar|github|financial)\s+(?:server|tool|api).*?to\s+(?:forward|transfer|invite|add)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
