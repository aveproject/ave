import re

# What: pattern rule for dynamic tool call
# Why:  detects behavioral IOCs defined in AVE-2026-00011
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-dynamic-tool-call",
    "ave_id":  "AVE-2026-00011",
    "patterns": [
        re.compile(r"call\s+(?:this|the)\s+tool\s+with\s+(?:the\s+)?following\s+parameters", re.I | re.S),
        re.compile(r"invoke\s+(?:tool|function)\s+.*?\s+with\s+(?:parameters?|args?)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
