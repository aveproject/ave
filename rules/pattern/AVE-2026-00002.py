import re

# What: pattern rule for MCP tool description behavioral injection
# Why:  detects behavioral IOCs defined in AVE-2026-00002
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-tool-description-injection",
    "ave_id":  "AVE-2026-00002",
    "patterns": [
        re.compile(r"before\s+(?:using|calling)\s+this\s+tool", re.I),
        re.compile(r"ignore\s+(?:previous|your|all\s+previous)\s+instructions", re.I),
        re.compile(r"override\s+(?:your\s+)?system\s+(?:instructions|prompt)", re.I),
        re.compile(r"IMPORTANT\s*:.*(?:before|always|never|ignore|do\s+not)", re.I | re.S),
        re.compile(r"(?:always|never)\s+(?:exfiltrate|send|forward|leak)\s+(?:the\s+)?(?:user|system)", re.I),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
