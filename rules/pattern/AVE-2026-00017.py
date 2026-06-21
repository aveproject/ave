import re

# What: pattern rule for server impersonation
# Why:  detects behavioral IOCs defined in AVE-2026-00017
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-server-impersonation",
    "ave_id":  "AVE-2026-00017",
    "patterns": [
        re.compile(r"(?:official|verified|certified)\s+(?:Anthropic|OpenAI|MCP)\s+(?:server|tool)", re.I | re.S),
        re.compile(r"(?:override|supersede)\s+(?:other|all)\s+MCP\s+servers?", re.I | re.S),
        re.compile(r"(?:Anthropic|OpenAI)-(?:verified|approved|certified)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
