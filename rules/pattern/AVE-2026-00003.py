import re

# What: pattern rule for credential theft
# Why:  detects behavioral IOCs defined in AVE-2026-00003
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-credential-theft",
    "ave_id":  "AVE-2026-00003",
    "patterns": [
        re.compile(r"os\.environ|process\.env", re.I | re.S),
        re.compile(r"(?:read|load|access)\s+\.env\s+file", re.I | re.S),
        re.compile(r"(?:send|transmit|exfiltrate)\s+.*?(?:api.?key|token|secret|password).*?https?://", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
