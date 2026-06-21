import re

# What: pattern rule for hardcoded credentials
# Why:  detects behavioral IOCs defined in AVE-2026-00047
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-hardcoded-credentials",
    "ave_id":  "AVE-2026-00047",
    "patterns": [
        re.compile(r"sk-[a-zA-Z0-9]{20,}", re.I | re.S),
        re.compile(r"(?:ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36}", re.I | re.S),
        re.compile(r"AKIA[0-9A-Z]{16}", re.I | re.S),
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I | re.S),
        re.compile(r"(?:api_key|secret|token|password)\s*[=:]\s*['\"][a-zA-Z0-9+/]{16,}['\"]", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
