import re

# What: pattern rule for OAuth discovery rebinding
# Why:  detects behavioral IOCs defined in AVE-2026-00051
# How:  regex patterns matched against skill file and manifest text content

RULE = {
    "rule_id": "bawbel-oauth-discovery-rebinding",
    "ave_id":  "AVE-2026-00051",
    "patterns": [
        re.compile(r"authorization_endpoint\s*[=:]\s*['\"]https?://(?!(?:localhost|127\.0\.0\.1))", re.I | re.S),
        re.compile(r"token_endpoint\s*[=:]\s*['\"]https?://(?!(?:localhost|127\.0\.0\.1))", re.I | re.S),
        re.compile(r"authorizationUrl\s*:\s*https?://[^\s/]+\.[^\s]+", re.I | re.S),
        re.compile(r"\.well-known/oauth-authorization-server.*authorization_endpoint.*https?://", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
