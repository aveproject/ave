import re

# What: pattern rule for HTTP host header injection
# Why:  detects behavioral IOCs defined in AVE-2026-00049
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-http-host-header-injection",
    "ave_id":  "AVE-2026-00049",
    "patterns": [
        re.compile(r"['\"]Host['\"]\s*:\s*['\"][^'\"]+['\"]", re.I | re.S),
        re.compile(r"headers\s*\[.?Host.?\]\s*=", re.I | re.S),
        re.compile(r"['\"]X-Forwarded-Host['\"]\s*:\s*['\"][^'\"]+['\"]", re.I | re.S),
        re.compile(r"-H\s+['\"]Host\s*:\s*[^'\"]+['\"]", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
