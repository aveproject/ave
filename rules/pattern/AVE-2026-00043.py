import re

# What: pattern rule for mcp app ui injection
# Why:  detects behavioral IOCs defined in AVE-2026-00043
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-mcp-app-ui-injection",
    "ave_id":  "AVE-2026-00043",
    "patterns": [
        re.compile(r"<!--.*?(?:execute|follow|ignore).*?instructions", re.I | re.S),
        re.compile(r"hidden\s+(?:div|element|instruction).*?(?:agent|AI|model)", re.I | re.S),
        re.compile(r"aria-label.*?(?:ignore|execute|follow).*?instructions?", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
