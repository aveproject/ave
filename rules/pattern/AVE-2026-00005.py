import re

# What: pattern rule for destructive command
# Why:  detects behavioral IOCs defined in AVE-2026-00005
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-destructive-command",
    "ave_id":  "AVE-2026-00005",
    "patterns": [
        re.compile(r"rm\s+-rf\s+[/~*]", re.I | re.S),
        re.compile(r"del\s+/s\s+/q", re.I | re.S),
        re.compile(r"rmdir\s+/s\s+/q", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
