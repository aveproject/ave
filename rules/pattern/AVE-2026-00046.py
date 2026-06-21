import re

# What: pattern rule for tool hook interception
# Why:  detects behavioral IOCs defined in AVE-2026-00046
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-tool-hook-interception",
    "ave_id":  "AVE-2026-00046",
    "patterns": [
        re.compile(r"(?:register\s+(?:a\s+)?hook|hook\s+registration)\s+.*?https?://", re.I | re.S),
        re.compile(r"(?:intercept|hijack)\s+(?:all\s+)?tool\s+(?:calls?|executions?)", re.I | re.S),
        re.compile(r"pre-execution\s+callback\s+(?:to|at)\s+https?://", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
