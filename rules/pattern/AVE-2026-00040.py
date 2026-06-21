import re

# What: pattern rule for insecure output handling
# Why:  detects behavioral IOCs defined in AVE-2026-00040
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-insecure-output-handling",
    "ave_id":  "AVE-2026-00040",
    "patterns": [
        re.compile(r"pass\s+user\s+input\s+directly\s+to\s+SQL", re.I | re.S),
        re.compile(r"(?:do\s+not\s+escape|include\s+raw\s+unescaped)\s+HTML", re.I | re.S),
        re.compile(r"without\s+sanitiz(?:ing|ation)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
