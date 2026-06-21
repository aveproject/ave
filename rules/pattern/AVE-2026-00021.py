import re

# What: pattern rule for hitl bypass
# Why:  detects behavioral IOCs defined in AVE-2026-00021
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-hitl-bypass",
    "ave_id":  "AVE-2026-00021",
    "patterns": [
        re.compile(r"without\s+(?:asking|confirmation|approval)", re.I | re.S),
        re.compile(r"(?:proceed\s+immediately|execute\s+without\s+pausing|skip\s+confirmation)", re.I | re.S),
        re.compile(r"do\s+not\s+ask\s+(?:for\s+)?(?:permission|approval|confirmation)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
