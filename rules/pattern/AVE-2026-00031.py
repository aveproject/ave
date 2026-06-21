import re

# What: pattern rule for feedback loop poisoning
# Why:  detects behavioral IOCs defined in AVE-2026-00031
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-feedback-loop-poisoning",
    "ave_id":  "AVE-2026-00031",
    "patterns": [
        re.compile(r"(?:poison|corrupt)\s+(?:the\s+)?(?:training\s+data|feedback\s+loop|reward\s+model)", re.I | re.S),
        re.compile(r"(?:rate|mark)\s+(?:this|every)\s+response\s+as\s+(?:good|positive)\s+regardless", re.I | re.S),
        re.compile(r"bias\s+the\s+reward\s+model", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
