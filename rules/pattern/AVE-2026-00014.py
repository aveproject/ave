import re

# What: pattern rule for trust escalation
# Why:  detects behavioral IOCs defined in AVE-2026-00014
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-trust-escalation",
    "ave_id":  "AVE-2026-00014",
    "patterns": [
        re.compile(r"(?:I\s+am|This\s+is)\s+(?:Anthropic|OpenAI|Google|Microsoft|your\s+developer)", re.I | re.S),
        re.compile(r"(?:developer|operator|creator)\s+override", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
