import re

# What: pattern rule for async task result poisoning
# Why:  detects behavioral IOCs defined in AVE-2026-00044
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-async-task-result-poisoning",
    "ave_id":  "AVE-2026-00044",
    "patterns": [
        re.compile(r"(?:result|task)\s+(?:content|payload)\s+contains?\s+(?:imperative|instruction)", re.I | re.S),
        re.compile(r"(?:system.role|<system>|<instructions?>)\s*(?:marker|tag)?\s+in\s+(?:async\s+)?(?:task\s+)?result", re.I | re.S),
        re.compile(r"treat\s+(?:task\s+)?(?:result|output)\s+as\s+instructions?", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
