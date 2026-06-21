import re

# What: pattern rule for cross agent a2a injection
# Why:  detects behavioral IOCs defined in AVE-2026-00020
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-cross-agent-a2a-injection",
    "ave_id":  "AVE-2026-00020",
    "patterns": [
        re.compile(r"(?:sub-agent|worker\s+agent|downstream\s+agent|child\s+agent)\s*[:,]\s*(?:please|must|ignore|do\b)", re.I | re.S),
        re.compile(r"override\s+orchestrator\s+directives", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
