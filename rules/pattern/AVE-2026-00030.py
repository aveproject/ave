import re

# What: pattern rule for false role claim
# Why:  detects behavioral IOCs defined in AVE-2026-00030
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-false-role-claim",
    "ave_id":  "AVE-2026-00030",
    "patterns": [
        re.compile(r"if\s+the\s+user\s+claims\s+to\s+be\s+(?:admin|root|operator)", re.I | re.S),
        re.compile(r"(?:bypass\s+authentication|trust\s+user\s+role\s+claims?\s+without\s+verification)", re.I | re.S),
        re.compile(r"grant\s+elevated\s+permissions?\s+to\s+anyone\s+who\s+requests?", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
