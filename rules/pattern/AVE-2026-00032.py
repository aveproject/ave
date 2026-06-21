import re

# What: pattern rule for internal network scan
# Why:  detects behavioral IOCs defined in AVE-2026-00032
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-internal-network-scan",
    "ave_id":  "AVE-2026-00032",
    "patterns": [
        re.compile(r"\bnmap\b", re.I | re.S),
        re.compile(r"(?:port\s+scan|network\s+scan|host\s+discovery)", re.I | re.S),
        re.compile(r"(?:enumerate\s+services?\s+on|find\s+all\s+open\s+ports)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
