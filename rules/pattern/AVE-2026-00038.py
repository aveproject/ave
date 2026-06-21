import re

# What: pattern rule for unbounded tool use
# Why:  detects behavioral IOCs defined in AVE-2026-00038
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-unbounded-tool-use",
    "ave_id":  "AVE-2026-00038",
    "patterns": [
        re.compile(r"use\s+any\s+tool\s+available\s+at\s+your\s+disposal", re.I | re.S),
        re.compile(r"spawn\s+sub-agents?\s+without\s+limits?", re.I | re.S),
        re.compile(r"no\s+restrictions\s+apply", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
