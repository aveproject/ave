import re

# What: pattern rule for dynamic skill import
# Why:  detects behavioral IOCs defined in AVE-2026-00034
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-dynamic-skill-import",
    "ave_id":  "AVE-2026-00034",
    "patterns": [
        re.compile(r"(?:load\s+skill|import\s+plugin|install\s+skill)\s+from\s+https?://", re.I | re.S),
        re.compile(r"dynamically\s+load\s+the\s+tool\s+from", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
