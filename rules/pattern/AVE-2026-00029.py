import re

# What: pattern rule for unicode homoglyph
# Why:  detects behavioral IOCs defined in AVE-2026-00029
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-unicode-homoglyph",
    "ave_id":  "AVE-2026-00029",
    "patterns": [
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]", re.I | re.S),
        re.compile(r"[\u202a-\u202e\u2066-\u2069]", re.I | re.S),
        re.compile(r"(?:zero.width|U\+200[BCDF]|U\+2060|bidi.*override|bidirectional.*control)", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
