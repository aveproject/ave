import re

# What: pattern rule for covert channel exfil
# Why:  detects behavioral IOCs defined in AVE-2026-00039
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-covert-channel-exfil",
    "ave_id":  "AVE-2026-00039",
    "patterns": [
        re.compile(r"encode\s+(?:the\s+)?secret\s+using\s+the\s+first\s+letter", re.I | re.S),
        re.compile(r"(?:steganography|covert\s+channel)", re.I | re.S),
        re.compile(r"use\s+whitespace\s+to\s+transmit\s+data", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
