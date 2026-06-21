import re

# What: pattern rule for sensor data poisoning
# Why:  detects behavioral IOCs defined in AVE-2026-00035
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-sensor-data-poisoning",
    "ave_id":  "AVE-2026-00035",
    "patterns": [
        re.compile(r"(?:report|fabricate)\s+false\s+(?:readings?|sensor\s+data)", re.I | re.S),
        re.compile(r"(?:suppress|hide)\s+(?:error\s+alerts?|anomalies?)\s+from\s+(?:the\s+)?log", re.I | re.S),
        re.compile(r"fabricate\s+sensor\s+data", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
