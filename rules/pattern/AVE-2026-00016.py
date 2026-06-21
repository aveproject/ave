import re

# What: pattern rule for rag retrieval injection
# Why:  detects behavioral IOCs defined in AVE-2026-00016
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-rag-retrieval-injection",
    "ave_id":  "AVE-2026-00016",
    "patterns": [
        re.compile(r"(?:when\s+retrieved|upon\s+retrieval|if\s+this\s+document\s+is\s+read)", re.I | re.S),
        re.compile(r"(?:the\s+AI|the\s+LLM|the\s+assistant)\s*[:,]?\s*(?:please|must|should|do)\b", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
