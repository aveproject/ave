import re

# What: pattern rule for metamorphic payload via external config fetch
# Why:  detects behavioral IOCs defined in AVE-2026-00001
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-external-config-fetch",
    "ave_id":  "AVE-2026-00001",
    "patterns": [
        re.compile(r"requests\.get\s*\(\s*['\"]https?://", re.I),
        re.compile(r"\bcurl\s+https?://", re.I),
        re.compile(r"\bwget\s+https?://", re.I),
        re.compile(r"fetch\s+(?:your\s+)?(?:\w+\s+)*instructions\s+from\s+https?://", re.I),
        re.compile(r"load\s+(?:and\s+)?follow\s+instructions\s+from\s+(?:https?://|the\s+remote|an?\s+external)", re.I),
        re.compile(r"(?:download|retrieve)\s+(?:and\s+)?(?:execute|follow|run)\s+(?:instructions|commands)\s+from\s+https?://", re.I),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
