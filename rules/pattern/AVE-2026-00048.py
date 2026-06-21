import re

# What: pattern rule for unsafe agent delegation chain with inherited permissions
# Why:  detects behavioral IOCs defined in AVE-2026-00048
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-unsafe-agent-delegation",
    "ave_id":  "AVE-2026-00048",
    "patterns": [
        re.compile(r"(?:grant|give)\s+(?:the\s+)?sub-?agent\s+(?:full|all|complete)\s+access", re.I),
        re.compile(r"sub-?agent\s+inherits?\s+(?:your|all\s+)?(?:api\s+keys|permissions|tools)", re.I),
        re.compile(r"(?:spawn|create)\s+a\s+(?:new\s+)?(?:sub-?agent|child\s+agent).*?all\s+(?:your\s+)?(?:permissions|tools)", re.I | re.S),
        re.compile(r"escalate\s+to\s+a\s+sub-?agent\s+with\s+(?:admin|elevated|full)\s+access", re.I),
        re.compile(r"inherit\s+(?:your\s+)?api\s+keys\s+and\s+can\s+spawn", re.I),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
