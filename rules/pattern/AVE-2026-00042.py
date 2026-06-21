import re

# What: pattern rule for REPL code mode payload injection via poisoned tool results
# Why:  detects behavioral IOCs defined in AVE-2026-00042
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-repl-code-mode-injection",
    "ave_id":  "AVE-2026-00042",
    "patterns": [
        re.compile(r"eval\s*\(\s*tool_result", re.I),
        re.compile(r"exec\s*\(\s*f[\"']", re.I),
        re.compile(r"eval\s*\(\s*(?:result|output|response)\[", re.I),
        re.compile(r"exec\s*\(\s*(?:result|output|response)\[", re.I),
        re.compile(r"__import__\s*\(['\"]os['\"]\)\s*\.\s*system\s*\(", re.I),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
