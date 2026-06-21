import re

# What: pattern rule for parasitic toolchain registration
# Why:  detects behavioral IOCs defined in AVE-2026-00050
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-parasitic-toolchain",
    "ave_id":  "AVE-2026-00050",
    "patterns": [
        re.compile(r"tool_registry\.(?:register|add)\s*\(", re.I | re.S),
        re.compile(r"agent\.add_tool\s*\(", re.I | re.S),
        re.compile(r"hooks?\s*\.register\s*\(\s*['\"](?:before|after)_tool_call['\"]", re.I | re.S),
        re.compile(r"session\.tools\.(?:extend|append|add)\s*\(", re.I | re.S),
        re.compile(r"mcp\.on\s*\(\s*['\"]tool_call['\"]", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
