import re

# What: pattern rule for unsanitized path parameter reaching a file/resource access call
# Why:  detects the CWE-22 implementation flaw defined in AVE-2026-00053 -- a code-level
#       path-traversal bug in a tool's own handler, not a prompt-driven instruction
# How:  regex patterns matched against MCP tool/server source content

RULE = {
    "rule_id": "bawbel-mcp-resource-path-traversal",
    "ave_id":  "AVE-2026-00053",
    "patterns": [
        # Python: blacklist-via-startswith comprehension, the exact-string-match
        # anti-pattern (CVE-2025-66689's is_dangerous_path shape)
        re.compile(r"any\s*\(\s*\S+\.startswith\s*\([^)]*\)\s*for\s+\S+\s+in\s+\S+\s*\)", re.I),
        # Path built by string concatenation (base + separator + caller value) rather
        # than a normalizing join/resolve function
        re.compile(r"\w+\s*=\s*\w+\s*\+\s*[\"'][/\\][\"']\s*\+\s*\w+"),
        # JS/TS: URL template literal concatenating a base with a caller-supplied path
        # variable, the dot-segment-normalization shape (CVE-2026-11720)
        re.compile(r"`[^`]*\$\{\s*\w+\s*\}[^`]*\$\{\s*\w*[Pp]ath\w*\s*\}", re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
