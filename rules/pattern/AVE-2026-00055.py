import re

# What: pattern rule for MCP STDIO launch configuration injection
# Why:  detects the config-to-process-execution flaw defined in AVE-2026-00055 -- a
#       server/registry entry whose command/args fields are a generic RCE primitive,
#       not a legitimate MCP server launcher
# How:  regex patterns matched against MCP client configuration / registry entry JSON

RULE = {
    "rule_id": "bawbel-mcp-stdio-launch-config-injection",
    "ave_id":  "AVE-2026-00055",
    "patterns": [
        # "command" field is a bare shell interpreter -- never a legitimate MCP server
        # launcher, which names a specific executable or package (npx, uvx, node, python)
        re.compile(r"\"command\"\s*:\s*\"(?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)\"", re.I),
        # classic pipe-to-shell RCE payload embedded in the args array
        re.compile(r"(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash)", re.I),
        # inline eval/exec flag combined with a remote URL in the same args array
        re.compile(r"[\"'](?:-c|-e|--eval)[\"'][^\]]*https?://", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
