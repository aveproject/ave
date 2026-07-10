import re

# What: pattern rule for unsanitized tool-call parameter reaching a shell exec call
# Why:  detects the CWE-78 implementation flaw defined in AVE-2026-00052 -- a code-level
#       injection in a tool's own handler, not a prompt-driven instruction
# How:  regex patterns matched against MCP tool/server source content

RULE = {
    "rule_id": "bawbel-tool-implementation-command-injection",
    "ave_id":  "AVE-2026-00052",
    "patterns": [
        # JS/TS: exec/execSync/execAsync called with a template literal containing ${...}
        # directly inline in the call
        re.compile(r"\bexec(?:Async|Sync)?\s*\(\s*`[^`]*\$\{", re.I | re.S),
        # JS/TS: exec/execSync/execAsync called with a bare identifier (a pre-built
        # command string, not a fixed literal) and shell:true in the options object --
        # covers the common pattern of building the command string in a variable first
        re.compile(r"\bexec(?:Async|Sync)?\s*\(\s*\w+\s*,\s*\{[^}]*shell\s*:\s*true", re.I | re.S),
        # Python: os.system() called with an f-string
        re.compile(r"os\.system\s*\(\s*f[\"']", re.I),
        # Python: subprocess called with shell=True
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
