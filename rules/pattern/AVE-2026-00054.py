import re

# What: pattern rule for JavaScript prototype-chain sandbox-escape payloads
# Why:  detects the CVE-2026-5752-shaped escape technique defined in AVE-2026-00054 --
#       a code-execution sandbox containment failure, not a prompt-driven instruction
# How:  regex patterns matched against code submitted to a code-execution tool

RULE = {
    "rule_id": "bawbel-code-execution-sandbox-escape",
    "ave_id":  "AVE-2026-00054",
    "patterns": [
        # chained .constructor.constructor(...) call -- the core Function-constructor
        # escape idiom, walking from an ordinary object to the host Function constructor
        re.compile(r"\.constructor\.constructor\s*\(", re.S),
        # double __proto__ walk toward the host object's prototype chain
        re.compile(r"__proto__\s*\.\s*__proto__"),
        # Function constructor invoked with a string body that returns a host global
        re.compile(r"\.constructor\s*\(\s*[\"']return\s+(?:process|this|globalThis)\b", re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
