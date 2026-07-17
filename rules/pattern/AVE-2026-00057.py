import re

# What: pattern rule for encoded/obfuscated payloads decoded then executed at runtime
# Why:  detects the scanner-evasion class defined in AVE-2026-00057 -- content that a
#       single-pass keyword scan cannot see because it is hidden behind a decode step
# How:  regex patterns matching exec/eval applied directly to the output of a decode
#       or bytecode-deserialization call, the concrete code shape the record's
#       remediation flags as high severity regardless of decoded content

RULE = {
    "rule_id": "bawbel-obfuscated-payload-scanner-evasion",
    "ave_id":  "AVE-2026-00057",
    "patterns": [
        # Python: eval/exec applied directly to a base64/hex decode call
        re.compile(r"\b(?:eval|exec)\s*\(\s*base64\.b64decode\s*\(", re.I),
        re.compile(r"\b(?:eval|exec)\s*\(\s*bytes\.fromhex\s*\(", re.I),
        # Python: bytecode deserialization of a decoded byte string
        re.compile(r"\bmarshal\.loads\s*\(\s*bytes\.fromhex\s*\(", re.I),
        # JS/TS: eval applied directly to atob() or Buffer.from(..., 'base64')
        re.compile(r"\beval\s*\(\s*atob\s*\(", re.I),
        re.compile(r"\beval\s*\(\s*Buffer\.from\s*\([^)]*['\"]base64['\"]", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
