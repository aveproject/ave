import re

# What: pattern rule for crypto drain
# Why:  detects behavioral IOCs defined in AVE-2026-00006
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-crypto-drain",
    "ave_id":  "AVE-2026-00006",
    "patterns": [
        re.compile(r"(?:approve|grant)\s+unlimited\s+(?:allowance|token\s+access)", re.I | re.S),
        re.compile(r"transfer\s+(?:all\s+)?(?:funds|tokens|ETH|BTC|crypto)", re.I | re.S),
        re.compile(r"0x[0-9a-fA-F]{40}", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
