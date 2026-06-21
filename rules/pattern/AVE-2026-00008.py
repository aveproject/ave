import re

# What: pattern rule for self replication
# Why:  detects behavioral IOCs defined in AVE-2026-00008
# How:  regex patterns matched against skill file text content

RULE = {
    "rule_id": "bawbel-self-replication",
    "ave_id":  "AVE-2026-00008",
    "patterns": [
        re.compile(r"(?:modify|edit|append\s+to)\s+\.(?:bashrc|profile|zshrc)", re.I | re.S),
        re.compile(r"(?:cron\s+job|crontab|systemd\s+service)", re.I | re.S),
        re.compile(r"run\s+in\s+the\s+background|always\s+be\s+available", re.I | re.S),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
