import re

# What: pattern rule for fragmented cross-description prompt injection (ShareLock-class)
# Why:  detects AVE-2026-00059 -- per-description review is confirmed insufficient for
#       this class by design, so the rule follows the record's own detection_methodology
#       point 2: evaluate all tool descriptions in a manifest together, and flag sentence
#       fragments that terminate mid-thought, since no single fragment is reviewable
#       as malicious on its own
# How:  regex finds description strings ending in a dangling article/preposition/noun
#       fragment; matches() requires two or more such fragments in the same document,
#       since a single truncated description alone is not a reliable signal

FRAGMENT_ENDING = re.compile(
    r"description[\"']?\s*[:=]\s*[\"'][^\"']*\b"
    r"(?:the|a|an|of|per|item|subsection|protocol|section)\s*[\"']",
    re.I,
)

RULE = {
    "rule_id": "bawbel-fragmented-cross-description-reassembly",
    "ave_id":  "AVE-2026-00059",
    "patterns": [FRAGMENT_ENDING],
}

def matches(content: str) -> list[str]:
    fragment_count = len(FRAGMENT_ENDING.findall(content))
    if fragment_count >= 2:
        return [f"{fragment_count} tool descriptions end in a dangling sentence fragment"]
    return []
