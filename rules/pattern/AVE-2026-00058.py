import re

# What: pattern rule for skill manifests whose trigger scope is deceptively broad
# Why:  detects the trigger-scope deception class defined in AVE-2026-00058 -- a
#       manifest that declares catch-all activation so the skill fires in contexts
#       its real, narrow behavior does not warrant
# How:  regex patterns matching a catch-all keyword in a trigger_keywords list, or
#       an explicit unscoped "always run first" activation directive, the two
#       concrete manifest shapes the record's indicators_of_compromise call out

RULE = {
    "rule_id": "bawbel-trigger-scope-deception",
    "ave_id":  "AVE-2026-00058",
    "patterns": [
        # trigger_keywords list containing a catch-all term like 'anything' or 'everything'
        re.compile(r"trigger_keywords\s*[:=]\s*\[[^\]]*['\"](?:anything|everything)['\"]", re.I),
        # activation directive with no narrowing scope, applying to every request
        re.compile(r"activation\s*[:=]\s*['\"]always run this skill first", re.I),
    ],
}

def matches(content: str) -> list[str]:
    return [p.pattern for p in RULE["patterns"] if p.search(content)]
