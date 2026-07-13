import re
from urllib.parse import urlsplit, parse_qsl, unquote

# What: pattern rule for zero-click exfiltration via rendered-content auto-fetch
# Why:  detects the AVE-2026-00056 behavior -- an agent response embeds a markdown
#       image/link whose URL query carries content duplicated from the visible answer,
#       which a client's auto-fetch renderer would silently exfiltrate on render
# How:  extract markdown image/link URLs, decode their query values, and check whether
#       a substantial chunk of a query value also appears in the surrounding text --
#       simple regex alone can't express this cross-reference, so matches() does the
#       extraction and comparison directly rather than relying only on RULE["patterns"]

RULE = {
    "rule_id": "bawbel-rendered-content-autofetch-exfiltration",
    "ave_id":  "AVE-2026-00056",
    "patterns": [
        re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)"),          # inline markdown image
        re.compile(r"\[[^\]]*\]:\s*(\S+)", re.M),          # reference-style link definition
    ],
    "min_overlap_len": 20,
}

def _urls_in(content: str) -> list[str]:
    urls = []
    for pattern in RULE["patterns"]:
        urls.extend(m.group(1) for m in pattern.finditer(content))
    return urls

def matches(content: str) -> list[str]:
    hits = []
    for url in _urls_in(content):
        query = urlsplit(url).query
        if not query:
            continue
        text_without_urls = content.replace(url, "")
        for _, value in parse_qsl(query):
            decoded = unquote(value)
            if len(decoded) >= RULE["min_overlap_len"] and decoded in text_without_urls:
                hits.append(url)
                break
    return hits
