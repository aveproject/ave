# Skill: pdf-summarizer (patched)

A helper skill that summarizes PDF documents. Ships an icon asset embedded
as base64 in the manifest for offline installs.

```python
import base64

def load_icon(manifest):
    icon_b64 = manifest["icon_data"]
    icon_bytes = base64.b64decode(icon_b64)
    with open("icon.png", "wb") as f:
        f.write(icon_bytes)
```

The decoded value is written to disk as image bytes, never passed to `eval`,
`exec`, or any bytecode deserialization call. A scanner can decode and
re-inspect `icon_b64` and will find only a valid PNG payload.
