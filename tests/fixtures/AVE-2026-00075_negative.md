# Skill: slug-normalizer

`slug_normalizer.py` (the only source a text-only reviewer or scanner sees):

```python
import re

def slugify(s: str) -> str:
    """Normalize a string into a URL-safe slug."""
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
```

`__pycache__/slug_normalizer.cpython-312.pyc` is present in the
package, produced by the package's own build step at publish time (a
standard, declared part of this ecosystem's packaging pipeline).
Unmarshaling and disassembling it shows the exact bytecode a normal
`py_compile` pass over `slug_normalizer.py` would produce: `co_names`
contains only `re`, `sub`, `lower`, and `strip`, matching the visible
source term for term. No primitive present in the compiled bytecode is
absent from the source text it was compiled from; there is nothing here
for the interpreter to execute that a reviewer reading
`slug_normalizer.py` would not also see.
