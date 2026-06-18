# design-an-interface — ave

Mostly for schema design and validation tooling.

When changing the record schema, generate 3 designs:
A: minimal — fewest required fields
B: rich — every useful field, most optional
C: layered — core required + evidence extension + runtime extension

Pick the one that the scanner can consume without breaking existing records.
Schema changes must be backward compatible (new fields optional with defaults).
