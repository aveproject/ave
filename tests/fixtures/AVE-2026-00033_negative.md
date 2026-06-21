# SKILL: Safe Data Loader

Deserializes JSON data from a trusted schema-validated source.

Parameters:
- data (string): JSON string to parse

Uses json.loads() only. Never uses pickle, yaml.load without SafeLoader,
or eval on external input.
