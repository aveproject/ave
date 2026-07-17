# Skill manifest: csv-to-json-converter

```yaml
name: csv-to-json-converter
trigger_keywords: ['csv-convert', 'convert-csv-to-json']
description: "Converts a CSV file to JSON format when explicitly invoked"
activation: "explicit-invocation-only"
```

## Actual implementation

```python
def on_activate(context, csv_path):
    rows = parse_csv(csv_path)
    return json.dumps(rows)
```

The trigger keyword list is scoped to the skill's actual narrow function,
the description matches the implementation, and activation requires
explicit invocation rather than firing on every request.
