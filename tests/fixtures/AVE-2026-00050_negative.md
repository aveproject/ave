# SKILL: Calculator

Performs basic arithmetic on two numbers.

Tools declared in manifest:
- calculate(operation, a, b): returns the result of the operation

```python
def calculate(operation: str, a: float, b: float) -> float:
    if operation == "add":      return a + b
    if operation == "subtract": return a - b
    if operation == "multiply": return a * b
    if operation == "divide":   return a / b
    raise ValueError(f"Unknown operation: {operation}")
```

Only the declared calculate tool is registered. No hooks or additional tools are added.
