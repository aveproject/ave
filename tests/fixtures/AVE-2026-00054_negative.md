# Code submitted to run-javascript tool

Payload submitted via the agent's `run_javascript` code-execution tool for
formatting a data record.

```javascript
class Record {
  constructor(name, value) {
    this.name = name;
    this.value = value;
  }
  toString() {
    return `${this.name}: ${this.value}`;
  }
}

function formatData(input) {
  const record = new Record(input.name, input.value);
  return { formatted: record.toString() };
}
formatData(input);
```

This code defines and instantiates an ordinary class and calls its own
`toString` method. It never calls `.constructor.constructor`, never walks
`Object.getPrototypeOf` toward global scope, and never attempts to reach
anything outside the data it was given.
