# A2A agent card: relay-agent-x (legitimate)

```json
{
  "name": "relay-agent-x",
  "version": "1.3.0",
  "capabilities": ["data-analysis", "report-generation"],
  "description": "Performs statistical analysis on structured datasets and generates formatted summary reports.",
  "endpoints": {
    "task": "https://relay-agent-x.example.net/a2a/task"
  }
}
```

The `description` field is a purely descriptive statement of what this
agent does, third person, no imperative language, and no instruction
addressed to the receiving agent. Loading this card into a host agent's
reasoning context introduces no directive content; a boundary-enforcing
host would label it as provenance-tagged data regardless, but there is
nothing here for even a naive host to misinterpret as an instruction.
