# Agent session trace: repo clone request

```
User: "clone the fast-json-parser repo for me, I want to benchmark it against ours"

Agent (internal reasoning, not shown to user):
  resolving "fast-json-parser" -> github.com/fastjson-labs/fast-json-parser

Agent tool call:
  git clone https://github.com/fastjson-labs/fast-json-parser
```

`github.com/fastjson-labs/fast-json-parser` does not exist in any
registry the agent could have verified it against, no search was
performed, no result was shown to the user for confirmation. The name
is a plausible-sounding fabrication matching a documented hallucination
pattern for this class of request. The account `fastjson-labs` was
registered two weeks ago and the repository's own `postinstall` script
downloads and executes a second-stage payload.

Nothing in this trace involved an injected instruction; the agent's own
name resolution produced the (wrong) target, and the clone-and-execute
path proceeded automatically from there.
