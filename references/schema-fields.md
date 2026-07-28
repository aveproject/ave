# Schema fields reference

## `entry_class`, confirmed live against the corpus, not assumed

This list was pulled directly from the live `dist/ave-records-latest.json`
during this workflow's own development, not reconstructed from memory.
Re-run the query below periodically, since new records may introduce
values not listed here yet:

```bash
curl -s https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json | python3 -c "
import json, sys
records = json.load(sys.stdin)
classes = set()
for r in records:
    ec = r.get('provenance_vector', {}).get('entry_class')
    if ec: classes.add(ec)
print(sorted(classes))
"
```

Confirmed values and what each actually means, with a real example
record for each:

- **`content`**: instruction text embedded in a skill's own body.
  Example: `AVE-2026-00048`, sub-agent delegation instructions written
  directly into skill instruction text.
- **`memory`**: an agent's persistent memory store. Example:
  `AVE-2026-00019`, planted false beliefs or instructions written into
  memory, executed in a future session.
- **`model_generated`**: content the agent itself produces, not something
  it reads. Example: `AVE-2026-00056`, a markdown image URL the agent's
  own generated response embeds.
- **`registry_metadata`**: a declarative configuration or registry entry,
  not instruction text. Example: `AVE-2026-00061` through `00064`
  (TLS verification, dependency pinning, approval bypass, auto-run
  configuration), all static config states, not content an agent reads
  and interprets as an instruction.
- **`retrieved_document`**: content pulled in via RAG or similar retrieval,
  distinct from a skill file's own body.
- **`runtime`**: something happening at execution time, not at a fixed
  location in a file. Example: `AVE-2026-00050`, tool registration
  happening during session initialization.
- **`server_card_document`**: a trusted capability-declaration document
  read before interaction begins, regardless of which protocol produces
  it. Example: `AVE-2026-00041` (MCP server-card injection) and
  `AVE-2026-00065` (A2A agent card poisoning), same entry_class,
  genuinely different protocols and payload surfaces, see the note in
  `00065` for the reasoning behind reusing rather than forking this
  value.
- **`skill_file`**: the skill file itself as a static artifact, distinct
  from `content` (the instruction text within it). Example:
  `AVE-2026-00024`, a file whose actual bytes don't match its declared
  extension.
- **`tool_response`**: a tool call's return value, not the request.
  Example: `AVE-2026-00018`, tool result manipulation.
- **`tool_schema`**: an MCP tool's own description or parameter schema
  field. Example: `AVE-2026-00002`, `AVE-2026-00059` (ShareLock).
- **`transport`**: the protocol/transport layer itself, not content
  carried over it. Example: `AVE-2026-00049` (HTTP header injection),
  `AVE-2026-00060` (STDIO shell injection), genuinely different
  mechanisms sharing this value the same way `server_card_document` is
  shared, confirmed by direct comparison before assuming overlap.
- **`user_input`**: content the user directly supplies, not something the
  agent fetches or reads from a component.

**When deciding whether a new candidate needs a new `entry_class` value or
can reuse an existing one**: ask whether the *role* the content plays is
the same as an existing value, even if the protocol or format differs.
`server_card_document` covers "trusted capability metadata read before
interaction" across two different protocols already. Reuse before
forking, and state the reasoning in the record's own `aivss.notes` field
either way, the same way `00065` did.

## `escalation`, the values seen so far

- `data_to_instruction`: passive content gets treated as an active
  directive. The most common value in the corpus.
- `instruction_to_capability`: an instruction is followed and grants or
  exercises a capability (a tool call, a permission grant).
- `capability_to_identity`: exercising a capability results in an
  identity or trust claim being accepted (impersonation, spoofing).

Not every record needs this field; omit rather than force a fit if none
of these describes the actual mechanism.

## Required fields, minimum viable record

`ave_id`, `schema_version`, `status`, `component_type`, `title`,
`attack_class`, `severity`, `description`, `aivss_score`,
`behavioral_fingerprint`, `provenance_vector` (at least `entry_class`),
`mitigation`, `detection_methodology`, `indicators_of_compromise`,
`remediation`, `researcher`, `published`, `references` (at least one, with
a real, working URL), `aivss` (the full scoring object, not just the
top-level `aivss_score` summary).

## `status` values

Currently only `active` is implemented in the schema. `deprecated`,
`merged`, and `rejected` are policy (see
`docs/specs/scaling-and-governance.md` Section 3) but not yet schema
fields, don't use them on a record until the schema change implementing
them has actually shipped, using them prematurely would produce a record
that fails validation or silently means nothing to any tooling reading
it.