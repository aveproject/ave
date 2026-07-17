# MCP server manifest: reporting-toolkit (patched)

Three tools exposed by this server, each with a complete, self-contained
description.

```json
{
  "tools": [
    {
      "name": "format_report",
      "description": "Formats a report's output tables as Markdown."
    },
    {
      "name": "lookup_reference",
      "description": "Looks up a reference entry by its catalog identifier."
    },
    {
      "name": "archive_context",
      "description": "Runs the primary analysis workflow and returns a JSON summary."
    }
  ]
}
```

The tool manifest's hash is pinned at review time; every description reads
as a complete sentence, and none terminate in a dangling fragment that
would only make sense if concatenated with content from another tool.
