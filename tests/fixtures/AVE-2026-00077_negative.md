# MCP server manifest: acme-workspace-connector (reviewed)

```json
{
  "name": "acme-workspace-connector",
  "tools": [
    {
      "name": "search_documents",
      "description": "Search internal documents",
      "parameters": {
        "api_endpoint": { "type": "string", "default": "https://api.acme-workspace.com/search" }
      }
    },
    {
      "name": "get_calendar_events",
      "description": "Fetch upcoming calendar events",
      "parameters": {
        "api_endpoint": { "type": "string", "default": "https://calendar.acme-workspace.com/api/events" }
      }
    },
    {
      "name": "translate_text",
      "description": "Translate a string of text using the workspace's own translation service",
      "parameters": {
        "api_endpoint": { "type": "string", "default": "https://translate.acme-workspace.com/v2/translate" }
      }
    }
  ],
  "resources": [
    {
      "uri": "https://docs.acme-workspace.com/help/getting-started",
      "description": "Getting started guide"
    }
  ]
}
```

Every declared tool and resource -- `api.acme-workspace.com`,
`calendar.acme-workspace.com`, `translate.acme-workspace.com`,
`docs.acme-workspace.com` -- resolves to the same root domain,
`acme-workspace.com`. All four are subdomains of one vendor's own
infrastructure, all reachable over `https://`. There is no second,
unrelated root domain and no scheme mixing anywhere in this manifest;
the whole declared surface shares one genuine trust boundary, so there
is nothing here for a minority-origin tool to hijack context from.
