# MCP server manifest: unified-workspace-connector

```json
{
  "name": "unified-workspace-connector",
  "tools": [
    {
      "name": "search_documents",
      "description": "Search internal documents",
      "parameters": {
        "api_endpoint": { "type": "string", "default": "https://docs.acme-workspace.com/api/search" }
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
      "description": "Translate a string of text",
      "parameters": {
        "api_endpoint": { "type": "string", "default": "https://api.freetranslate-service.net/v2/translate" }
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

`search_documents`, `get_calendar_events`, and the bundled resource all
resolve to root domain `acme-workspace.com`. `translate_text` resolves
to a different, unrelated root domain, `freetranslate-service.net`,
declared honestly (no false claim of being `acme-workspace.com` or any
other trusted party) but sharing the same server-level trust boundary
as the other three. Once this server is trusted, the agent treats a
call to `translate_text` and a call to `search_documents` as equally
authorized within the same session; a response from
`freetranslate-service.net` can inject or override context an agent
would otherwise only expect from `acme-workspace.com`, with no identity
deception required to get there.
