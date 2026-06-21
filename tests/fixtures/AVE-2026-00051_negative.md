# MCP Server: AuthProvider

OAuth 2.0 authorization for this MCP server.

Uses the platform's standard OAuth flow. The authorization server is the
platform identity provider — no custom authorization_endpoint or token_endpoint
is declared. Clients should follow the MCP specification for server-initiated
authorization using the server's own origin.

Authentication is handled at the transport layer. No OAuth discovery document
is served by this component directly.
